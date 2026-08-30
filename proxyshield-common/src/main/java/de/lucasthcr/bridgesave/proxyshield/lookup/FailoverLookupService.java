package de.lucasthcr.bridgesave.proxyshield.lookup;

import de.lucasthcr.bridgesave.proxyshield.cache.ExpiringCache;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.net.IpAddresses;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import de.lucasthcr.bridgesave.proxyshield.storage.ShieldStorage;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Combines several lookup providers into one answer, and caches it.
 * <p>
 * Two modes. {@code failover} asks providers in order and takes the first answer, which is cheap
 * but means a service that has never heard of a particular commercial VPN clears the address before
 * anything better gets asked — the single biggest source of misses in v2.1. {@code consensus} asks
 * several at once and blocks when the combined weight of the services flagging the address reaches
 * the configured score, so one blind provider can no longer wave a connection through.
 * <p>
 * Consensus is not more expensive per login than it looks: answers are cached under a key that
 * folds IPv6 down to its /64, concurrent logins from the same address share a single lookup, the
 * fan-out stops the moment the threshold is met, and a provider that keeps failing is taken out of
 * the rotation by its own circuit breaker.
 */
public final class FailoverLookupService implements LookupProvider, AutoCloseable {

   private final Platform platform;
   private final List<IpLookupService> providers;
   private final ExpiringCache<String, LookupResult> cache;
   private final ShieldConfig.LookupMode mode;
   private final double requiredScore;
   private final long cleanTtlMillis;
   private final long flaggedTtlMillis;
   private final long totalBudgetMillis;
   private final ExecutorService executor;
   private final ShieldStorage storage;

   /** Lookups already running, so a burst from one address costs one request, not one each. */
   private final ConcurrentHashMap<String, CompletableFuture<LookupResult>> inFlight =
         new ConcurrentHashMap<>();

   private final AtomicLong lookups = new AtomicLong();
   private final AtomicLong failures = new AtomicLong();
   private final AtomicLong failovers = new AtomicLong();
   private final AtomicLong coalesced = new AtomicLong();
   private final AtomicLong budgetExceeded = new AtomicLong();
   private final AtomicLong sharedHits = new AtomicLong();

   public FailoverLookupService(Platform platform, ShieldConfig config) {
      this(platform, config, null, null);
   }

   public FailoverLookupService(Platform platform, ShieldConfig config,
         FailoverLookupService previous) {
      this(platform, config, previous, previous == null ? null : previous.storage);
   }

   /**
    * @param previous the service being replaced on reload, whose cache is inherited when it is
    *                 still sized and timed the same. Without that, every {@code /proxyshield
    *                 reload} threw away thousands of answers and sent the server straight back
    *                 into the providers' rate limits.
    */
   /**
    * @param storage where verdicts are kept between restarts and, on a network, shared between
    *                servers. {@code null} keeps everything in memory.
    */
   public FailoverLookupService(Platform platform, ShieldConfig config,
         FailoverLookupService previous, ShieldStorage storage) {
      this.platform = platform;
      this.storage = storage;
      this.mode = config.lookupMode();
      this.requiredScore = config.requiredScore();
      this.cleanTtlMillis = config.apiCacheMinutes() * 60_000L;
      this.flaggedTtlMillis = config.apiFlaggedCacheMinutes() * 60_000L;
      this.totalBudgetMillis = config.apiTotalTimeoutSeconds() * 1000L;

      List<IpLookupService> built = new ArrayList<>();
      List<String> unusable = new ArrayList<>();
      for (ProviderDefinition definition : config.providers()) {
         if (definition.usable()) {
            built.add(new IpLookupService(platform, config, definition));
         } else {
            unusable.add(definition.id());
         }
      }
      this.providers = List.copyOf(built);
      if (!unusable.isEmpty()) {
         platform.warn("Skipping lookup providers that are enabled but have no API key: "
               + String.join(", ", unusable) + ". Add a key under api.providers or disable them.");
      }

      this.cache = inheritableCache(previous, config);
      this.executor = Executors.newFixedThreadPool(
            Math.min(config.apiMaxParallel(), Math.max(1, providers.size())),
            daemonThreads());
   }

   private ExpiringCache<String, LookupResult> inheritableCache(FailoverLookupService previous,
         ShieldConfig config) {
      ExpiringCache<String, LookupResult> fresh =
            new ExpiringCache<>(config.apiMaxCacheEntries(), cleanTtlMillis);
      if (previous == null) {
         return fresh;
      }
      for (Map.Entry<String, Long> entry : previous.cache.expirySnapshot().entrySet()) {
         LookupResult value = previous.cache.peek(entry.getKey());
         if (value != null) {
            fresh.putWithExpiry(entry.getKey(), value, entry.getValue());
         }
      }
      return fresh;
   }

   private static ThreadFactory daemonThreads() {
      AtomicInteger counter = new AtomicInteger();
      return task -> {
         Thread thread = new Thread(task, "ProxyShield-lookup-" + counter.incrementAndGet());
         thread.setDaemon(true);
         return thread;
      };
   }

   /** Number of endpoints in the chain. */
   public int providerCount() {
      return providers.size();
   }

   public List<IpLookupService> providers() {
      return providers;
   }

   public ShieldConfig.LookupMode mode() {
      return mode;
   }

   /** Host of the first provider, for display in {@code /proxyshield info}. */
   public String primaryHost() {
      return providers.isEmpty() ? "none" : providers.get(0).host();
   }

   public Optional<LookupResult> cached(String ip) {
      return cache.get(IpAddresses.cacheKey(ip));
   }

   @Override
   public LookupResult lookup(String ip) {
      String key = IpAddresses.cacheKey(ip);

      Optional<LookupResult> hit = cache.get(key);
      if (hit.isPresent()) {
         return hit.get();
      }

      // On a network the answer may already have been paid for by another proxy.
      Optional<LookupResult> shared = fromStorage(key);
      if (shared.isPresent()) {
         return shared.get();
      }

      if (providers.isEmpty()) {
         return LookupResult.failed("no lookup provider configured");
      }

      CompletableFuture<LookupResult> fresh = new CompletableFuture<>();
      CompletableFuture<LookupResult> running = inFlight.putIfAbsent(key, fresh);
      if (running != null) {
         // Another login is already asking about this address; wait for that answer instead of
         // sending a second identical request.
         coalesced.incrementAndGet();
         return await(running);
      }

      try {
         LookupResult result = mode == ShieldConfig.LookupMode.FAILOVER
               ? failover(ip)
               : consensus(ip);

         lookups.incrementAndGet();
         if (result.resolved()) {
            long ttl = result.proxy() || result.hosting() ? flaggedTtlMillis : cleanTtlMillis;
            cache.put(key, result, ttl);
            if (storage != null) {
               storage.put(key, new ShieldStorage.CachedVerdict(result,
                     System.currentTimeMillis() + ttl));
            }
         } else {
            // Deliberately not cached: a chain-wide failure says nothing about the address.
            failures.incrementAndGet();
         }
         fresh.complete(result);
         return result;
      } catch (RuntimeException unexpected) {
         fresh.complete(LookupResult.failed("lookup error: " + unexpected));
         throw unexpected;
      } finally {
         inFlight.remove(key, fresh);
      }
   }

   private LookupResult await(CompletableFuture<LookupResult> running) {
      try {
         return running.get(totalBudgetMillis, TimeUnit.MILLISECONDS);
      } catch (InterruptedException interrupted) {
         Thread.currentThread().interrupt();
         return LookupResult.failed("interrupted while waiting for a shared lookup");
      } catch (ExecutionException | TimeoutException failure) {
         return LookupResult.failed("shared lookup did not finish in time");
      }
   }

   /** First answer wins. */
   private LookupResult failover(String ip) {
      LookupResult last = LookupResult.failed("no provider answered");
      long deadline = System.currentTimeMillis() + totalBudgetMillis;

      for (int i = 0; i < providers.size(); i++) {
         if (System.currentTimeMillis() >= deadline) {
            budgetExceeded.incrementAndGet();
            return last;
         }

         IpLookupService provider = providers.get(i);
         LookupResult result = provider.lookup(ip);
         if (result.resolved()) {
            if (i > 0) {
               failovers.incrementAndGet();
            }
            return result;
         }

         last = result;
         if (i + 1 < providers.size()) {
            platform.warn("Lookup provider " + provider.id() + " failed for " + ip + " ("
                  + result.failureReason() + "), trying " + providers.get(i + 1).id());
         }
      }
      return last;
   }

   /**
    * Asks every provider at once and adds up the weight of those that flagged the address.
    * <p>
    * Returns as soon as the threshold is reached — the remaining requests are cancelled, so the
    * common case of an obvious VPN costs the latency of the fastest provider that recognises it,
    * not of the slowest one in the list.
    */
   private LookupResult consensus(String ip) {
      ExecutorCompletionService<ProviderAnswer> completions =
            new ExecutorCompletionService<>(executor);
      List<Future<ProviderAnswer>> pending = new ArrayList<>(providers.size());
      for (IpLookupService provider : providers) {
         pending.add(completions.submit(() ->
               new ProviderAnswer(provider.id(), provider.weight(), provider.lookup(ip))));
      }

      Merge merge = new Merge();
      long deadline = System.currentTimeMillis() + totalBudgetMillis;
      try {
         for (int answered = 0; answered < pending.size(); answered++) {
            long remaining = deadline - System.currentTimeMillis();
            if (remaining <= 0) {
               budgetExceeded.incrementAndGet();
               break;
            }

            // Take answers in the order they arrive, so a slow provider never holds up a verdict
            // a fast one has already settled.
            Future<ProviderAnswer> completed = completions.poll(remaining, TimeUnit.MILLISECONDS);
            if (completed == null) {
               budgetExceeded.incrementAndGet();
               break;
            }

            ProviderAnswer answer;
            try {
               answer = completed.get();
            } catch (ExecutionException failed) {
               continue;
            }

            merge.add(answer);
            if (merge.proxyScore >= requiredScore) {
               break;
            }
         }
      } catch (InterruptedException interrupted) {
         Thread.currentThread().interrupt();
      } finally {
         for (Future<ProviderAnswer> future : pending) {
            future.cancel(true);
         }
      }

      return merge.toResult(requiredScore);
   }

   /** Accumulates provider answers into one verdict. */
   private static final class Merge {

      private final LinkedHashSet<String> flaggedBy = new LinkedHashSet<>();
      private double proxyScore;
      private double hostingScore;
      private boolean resolved;
      private boolean tor;
      private String countryCode;
      private String countryName;
      private String isp;
      private String asn;
      private String connectionType;
      private String lastFailure = "no provider answered";

      void add(ProviderAnswer answer) {
         LookupResult result = answer.result();
         if (!result.resolved()) {
            lastFailure = answer.id() + ": " + result.failureReason();
            return;
         }

         resolved = true;
         double weight = answer.weight();
         if (result.proxy() || result.tor()) {
            proxyScore += weight;
            flaggedBy.add(answer.id());
         }
         if (result.hosting()) {
            hostingScore += weight;
            flaggedBy.add(answer.id());
         }
         tor |= result.tor();

         countryCode = firstNonNull(countryCode, result.countryCode());
         countryName = firstNonNull(countryName, result.countryName());
         isp = firstNonNull(isp, result.isp());
         asn = firstNonNull(asn, result.asn());
         connectionType = firstNonNull(connectionType, result.connectionType());
      }

      LookupResult toResult(double requiredScore) {
         if (!resolved) {
            return LookupResult.failed(lastFailure);
         }
         // The score describes proxy-likeness only. Folding the hosting weight into it would let
         // a datacenter address take the proxy path and skip both detection.block-hosting and the
         // residential exemption.
         return LookupResult.of(proxyScore >= requiredScore, hostingScore >= requiredScore, tor,
               countryCode, countryName, isp, asn, connectionType, proxyScore,
               List.copyOf(flaggedBy));
      }

      private static String firstNonNull(String current, String candidate) {
         return current != null ? current : candidate;
      }
   }

   /** Runs one address through every provider individually, for {@code /proxyshield check}. */
   public List<ProviderAnswer> diagnose(String ip) {
      List<ProviderAnswer> answers = new ArrayList<>(providers.size());
      for (IpLookupService provider : providers) {
         answers.add(new ProviderAnswer(provider.id(), provider.weight(), provider.lookup(ip)));
      }
      return answers;
   }

   /** One provider's opinion, with the weight it carries. */
   public record ProviderAnswer(String id, double weight, LookupResult result) {
   }

   public void invalidate(String ip) {
      String key = IpAddresses.cacheKey(ip);
      cache.invalidate(key);
      if (storage != null) {
         storage.invalidate(key);
      }
   }

   public void clearCache() {
      cache.clear();
      if (storage != null) {
         storage.clearVerdicts();
      }
   }

   public int purgeExpired() {
      return cache.purgeExpired();
   }

   public int cacheSize() {
      return cache.size();
   }

   public long cacheHits() {
      return cache.hits();
   }

   public long lookups() {
      return lookups.get();
   }

   public long failureCount() {
      return failures.get();
   }

   /** How often a provider other than the first one supplied the answer, in failover mode. */
   public long failoverCount() {
      return failovers.get();
   }

   /** Requests saved by joining a lookup that was already running. */
   public long coalescedCount() {
      return coalesced.get();
   }

   /** How often the lookup stage hit its time budget and answered with what it had. */
   public long budgetExceededCount() {
      return budgetExceeded.get();
   }

   public long rateLimitedCount() {
      long total = 0;
      for (IpLookupService provider : providers) {
         total += provider.rateLimitedCount();
      }
      return total;
   }

   // ------------------------------------------------------------- shared storage

   /** Reads a verdict another server already paid for, and adopts it locally. */
   private Optional<LookupResult> fromStorage(String key) {
      if (storage == null || !storage.shared() || !storage.available()) {
         return Optional.empty();
      }

      Optional<ShieldStorage.CachedVerdict> stored = storage.find(key);
      if (stored.isEmpty()) {
         return Optional.empty();
      }

      ShieldStorage.CachedVerdict verdict = stored.get();
      cache.putWithExpiry(key, verdict.result(), verdict.expiresAt());
      sharedHits.incrementAndGet();
      return Optional.of(verdict.result());
   }

   /** Loads whatever the store wants kept in memory, e.g. the file store's cache. */
   public void preloadFrom(ShieldStorage source) {
      int restored = 0;
      for (java.util.Map.Entry<String, ShieldStorage.CachedVerdict> entry
            : source.preload().entrySet()) {
         ShieldStorage.CachedVerdict verdict = entry.getValue();
         if (!verdict.isExpired()) {
            cache.putWithExpiry(entry.getKey(), verdict.result(), verdict.expiresAt());
            restored++;
         }
      }
      if (restored > 0) {
         platform.info("Restored " + restored + " cached lookups from " + source.name() + ".");
      }
   }

   /** Drops a key that another server invalidated. Does not echo the invalidation back. */
   public void invalidateLocally(String key) {
      if ("*".equals(key)) {
         cache.clear();
      } else {
         cache.invalidate(key);
      }
   }

   /** Answers served from the shared store instead of a provider. */
   public long sharedHitCount() {
      return sharedHits.get();
   }

   /** Warns once at startup about endpoints that are not encrypted. */
   public void warnIfInsecure() {
      for (IpLookupService provider : providers) {
         provider.warnIfInsecure();
      }
      if (providers.size() == 1 && mode == ShieldConfig.LookupMode.CONSENSUS) {
         platform.warn("Consensus mode is on but only one provider is enabled, so there is nothing"
               + " to cross-check against. Enable a few more under api.providers — the free ones"
               + " need no key.");
      }
   }

   @Override
   public void close() {
      executor.shutdownNow();
   }
}
