/*
 * ProxyShield - Proxy and VPN protection plugin
 * Copyright (C) 2026  LucasTHCR
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package de.lucasthcr.bridgesave.proxyshield.lookup;

import de.lucasthcr.bridgesave.proxyshield.cache.ExpiringCache;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.net.IpAddresses;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import de.lucasthcr.bridgesave.proxyshield.storage.ShieldStorage;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
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
 * anything better gets asked - the single biggest source of misses in v2.1. {@code consensus} asks
 * several at once and blocks when the combined weight of the services flagging the address reaches
 * the configured score, so one blind provider can no longer wave a connection through.
 * <p>
 * Consensus is not more expensive per login than it looks: answers are cached under a key that
 * folds IPv6 down to its /64, concurrent logins from the same address share a single lookup, the
 * fan-out stops the moment the threshold is met, and a provider that keeps failing is taken out of
 * the rotation by its own circuit breaker.
 */
public final class FailoverLookupService implements LookupProvider, AutoCloseable {

   /**
    * How long a clean verdict survives when some providers never answered. Long enough that a
    * burst of logins costs one round of requests, short enough that a rate limit cannot keep an
    * address looking clean for the rest of the day.
    */
   private static final long INCOMPLETE_CLEAN_TTL_MILLIS = 300_000L;

   private final Platform platform;
   private final List<IpLookupService> providers;
   private final ExpiringCache<String, LookupResult> cache;
   private final ShieldConfig.LookupMode mode;
   private final double requiredScore;
   private final int firstWave;
   private final long cleanSettleMillis;
   private final AtomicLong cleanSettles = new AtomicLong();
   private final AtomicLong stagedSkips = new AtomicLong();
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
   private final AtomicLong overloaded = new AtomicLong();
   private java.util.concurrent.Semaphore waiting = new java.util.concurrent.Semaphore(256);

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
      this.firstWave = config.apiFirstWave();
      this.cleanSettleMillis = config.apiCleanSettleMillis();
      this.cleanTtlMillis = config.apiCacheMinutes() * 60_000L;
      this.flaggedTtlMillis = config.apiFlaggedCacheMinutes() * 60_000L;
      this.totalBudgetMillis = config.apiTotalTimeoutMillis();
      this.waiting = new java.util.concurrent.Semaphore(config.apiMaxWaiting());

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
      // One pool for every login. Sizing it to the provider count meant a single lookup used all of
      // it, so a burst of joins queued behind each other until the total timeout ran out.
      this.executor = Executors.newFixedThreadPool(
            Math.max(config.apiMaxParallel(), Math.max(1, providers.size())),
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
      return lookup(ip, false);
   }

   @Override
   public LookupResult lookup(String ip, boolean endUserNetwork) {
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

      // Zu viele wartende Logins: nicht anstellen, sondern sofort lokal entscheiden lassen
      if (!waiting.tryAcquire()) {
         overloaded.incrementAndGet();
         return LookupResult.failed("too many logins waiting for providers");
      }
      try {
         return lookupAdmitted(ip, key, endUserNetwork);
      } finally {
         waiting.release();
      }
   }

   private LookupResult lookupAdmitted(String ip, String key, boolean endUserNetwork) {
      CompletableFuture<LookupResult> fresh = new CompletableFuture<>();
      CompletableFuture<LookupResult> running = inFlight.putIfAbsent(key, fresh);
      if (running != null) {
         // Another login is already asking about this address; wait for that answer instead of
         // sending a second identical request.
         coalesced.incrementAndGet();
         return await(running);
      }

      try {
         // Der vorige Anfrager kann zwischen Cache-Blick und putIfAbsent fertig geworden sein
         Optional<LookupResult> late = cache.get(key);
         if (late.isPresent()) {
            fresh.complete(late.get());
            return late.get();
         }
         Round round = mode == ShieldConfig.LookupMode.FAILOVER
               ? new Round(failover(ip), true)
               : consensus(ip, endUserNetwork ? cleanSettleMillis : 0);
         LookupResult result = round.result();

         lookups.incrementAndGet();
         if (result.resolved()) {
            long ttl = ttlFor(round);
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
         LookupResult result = provider.lookup(ip, deadline);
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
    * Asks the providers and adds up the weight of those that flagged the address.
    * <p>
    * The first wave is the first {@code api.first-wave} providers that are not tripped or out of
    * quota. When every one of them answers and none flags the address, that settles it and the
    * rest are never asked, so an ordinary address costs a couple of requests instead of one per
    * provider and the free quotas go further. Anything else (a flag, a failure, a slow answer)
    * brings in the remaining providers. A first wave of 0 asks everyone at once.
    * <p>
    * Either way the round returns as soon as the threshold is reached and cancels what is still
    * running, so an obvious VPN costs the latency of the fastest provider that recognises it.
    */
   private Round consensus(String ip, long softMillis) {
      ExecutorCompletionService<ProviderAnswer> completions =
            new ExecutorCompletionService<>(executor);
      List<Future<ProviderAnswer>> pending = new ArrayList<>(providers.size());

      List<IpLookupService> ready = new ArrayList<>(providers.size());
      for (IpLookupService provider : providers) {
         if (provider.ready()) {
            ready.add(provider);
         }
      }
      if (ready.isEmpty()) {
         ready.addAll(providers);
      }
      int firstSize = firstWave > 0 && firstWave < ready.size() ? firstWave : ready.size();

      Merge merge = new Merge();
      long deadline = System.currentTimeMillis() + totalBudgetMillis;
      try {
         submit(completions, pending, ready.subList(0, firstSize), ip);
         int state = collect(completions, firstSize, merge, deadline, softMillis);
         if (state == COLLECT_DONE && firstSize < ready.size()) {
            if (merge.answered == firstSize && merge.proxyScore == 0.0 && merge.hostingScore == 0.0) {
               merge.settledEarly();
               stagedSkips.incrementAndGet();
            } else {
               int rest = ready.size() - firstSize;
               submit(completions, pending, ready.subList(firstSize, ready.size()), ip);
               collect(completions, rest, merge, deadline, 0);
            }
         }
      } catch (InterruptedException interrupted) {
         Thread.currentThread().interrupt();
      } finally {
         for (Future<ProviderAnswer> future : pending) {
            future.cancel(true);
         }
      }

      return new Round(merge.toResult(requiredScore), merge.complete(pending.size()));
   }

   private static final int COLLECT_DONE = 0;
   private static final int COLLECT_SETTLED = 1;
   private static final int COLLECT_BUDGET = 2;

   private void submit(ExecutorCompletionService<ProviderAnswer> completions,
         List<Future<ProviderAnswer>> pending, List<IpLookupService> group, String ip) {
      for (IpLookupService provider : group) {
         pending.add(completions.submit(() ->
               new ProviderAnswer(provider.id(), provider.weight(), provider.lookup(ip))));
      }
   }

   /**
    * Takes {@code count} answers in the order they arrive, or stops on a settled verdict.
    * <p>
    * With {@code softMillis} above zero (an address in a home network) it also stops when that time has
    * passed, one provider has answered clean and no provider has flagged anything: waiting for the slowest
    * provider then costs the player more than it adds. The verdict is not treated as complete, so it is
    * cached only briefly.
    */
   private int collect(ExecutorCompletionService<ProviderAnswer> completions, int count,
         Merge merge, long deadline, long softMillis) throws InterruptedException {
      long softAt = softMillis > 0 ? System.currentTimeMillis() + softMillis : 0;
      int taken = 0;
      while (taken < count) {
         long now = System.currentTimeMillis();
         long remaining = deadline - now;
         if (remaining <= 0) {
            budgetExceeded.incrementAndGet();
            return COLLECT_BUDGET;
         }

         long wait = softAt > 0 ? Math.min(remaining, Math.max(1, softAt - now)) : remaining;
         // Take answers in the order they arrive, so a slow provider never holds up a verdict
         // a fast one has already settled.
         Future<ProviderAnswer> completed = completions.poll(wait, TimeUnit.MILLISECONDS);
         if (completed == null) {
            if (softAt > 0 && System.currentTimeMillis() >= softAt) {
               if (merge.answered >= 1 && merge.proxyScore == 0.0 && merge.hostingScore == 0.0) {
                  merge.softSettled();
                  cleanSettles.incrementAndGet();
                  return COLLECT_SETTLED;
               }
               softAt = 0;  // nothing clean to rely on yet, wait the normal way
               continue;
            }
            budgetExceeded.incrementAndGet();
            return COLLECT_BUDGET;
         }
         taken++;

         ProviderAnswer answer;
         try {
            answer = completed.get();
         } catch (ExecutionException failed) {
            continue;
         }

         merge.add(answer);
         if (merge.proxyScore >= requiredScore) {
            merge.settledEarly();
            return COLLECT_SETTLED;
         }
      }
      return COLLECT_DONE;
   }

   /**
    * One round of questions and how much of it came back.
    *
    * @param complete whether every provider asked actually answered, or the round stopped early
    *                 with a verdict already settled
    */
   private record Round(LookupResult result, boolean complete) {
   }

   /**
    * How long an answer may be reused.
    * <p>
    * A clean verdict off an incomplete round is the dangerous one. One provider answering "not a
    * proxy" is enough to resolve the round, so a rate limit or a timeout on the single provider
    * that would have flagged the address produces a clean answer that then sits in the cache for
    * the full six hours, surviving restarts through lookup-cache.json. The address keeps passing
    * long after the providers recovered, and nothing in the log says why. An incomplete clean
    * round is therefore kept only long enough to absorb a burst of logins.
    */
   private long ttlFor(Round round) {
      LookupResult result = round.result();
      if (result.proxy() || result.hosting()) {
         return flaggedTtlMillis;
      }
      return round.complete()
            ? cleanTtlMillis
            : Math.min(cleanTtlMillis, INCOMPLETE_CLEAN_TTL_MILLIS);
   }

   /** Accumulates provider answers into one verdict. */
   private static final class Merge {

      private final LinkedHashSet<String> flaggedBy = new LinkedHashSet<>();
      private int answered;
      private int settledEarly;
      private boolean soft;
      private double proxyScore;
      private double hostingScore;
      private boolean resolved;
      private boolean tor;
      private String countryCode;
      private String countryName;
      private final Map<String, Integer> ispVotes = new LinkedHashMap<>();
      private final Map<String, String> ispSpelling = new LinkedHashMap<>();
      private String asn;
      private String connectionType;
      private String lastFailure = "no provider answered";

      void add(ProviderAnswer answer) {
         LookupResult result = answer.result();
         if (!result.resolved()) {
            lastFailure = answer.id() + ": " + result.failureReason();
            return;
         }

         answered++;
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
         voteIsp(result.isp());
         asn = firstNonNull(asn, result.asn());
         connectionType = firstNonNull(connectionType, result.connectionType());
      }

      /** Marks that the loop stopped on a settled verdict rather than on a missing answer. */
      void settledEarly() {
         settledEarly++;
      }

      /** Marks that the loop stopped at the time limit on one clean answer: not the full picture. */
      void softSettled() {
         soft = true;
      }

      /**
       * Whether the verdict rests on the full picture. Stopping early because the score was
       * already reached counts as complete: the remaining answers could not have changed it.
       */
      boolean complete(int asked) {
         return !soft && (settledEarly > 0 || answered >= asked);
      }

      LookupResult toResult(double requiredScore) {
         if (!resolved) {
            return LookupResult.failed(lastFailure);
         }
         // The score describes proxy-likeness only. Folding the hosting weight into it would let
         // a datacenter address take the proxy path and skip both detection.block-hosting and the
         // residential exemption.
         return LookupResult.of(proxyScore >= requiredScore, hostingScore >= requiredScore, tor,
               countryCode, countryName, isp(), asn, connectionType, proxyScore,
               List.copyOf(flaggedBy));
      }

      /**
       * Providers disagree on the name more often than on anything else: one reports the
       * operator, another the registrant of the block ("APNIC Research and Development" for
       * Cloudflare's 1.1.1.1). Taking whichever answered first made the ISP filter depend on
       * network timing, so the name most providers agree on wins, ties going to the earliest.
       */
      private void voteIsp(String name) {
         if (name == null || name.isBlank()) {
            return;
         }
         String key = name.toLowerCase(Locale.ROOT).replaceAll("[^\\p{L}\\p{N}]", "");
         if (key.isEmpty()) {
            return;
         }
         ispVotes.merge(key, 1, Integer::sum);
         ispSpelling.putIfAbsent(key, name.trim());
      }

      private String isp() {
         String best = null;
         int votes = 0;
         for (Map.Entry<String, Integer> entry : ispVotes.entrySet()) {
            if (entry.getValue() > votes) {
               best = entry.getKey();
               votes = entry.getValue();
            }
         }
         return best == null ? null : ispSpelling.get(best);
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

   /** Lookups that stopped at the time limit on one clean answer. */
   public long cleanSettles() {
      return cleanSettles.get();
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
   public long overloadedCount() {
      return overloaded.get();
   }

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
               + " to cross-check against. Enable a few more under api.providers - the free ones"
               + " need no key.");
      }
   }

   @Override
   public void close() {
      executor.shutdownNow();
   }
}
