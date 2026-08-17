package de.lucasthcr.bridgesave.proxyshield.lookup;

import de.lucasthcr.bridgesave.proxyshield.cache.ExpiringCache;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Tries several lookup providers in order and caches whichever one answered.
 * <p>
 * A single provider is a single point of failure, and the free tiers are exactly the ones that go
 * down or start refusing requests. With a chain, a rate-limited or unreachable first provider costs
 * one failed request rather than the whole check: the next one is asked immediately, and only when
 * every provider has failed does the result come back unresolved for {@code settings.fail-closed}
 * to act on.
 * <p>
 * The cache sits here rather than in the individual providers, so a hit costs nothing regardless of
 * which provider originally supplied the answer.
 */
public final class FailoverLookupService implements LookupProvider {

   private final Platform platform;
   private final List<IpLookupService> providers;
   private final ExpiringCache<String, LookupResult> cache;

   private final AtomicLong lookups = new AtomicLong();
   private final AtomicLong failures = new AtomicLong();
   private final AtomicLong failovers = new AtomicLong();

   public FailoverLookupService(Platform platform, ShieldConfig config) {
      this.platform = platform;
      this.cache = new ExpiringCache<>(config.apiMaxCacheEntries(),
            config.apiCacheMinutes() * 60_000L);

      List<IpLookupService> built = new ArrayList<>();
      for (String endpoint : config.activeApiProviders()) {
         built.add(new IpLookupService(platform, config, endpoint));
      }
      this.providers = List.copyOf(built);
   }

   /** Number of endpoints in the chain. */
   public int providerCount() {
      return providers.size();
   }

   /** Host of the first provider, for display in {@code /proxyshield info}. */
   public String primaryHost() {
      return providers.isEmpty() ? "none" : providers.get(0).host();
   }

   public Optional<LookupResult> cached(String ip) {
      return cache.get(ip);
   }

   @Override
   public LookupResult lookup(String ip) {
      Optional<LookupResult> hit = cache.get(ip);
      if (hit.isPresent()) {
         return hit.get();
      }

      if (providers.isEmpty()) {
         return LookupResult.failed("no lookup provider configured");
      }

      LookupResult last = LookupResult.failed("no provider answered");
      for (int i = 0; i < providers.size(); i++) {
         IpLookupService provider = providers.get(i);
         LookupResult result = provider.lookup(ip);

         if (result.resolved()) {
            if (i > 0) {
               failovers.incrementAndGet();
            }
            lookups.incrementAndGet();
            cache.put(ip, result);
            return result;
         }

         last = result;
         if (i + 1 < providers.size()) {
            platform.warn("Lookup provider " + provider.host() + " failed for " + ip + " ("
                  + result.failureReason() + "), trying " + providers.get(i + 1).host());
         }
      }

      lookups.incrementAndGet();
      failures.incrementAndGet();
      // Deliberately not cached: a chain-wide failure says nothing about the address.
      return last;
   }

   public void invalidate(String ip) {
      cache.invalidate(ip);
   }

   public void clearCache() {
      cache.clear();
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

   /** How often a provider other than the first one supplied the answer. */
   public long failoverCount() {
      return failovers.get();
   }

   public long rateLimitedCount() {
      long total = 0;
      for (IpLookupService provider : providers) {
         total += provider.rateLimitedCount();
      }
      return total;
   }

   /** Warns once at startup about endpoints that are not encrypted. */
   public void warnIfInsecure() {
      for (IpLookupService provider : providers) {
         provider.warnIfInsecure();
      }
      if (providers.size() == 1) {
         platform.info("Only one lookup provider is configured. Adding a second one under "
               + "api.providers keeps detection working when the first is down or rate limited.");
      }
   }
}
