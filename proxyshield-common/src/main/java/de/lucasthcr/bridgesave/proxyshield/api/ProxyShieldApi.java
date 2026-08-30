package de.lucasthcr.bridgesave.proxyshield.api;

import de.lucasthcr.bridgesave.proxyshield.ProxyShieldCore;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import java.util.Optional;
import java.util.UUID;

/**
 * What other plugins may ask ProxyShield.
 * <p>
 * Deliberately small and platform independent, so the same three calls work whether the caller sits
 * on Paper, BungeeCord, Velocity or Sponge. Everything here reads state that already exists; nothing
 * on this interface changes a verdict or kicks anybody.
 * <p>
 * Availability is not guaranteed: a caller must handle {@link #isAvailable()} being {@code false},
 * because the plugin may be absent or still starting.
 */
public final class ProxyShieldApi {

   private static volatile ProxyShieldCore core;

   private ProxyShieldApi() {
   }

   /** Called by the plugin itself once the core is up. Not part of the public contract. */
   public static void bind(ProxyShieldCore instance) {
      core = instance;
   }

   public static void unbind() {
      core = null;
   }

   public static boolean isAvailable() {
      return core != null;
   }

   /**
    * Whether the address is currently believed to be a proxy, VPN or Tor exit.
    * <p>
    * Answers from the cache only — it never performs a network request, so it is safe to call from
    * the main thread. An address nobody has looked up yet is reported as {@code false}.
    */
   public static boolean isProxy(String ip) {
      return cached(ip).map(result -> result.proxy() || result.tor()).orElse(false);
   }

   /** Whether the address is currently believed to be a datacenter or hosting range. Cache only. */
   public static boolean isHosting(String ip) {
      return cached(ip).map(LookupResult::hosting).orElse(false);
   }

   /**
    * Everything known about an address, from the cache.
    * <p>
    * Includes the country, ISP, ASN, the combined score and which services flagged it.
    */
   public static Optional<LookupResult> cached(String ip) {
      ProxyShieldCore instance = core;
      if (instance == null || ip == null) {
         return Optional.empty();
      }
      return instance.lookups().cached(ip);
   }

   /**
    * Performs a full lookup, querying the providers when the address is not cached.
    * <p>
    * Blocking: never call this from the main thread.
    */
   public static LookupResult lookup(String ip) {
      ProxyShieldCore instance = core;
      if (instance == null || ip == null) {
         return LookupResult.UNKNOWN;
      }
      return instance.lookups().lookup(ip);
   }

   /**
    * Whether this account has earned an exemption through its history on the server.
    *
    * @see de.lucasthcr.bridgesave.proxyshield.check.TrustStore
    */
   public static boolean isTrusted(UUID uuid) {
      ProxyShieldCore instance = core;
      if (instance == null || uuid == null) {
         return false;
      }
      return instance.trust().trusted(uuid, instance.config().trustMinLogins(),
            instance.config().trustMinDays());
   }

   /** Drops a cached answer, e.g. after an operator whitelisted the address elsewhere. */
   public static void invalidate(String ip) {
      ProxyShieldCore instance = core;
      if (instance != null && ip != null) {
         instance.lookups().invalidate(ip);
      }
   }
}
