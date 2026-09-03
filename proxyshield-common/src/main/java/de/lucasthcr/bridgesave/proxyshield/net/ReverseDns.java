package de.lucasthcr.bridgesave.proxyshield.net;

import de.lucasthcr.bridgesave.proxyshield.cache.ExpiringCache;
import java.net.InetAddress;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Reverse DNS as a detection signal, with a hard timeout.
 * <p>
 * Hosting and VPN operators name their machines after themselves - {@code
 * mad-01.torguard.io}, {@code vpn-gw3.example.net}, {@code static.hosting.provider} - so the PTR
 * record catches ranges no feed has picked up yet and no API quota is spent on it. It is a hint,
 * not a verdict: it contributes weight to the consensus score rather than blocking on its own,
 * because plenty of legitimate ISPs put words like {@code host} in their customer PTRs.
 * <p>
 * The JDK's reverse lookup has no timeout of its own and can hang for many seconds behind a broken
 * resolver, which on a login thread is a stall the player sees. Every lookup therefore runs on a
 * daemon thread that the caller abandons once the budget is spent.
 */
public final class ReverseDns {

   private static final List<String> DEFAULT_PATTERNS = List.of(
         "vpn", "proxy", "tor-exit", "torexit", "torguard", "nordvpn", "expressvpn",
         "surfshark", "cyberghost", "privateinternetaccess", "mullvad", "protonvpn",
         "ipvanish", "purevpn", "windscribe", "hidemyass", "datacenter", "data-center",
         "hosting", "colo", "cloud", "server", "dedicated", "vps");

   private final ExecutorService resolver;
   private final ExpiringCache<String, String> cache;
   private final int timeoutMillis;

   public ReverseDns(int timeoutMillis, int maxCacheEntries, long cacheTtlMillis) {
      this.timeoutMillis = Math.max(50, timeoutMillis);
      this.cache = new ExpiringCache<>(maxCacheEntries, cacheTtlMillis);
      this.resolver = Executors.newCachedThreadPool(daemonThreads());
   }

   private static ThreadFactory daemonThreads() {
      AtomicInteger counter = new AtomicInteger();
      return task -> {
         Thread thread = new Thread(task, "ProxyShield-rdns-" + counter.incrementAndGet());
         thread.setDaemon(true);
         return thread;
      };
   }

   /** The PTR name for an address, or empty when there is none or the lookup ran out of time. */
   public Optional<String> hostname(String ip) {
      byte[] raw = IpAddresses.parseLiteral(ip);
      if (raw == null) {
         return Optional.empty();
      }

      String key = IpAddresses.cacheKey(ip);
      Optional<String> cached = cache.get(key);
      if (cached.isPresent()) {
         return cached.get().isEmpty() ? Optional.empty() : cached;
      }

      Future<String> pending = resolver.submit(() -> {
         InetAddress address = InetAddress.getByAddress(raw);
         String name = address.getCanonicalHostName();
         // The JDK hands back the literal when there is no PTR record.
         return name.equalsIgnoreCase(address.getHostAddress()) ? "" : name;
      });

      try {
         String name = pending.get(timeoutMillis, TimeUnit.MILLISECONDS);
         cache.put(key, name);
         return name.isEmpty() ? Optional.empty() : Optional.of(name);
      } catch (InterruptedException interrupted) {
         Thread.currentThread().interrupt();
         pending.cancel(true);
         return Optional.empty();
      } catch (Exception timedOutOrFailed) {
         pending.cancel(true);
         // Remember the miss briefly so a dead resolver does not cost the budget on every login.
         cache.put(key, "");
         return Optional.empty();
      }
   }

   /**
    * The pattern that matched the address's PTR name, if any.
    *
    * @param patterns substrings to look for, or empty to use the built-in list
    */
   public Optional<String> match(String ip, List<String> patterns) {
      Optional<String> hostname = hostname(ip);
      if (hostname.isEmpty()) {
         return Optional.empty();
      }

      String name = hostname.get().toLowerCase(Locale.ROOT);
      for (String pattern : patterns.isEmpty() ? DEFAULT_PATTERNS : patterns) {
         if (!pattern.isBlank() && name.contains(pattern)) {
            return Optional.of(pattern);
         }
      }
      return Optional.empty();
   }

   /** The built-in pattern list, written into config.yml as the default. */
   public static List<String> defaultPatterns() {
      return DEFAULT_PATTERNS;
   }

   public int cacheSize() {
      return cache.size();
   }

   public void clearCache() {
      cache.clear();
   }

   public void close() {
      resolver.shutdownNow();
   }

   /** Static check for a name already in hand, used by tests and the lookup diagnostics. */
   public static Optional<String> matchName(String hostname, List<String> patterns) {
      if (hostname == null || hostname.isBlank()) {
         return Optional.empty();
      }
      String name = hostname.toLowerCase(Locale.ROOT);
      for (String pattern : patterns.isEmpty() ? DEFAULT_PATTERNS : patterns) {
         if (!pattern.isBlank() && name.contains(pattern)) {
            return Optional.of(pattern);
         }
      }
      return Optional.empty();
   }
}
