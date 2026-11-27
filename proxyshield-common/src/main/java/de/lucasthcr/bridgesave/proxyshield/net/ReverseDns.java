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

package de.lucasthcr.bridgesave.proxyshield.net;

import de.lucasthcr.bridgesave.proxyshield.cache.ExpiringCache;
import java.net.InetAddress;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;

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

   /**
    * {@code protonmail} is not a stray entry. ProtonVPN names its exits after the mail brand, so a
    * Swiss exit resolves to {@code 185-70-41-1.protonmail.ch} and {@code protonvpn} on its own
    * matched none of the seventeen ranges Proton announces. {@code hosted} sits next to
    * {@code hosting} for the same reason: {@code hosted-by-<name>.net} is a common shape and the
    * longer word does not cover it.
    */
   private static final List<String> DEFAULT_PATTERNS = List.of(
         "vpn", "proxy", "tor-exit", "torexit", "torguard", "nordvpn", "expressvpn",
         "surfshark", "cyberghost", "privateinternetaccess", "mullvad", "protonvpn",
         "protonmail", "ipvanish", "purevpn", "windscribe", "hidemyass", "datacenter",
         "data-center", "hosting", "hosted", "colo", "cloud", "server", "dedicated", "vps");

   private final ExecutorService resolver;
   private final ExpiringCache<String, String> cache;
   private final int timeoutMillis;

   /**
    * One DNS context for the lifetime of the plugin. Building it costs several hundred
    * milliseconds, which is most of the budget a single lookup is given, so doing it per query
    * made the first lookup after a restart time out on the shipped 700 ms. Held behind a lock
    * because the JNDI DNS context is not thread safe; queries cost about a millisecond once it is
    * warm and the cache keeps the rate to one per address per TTL.
    */
   private final Object dnsLock = new Object();
   private InitialDirContext dns;
   private boolean dnsUnavailable;

   public ReverseDns(int timeoutMillis, int maxCacheEntries, long cacheTtlMillis) {
      this.timeoutMillis = Math.max(50, timeoutMillis);
      this.cache = new ExpiringCache<>(maxCacheEntries, cacheTtlMillis);
      // Begrenzt: bei einer Welle wird rDNS lieber ausgelassen als unbegrenzt Threads zu starten
      this.resolver = new java.util.concurrent.ThreadPoolExecutor(2, 16, 60L, java.util.concurrent.TimeUnit.SECONDS,
            new java.util.concurrent.ArrayBlockingQueue<>(256), daemonThreads(),
            new java.util.concurrent.ThreadPoolExecutor.DiscardPolicy());
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
      return hostname(ip, Long.MAX_VALUE);
   }

   // graceMillis: hoechstens so lange noch warten, auch wenn das Budget mehr erlaubt
   public Optional<String> hostname(String ip, long graceMillis) {
      byte[] raw = IpAddresses.parseLiteral(ip);
      if (raw == null) {
         return Optional.empty();
      }

      String key = IpAddresses.cacheKey(ip);
      Optional<String> cached = cache.get(key);
      if (cached.isPresent()) {
         return cached.get().isEmpty() ? Optional.empty() : cached;
      }
      if (System.currentTimeMillis() < resolverDownUntil) {
         return Optional.empty();
      }

      Started started = inFlight.computeIfAbsent(key,
            k -> new Started(resolver.submit(() -> resolvePtr(raw)), System.currentTimeMillis()));
      long wait = Math.max(1, Math.min(graceMillis, timeoutMillis - (System.currentTimeMillis() - started.at())));

      try {
         String name = started.future().get(wait, TimeUnit.MILLISECONDS);
         cache.put(key, name);
         timeoutsInARow.set(0);
         return name.isEmpty() ? Optional.empty() : Optional.of(name);
      } catch (InterruptedException interrupted) {
         Thread.currentThread().interrupt();
         started.future().cancel(true);
         return Optional.empty();
      } catch (Exception timedOutOrFailed) {
         started.future().cancel(true);
         // Remember the miss briefly so a dead resolver does not cost the budget on every login.
         cache.put(key, "");
         // Drei Timeouts am Stueck: Resolver gilt fuer 5 Minuten als tot
         if (System.currentTimeMillis() - started.at() >= timeoutMillis
               && timeoutsInARow.incrementAndGet() >= 3) {
            resolverDownUntil = System.currentTimeMillis() + 300_000L;
            timeoutsInARow.set(0);
         }
         return Optional.empty();
      } finally {
         inFlight.remove(key, started);
      }
   }

   // Beim Start einmal pruefen, ob DNS antwortet, sonst warten die ersten Joins umsonst
   public void probe() {
      byte[] probe = {1, 1, 1, 1};
      Thread thread = new Thread(() -> {
         Future<String> pending = resolver.submit(() -> resolvePtr(probe));
         try {
            pending.get(timeoutMillis, TimeUnit.MILLISECONDS);
         } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
         } catch (Exception deadResolver) {
            pending.cancel(true);
            resolverDownUntil = System.currentTimeMillis() + 300_000L;
         }
      }, "ProxyShield-rdns-probe");
      thread.setDaemon(true);
      thread.start();
   }

   /** Starts the lookup early, so it runs while the providers are asked. */
   public void prefetch(String ip) {
      byte[] raw = IpAddresses.parseLiteral(ip);
      if (raw == null || System.currentTimeMillis() < resolverDownUntil) {
         return;
      }
      String key = IpAddresses.cacheKey(ip);
      if (cache.get(key).isPresent()) {
         return;
      }
      inFlight.computeIfAbsent(key,
            k -> new Started(resolver.submit(() -> resolvePtr(raw)), System.currentTimeMillis()));
   }

   private record Started(Future<String> future, long at) {
   }

   private final java.util.concurrent.ConcurrentHashMap<String, Started> inFlight =
         new java.util.concurrent.ConcurrentHashMap<>();
   private final AtomicInteger timeoutsInARow = new AtomicInteger();
   private volatile long resolverDownUntil;

   /**
    * Asks for the PTR record itself instead of going through {@link
    * InetAddress#getCanonicalHostName()}.
    * <p>
    * That method performs a forward confirmed reverse lookup: it reads the PTR, resolves the name
    * it got back, and discards it unless the original address is among the answers. VPN operators
    * routinely publish a PTR with no matching A record, so the confirmation fails and the JDK
    * hands back the literal. ProtonVPN is the case that exposed this: every exit answers {@code
    * 185-70-41-1.protonmail.ch} to dig, {@code 185-70-41-1.protonmail.ch} has no A record, and the
    * plugin therefore saw no PTR at all on precisely the addresses the check exists to catch.
    * <p>
    * JNDI's DNS provider returns the record as published. The JDK lookup stays as a fallback for
    * an environment where JNDI is unavailable, since it still works for anything that does
    * forward confirm.
    */
   private String resolvePtr(byte[] raw) throws Exception {
      String query = arpaName(raw);
      if (query != null) {
         try {
            synchronized (dnsLock) {
               InitialDirContext context = dnsContext();
               if (context != null) {
                  Attributes attributes = context.getAttributes(query, new String[] {"PTR"});
                  Attribute ptr = attributes.get("PTR");
                  if (ptr != null && ptr.size() > 0) {
                     String name = String.valueOf(ptr.get(0));
                     // A PTR is published with the trailing dot; nothing downstream wants it.
                     return name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
                  }
                  return "";
               }
            }
         } catch (NamingException | NoClassDefFoundError unavailable) {
            // Fall through to the JDK lookup below.
         }
      }

      InetAddress address = InetAddress.getByAddress(raw);
      String name = address.getCanonicalHostName();
      // The JDK hands back the literal when there is no PTR record.
      return name.equalsIgnoreCase(address.getHostAddress()) ? "" : name;
   }

   /** The shared DNS context, built on first use. Null once JNDI has proven unavailable. */
   private InitialDirContext dnsContext() {
      if (dns == null && !dnsUnavailable) {
         try {
            Hashtable<String, String> environment = new Hashtable<>();
            environment.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            environment.put("com.sun.jndi.dns.timeout.initial", String.valueOf(timeoutMillis));
            environment.put("com.sun.jndi.dns.timeout.retries", "1");
            dns = new InitialDirContext(environment);
         } catch (NamingException | NoClassDefFoundError unavailable) {
            dnsUnavailable = true;
         }
      }
      return dns;
   }

   /**
    * The address written as the name its PTR record lives under: {@code 1.41.70.185.in-addr.arpa}
    * for IPv4, and the nibble form under {@code ip6.arpa} for IPv6.
    */
   static String arpaName(byte[] raw) {
      StringBuilder name = new StringBuilder();
      if (raw.length == 4) {
         for (int i = 3; i >= 0; i--) {
            name.append(raw[i] & 0xFF).append('.');
         }
         return name.append("in-addr.arpa").toString();
      }
      if (raw.length == 16) {
         for (int i = 15; i >= 0; i--) {
            int octet = raw[i] & 0xFF;
            name.append(Character.forDigit(octet & 0x0F, 16)).append('.');
            name.append(Character.forDigit(octet >> 4, 16)).append('.');
         }
         return name.append("ip6.arpa").toString();
      }
      return null;
   }

   /**
    * The pattern that matched the address's PTR name, if any.
    *
    * @param patterns substrings to look for, or empty to use the built-in list
    */
   public Optional<String> match(String ip, List<String> patterns) {
      return match(ip, patterns, Long.MAX_VALUE);
   }

   public Optional<String> match(String ip, List<String> patterns, long graceMillis) {
      Optional<String> hostname = hostname(ip, graceMillis);
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
      synchronized (dnsLock) {
         if (dns != null) {
            try {
               dns.close();
            } catch (NamingException ignored) {
               // Nothing useful to do while shutting down.
            }
            dns = null;
         }
      }
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
