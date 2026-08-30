package de.lucasthcr.bridgesave.proxyshield.check;

import de.lucasthcr.bridgesave.proxyshield.net.IpAddresses;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Behavioural signals that need no provider and no quota.
 * <p>
 * Every commercial dataset is a list of addresses somebody already reported. A bot attack from a
 * freshly rented range is invisible to all of them on day one, but not to the server being attacked:
 * thirty accounts appearing out of one /24 inside a minute, or one address cycling through a dozen
 * names, is a shape no normal player base produces. Those signals are what turn a good anti-VPN
 * into one that stops the attack that nobody has catalogued yet.
 * <p>
 * They add weight to the consensus score instead of blocking outright, so a school or a Discord
 * community joining together does not become a mass kick.
 */
public final class JoinHeuristics {

   /** How long a join is remembered for the rate windows. */
   private static final long WINDOW_MILLIS = 60_000L;

   /** How long an address's account list and last country are kept. */
   private static final long MEMORY_MILLIS = 3_600_000L;

   private final Map<String, Deque<Long>> joinsBySubnet = new ConcurrentHashMap<>();
   private final Map<String, AccountsSeen> accountsByIp = new ConcurrentHashMap<>();
   private final Map<UUID, LastLocation> lastLocation = new ConcurrentHashMap<>();

   /** What the heuristics noticed about one connection. */
   public record Signals(int joinsInSubnet, int accountsOnAddress, boolean geoJump,
         Set<String> descriptions) {

      public boolean any() {
         return !descriptions.isEmpty();
      }

      public String summary() {
         return String.join(", ", descriptions);
      }
   }

   /**
    * Records this connection and reports what stands out about it.
    *
    * @param maxJoinsPerSubnet how many joins from one /24 (or v6 /48) per minute are normal
    * @param maxAccountsPerIp  how many distinct accounts one address may use per hour
    * @param geoJumpMinutes    within how many minutes a country change is suspicious, 0 to ignore
    */
   public Signals observe(UUID uuid, String ip, String countryCode, int maxJoinsPerSubnet,
         int maxAccountsPerIp, int geoJumpMinutes) {
      long now = System.currentTimeMillis();
      Set<String> descriptions = new LinkedHashSet<>();

      int joins = recordJoin(IpAddresses.subnetKey(ip), now);
      if (joins > maxJoinsPerSubnet) {
         descriptions.add("burst: " + joins + " joins/min from " + IpAddresses.subnetKey(ip));
      }

      int accounts = recordAccount(ip, uuid, now);
      if (accounts > maxAccountsPerIp) {
         descriptions.add("account sharing: " + accounts + " accounts on this address");
      }

      boolean geoJump = geoJumpMinutes > 0 && recordLocation(uuid, countryCode, now,
            geoJumpMinutes * 60_000L);
      if (geoJump) {
         descriptions.add("country changed within " + geoJumpMinutes + " minutes");
      }

      return new Signals(joins, accounts, geoJump, Set.copyOf(descriptions));
   }

   private int recordJoin(String subnet, long now) {
      Deque<Long> window = joinsBySubnet.computeIfAbsent(subnet, key -> new ArrayDeque<>());
      synchronized (window) {
         window.addLast(now);
         while (!window.isEmpty() && now - window.peekFirst() > WINDOW_MILLIS) {
            window.removeFirst();
         }
         return window.size();
      }
   }

   private int recordAccount(String ip, UUID uuid, long now) {
      if (uuid == null) {
         return 0;
      }
      AccountsSeen seen = accountsByIp.computeIfAbsent(IpAddresses.cacheKey(ip),
            key -> new AccountsSeen());
      synchronized (seen) {
         if (now - seen.since > MEMORY_MILLIS) {
            seen.uuids.clear();
            seen.since = now;
         }
         seen.uuids.add(uuid);
         return seen.uuids.size();
      }
   }

   /** @return whether the account's country changed inside the window */
   private boolean recordLocation(UUID uuid, String countryCode, long now, long windowMillis) {
      if (uuid == null || countryCode == null || countryCode.isBlank()) {
         return false;
      }
      String code = countryCode.trim().toUpperCase(Locale.ROOT);
      LastLocation previous = lastLocation.put(uuid, new LastLocation(code, now));
      return previous != null
            && !previous.countryCode.equals(code)
            && now - previous.at <= windowMillis;
   }

   /** Which accounts have used an address recently, for {@code /proxyshield check}. */
   public Optional<Set<UUID>> accountsOn(String ip) {
      AccountsSeen seen = accountsByIp.get(IpAddresses.cacheKey(ip));
      if (seen == null) {
         return Optional.empty();
      }
      synchronized (seen) {
         return Optional.of(Set.copyOf(seen.uuids));
      }
   }

   /** Drops windows nobody has touched, called from the heartbeat. */
   public int purgeExpired() {
      long now = System.currentTimeMillis();
      int removed = 0;

      for (Map.Entry<String, Deque<Long>> entry : joinsBySubnet.entrySet()) {
         Deque<Long> window = entry.getValue();
         synchronized (window) {
            while (!window.isEmpty() && now - window.peekFirst() > WINDOW_MILLIS) {
               window.removeFirst();
            }
            if (window.isEmpty() && joinsBySubnet.remove(entry.getKey(), window)) {
               removed++;
            }
         }
      }

      for (Map.Entry<String, AccountsSeen> entry : accountsByIp.entrySet()) {
         AccountsSeen seen = entry.getValue();
         synchronized (seen) {
            if (now - seen.since > MEMORY_MILLIS && accountsByIp.remove(entry.getKey(), seen)) {
               removed++;
            }
         }
      }

      lastLocation.entrySet().removeIf(entry -> now - entry.getValue().at > MEMORY_MILLIS);
      return removed;
   }

   public void clear() {
      joinsBySubnet.clear();
      accountsByIp.clear();
      lastLocation.clear();
   }

   private static final class AccountsSeen {
      private final Set<UUID> uuids = new LinkedHashSet<>();
      private long since = System.currentTimeMillis();
   }

   private record LastLocation(String countryCode, long at) {
   }
}
