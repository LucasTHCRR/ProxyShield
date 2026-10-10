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

package de.lucasthcr.bridgesave.proxyshield.check;

import de.lucasthcr.bridgesave.proxyshield.net.IpAddresses;
import de.lucasthcr.bridgesave.proxyshield.platform.ShieldPlayer;
import java.util.ArrayDeque;
import java.util.Collection;
import java.util.Deque;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Caps how many accounts may use one address.
 * <p>
 * Two modes. Without a window the count is the number of players online from the address right
 * now, so a slot frees up the moment somebody leaves. With a window the count is the number of
 * accounts admitted from the address inside it, which also stops a bot that joins, leaves and
 * rejoins on a fresh name, and resets on its own once the window has passed.
 * <p>
 * Unlike {@code heuristics.max-accounts-per-ip}, which only adds weight to the score, this is a
 * hard limit: the connection over the cap is refused outright.
 */
public final class ConnectionLimiter {

   private final LongSupplier clock;
   private final Map<String, Deque<Admission>> admissions = new ConcurrentHashMap<>();

   public ConnectionLimiter() {
      this(System::currentTimeMillis);
   }

   ConnectionLimiter(LongSupplier clock) {
      this.clock = clock;
   }

   private record Admission(UUID uuid, long at) {
   }

   /**
    * Decides whether one more account may join from {@code ip}.
    *
    * @param online the players currently connected, used when {@code windowMinutes} is 0
    * @param windowMinutes 0 to count players online, otherwise the counting window
    * @return {@code true} if the connection is over the limit and must be refused
    */
   public boolean exceeds(String ip, UUID uuid, int max, int windowMinutes,
         Collection<? extends ShieldPlayer> online) {
      String key = IpAddresses.cacheKey(ip);
      if (key == null) {
         return false;
      }
      if (windowMinutes <= 0) {
         int count = 0;
         for (ShieldPlayer player : online) {
            if (uuid != null && uuid.equals(player.uuid())) {
               // The same account reconnecting replaces its old session rather than adding one.
               continue;
            }
            String other = player.ip();
            if (other != null && key.equals(IpAddresses.cacheKey(other))) {
               count++;
            }
         }
         return count >= max;
      }

      long now = clock.getAsLong();
      long cutoff = now - windowMinutes * 60_000L;
      Deque<Admission> recent = admissions.computeIfAbsent(key, ignored -> new ArrayDeque<>());
      synchronized (recent) {
         while (!recent.isEmpty() && recent.peekFirst().at() < cutoff) {
            recent.pollFirst();
         }
         if (uuid != null) {
            for (Admission admission : recent) {
               if (uuid.equals(admission.uuid())) {
                  return false; // already counted inside this window
               }
            }
         }
         if (recent.size() >= max) {
            return true;
         }
         recent.addLast(new Admission(uuid, now));
         return false;
      }
   }

   /** Drops addresses whose window has fully elapsed. */
   public void purgeExpired(int windowMinutes) {
      if (windowMinutes <= 0) {
         admissions.clear();
         return;
      }
      long cutoff = clock.getAsLong() - windowMinutes * 60_000L;
      admissions.values().removeIf(recent -> {
         synchronized (recent) {
            return recent.isEmpty() || recent.peekLast().at() < cutoff;
         }
      });
   }
}
