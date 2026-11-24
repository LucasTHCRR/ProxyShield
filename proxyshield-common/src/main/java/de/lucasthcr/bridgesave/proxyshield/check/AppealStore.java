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

import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.LongSupplier;

/**
 * Short codes for refused players. The code is shown on the kick screen, a staff member enters it and the
 * address is let through for a while. Kept in memory only, bounded, and gone after a restart.
 */
public final class AppealStore {

   private static final String ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
   private static final int CODE_LENGTH = 5;
   private static final int MAX_ENTRIES = 500;

   /** What a code stands for. */
   public record Entry(String ip, String player, long expiresAt) {
   }

   private final SecureRandom random = new SecureRandom();
   private final LongSupplier clock;
   private final long ttlMillis;
   private final Map<String, Entry> byCode = new LinkedHashMap<>();
   private final Map<String, String> byIp = new LinkedHashMap<>();

   public AppealStore(long ttlMillis) {
      this(ttlMillis, System::currentTimeMillis);
   }

   AppealStore(long ttlMillis, LongSupplier clock) {
      this.ttlMillis = ttlMillis;
      this.clock = clock;
   }

   /** Gives the address a code. The same address keeps its code while it is valid. */
   public synchronized String issue(String ip, String player) {
      long now = clock.getAsLong();
      purge(now);
      String known = byIp.get(ip);
      if (known != null && byCode.containsKey(known)) {
         byCode.put(known, new Entry(ip, player, now + ttlMillis));
         return "PS-" + known;
      }
      String code;
      do {
         StringBuilder builder = new StringBuilder(CODE_LENGTH);
         for (int i = 0; i < CODE_LENGTH; i++) {
            builder.append(ALPHABET.charAt(random.nextInt(ALPHABET.length())));
         }
         code = builder.toString();
      } while (byCode.containsKey(code));
      byCode.put(code, new Entry(ip, player, now + ttlMillis));
      byIp.put(ip, code);
      while (byCode.size() > MAX_ENTRIES) {
         String eldest = byCode.keySet().iterator().next();
         Entry removed = byCode.remove(eldest);
         byIp.remove(removed.ip());
      }
      return "PS-" + code;
   }

   /** The address behind a code, if it is still valid. Lower case and a missing prefix are fine. */
   public synchronized Optional<Entry> resolve(String input) {
      if (input == null) {
         return Optional.empty();
      }
      String code = input.trim().toUpperCase(Locale.ROOT);
      if (code.startsWith("PS-")) {
         code = code.substring(3);
      }
      Entry entry = byCode.get(code);
      if (entry == null || entry.expiresAt() < clock.getAsLong()) {
         return Optional.empty();
      }
      return Optional.of(entry);
   }

   private void purge(long now) {
      byCode.entrySet().removeIf(item -> {
         boolean gone = item.getValue().expiresAt() < now;
         if (gone) {
            byIp.remove(item.getValue().ip());
         }
         return gone;
      });
   }
}
