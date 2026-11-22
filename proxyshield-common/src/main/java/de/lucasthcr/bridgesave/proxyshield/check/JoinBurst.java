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

import java.util.function.LongSupplier;

public final class JoinBurst {

   private static final long WINDOW_MILLIS = 10_000L;

   private final int threshold;
   private final LongSupplier clock;
   private long windowStart;
   private int count;
   private boolean active;

   public JoinBurst(int threshold, LongSupplier clock) {
      this.threshold = Math.max(1, threshold);
      this.clock = clock;
      this.windowStart = clock.getAsLong();
   }

   // Zaehlt einen Beitritt und sagt, ob gerade ein Ansturm laeuft
   public synchronized boolean record() {
      long now = clock.getAsLong();
      if (now - windowStart >= WINDOW_MILLIS) {
         active = count >= threshold && now - windowStart < 2 * WINDOW_MILLIS;
         windowStart = now;
         count = 0;
      }
      count++;
      if (count >= threshold) {
         active = true;
      }
      return active;
   }
}
