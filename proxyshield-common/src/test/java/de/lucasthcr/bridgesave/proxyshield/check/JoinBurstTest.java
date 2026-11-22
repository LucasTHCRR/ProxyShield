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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class JoinBurstTest {

   @Test
   @DisplayName("A wave switches on at the threshold and off after a quiet window")
   void switchesOnAndOff() {
      AtomicLong now = new AtomicLong(1_000);
      JoinBurst burst = new JoinBurst(3, now::get);

      assertFalse(burst.record());
      assertFalse(burst.record());
      assertTrue(burst.record());
      assertTrue(burst.record());

      now.addAndGet(10_000);
      assertTrue(burst.record(), "the window before was busy, so it stays on");
      now.addAndGet(10_000);
      assertFalse(burst.record(), "a full window below the threshold ends it");
   }

   @Test
   @DisplayName("A long pause starts from zero")
   void pauseResets() {
      AtomicLong now = new AtomicLong(0);
      JoinBurst burst = new JoinBurst(2, now::get);
      burst.record();
      assertTrue(burst.record());
      now.addAndGet(60_000);
      assertFalse(burst.record());
   }
}
