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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AppealStoreTest {

   private final AtomicLong now = new AtomicLong(1_000_000L);
   private final AppealStore store = new AppealStore(60_000L, now::get);

   @Test
   @DisplayName("A code leads back to the address and the player, case and prefix do not matter")
   void codeResolves() {
      String code = store.issue("203.0.113.9", "Steve");
      assertTrue(code.startsWith("PS-"));
      AppealStore.Entry entry = store.resolve(code.toLowerCase()).orElseThrow();
      assertEquals("203.0.113.9", entry.ip());
      assertEquals("Steve", entry.player());
      assertTrue(store.resolve(code.substring(3)).isPresent());
   }

   @Test
   @DisplayName("The same address keeps its code, another address gets another one")
   void sameAddressSameCode() {
      String first = store.issue("203.0.113.9", "Steve");
      assertEquals(first, store.issue("203.0.113.9", "Alex"));
      assertNotEquals(first, store.issue("203.0.113.10", "Alex"));
   }

   @Test
   @DisplayName("A code expires and unknown codes find nothing")
   void expiry() {
      String code = store.issue("203.0.113.9", "Steve");
      now.addAndGet(60_001L);
      assertTrue(store.resolve(code).isEmpty());
      assertTrue(store.resolve("PS-ZZZZZ").isEmpty());
      assertTrue(store.resolve(null).isEmpty());
   }

   @Test
   @DisplayName("The store stays bounded")
   void bounded() {
      String first = store.issue("10.0.0.1", "A");
      for (int i = 2; i <= 600; i++) {
         store.issue("10.0." + (i / 250) + "." + (i % 250), "P" + i);
      }
      assertTrue(store.resolve(first).isEmpty(), "the oldest entry should have been dropped");
   }
}
