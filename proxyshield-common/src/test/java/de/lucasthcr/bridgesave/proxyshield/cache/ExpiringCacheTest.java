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

package de.lucasthcr.bridgesave.proxyshield.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ExpiringCacheTest {

   @Test
   void returnsWhatWasStored() {
      ExpiringCache<String, String> cache = new ExpiringCache<>(10, 60_000L);
      cache.put("a", "1");

      assertEquals("1", cache.get("a").orElseThrow());
      assertTrue(cache.get("missing").isEmpty());
   }

   @Test
   void entriesExpire() throws InterruptedException {
      ExpiringCache<String, String> cache = new ExpiringCache<>(10, 30L);
      cache.put("a", "1");
      assertTrue(cache.get("a").isPresent());

      Thread.sleep(60L);
      assertTrue(cache.get("a").isEmpty(), "entry should have expired");
   }

   /** v1 never evicted anything, so a busy proxy grew one entry per address forever. */
   @Test
   void evictsLeastRecentlyUsedWhenFull() {
      ExpiringCache<String, String> cache = new ExpiringCache<>(3, 60_000L);
      cache.put("a", "1");
      cache.put("b", "2");
      cache.put("c", "3");

      // Touch "a" so "b" becomes the least recently used entry.
      cache.get("a");
      cache.put("d", "4");

      assertEquals(3, cache.size());
      assertTrue(cache.get("a").isPresent(), "recently used entry survives");
      assertTrue(cache.get("b").isEmpty(), "least recently used entry was evicted");
      assertTrue(cache.get("d").isPresent());
   }

   @Test
   void purgeRemovesOnlyExpiredEntries() throws InterruptedException {
      ExpiringCache<String, String> shortLived = new ExpiringCache<>(10, 30L);
      shortLived.put("a", "1");
      Thread.sleep(60L);
      shortLived.put("b", "2");

      assertEquals(1, shortLived.purgeExpired());
      assertEquals(1, shortLived.size());
   }

   @Test
   void tracksHitsAndMisses() {
      ExpiringCache<String, String> cache = new ExpiringCache<>(10, 60_000L);
      cache.put("a", "1");

      cache.get("a");
      cache.get("a");
      cache.get("nope");

      assertEquals(2, cache.hits());
      assertEquals(1, cache.misses());
   }

   @Test
   void invalidateAndClear() {
      ExpiringCache<String, String> cache = new ExpiringCache<>(10, 60_000L);
      cache.put("a", "1");
      cache.put("b", "2");

      cache.invalidate("a");
      assertFalse(cache.get("a").isPresent());
      assertEquals(1, cache.size());

      cache.clear();
      assertEquals(0, cache.size());
   }
}
