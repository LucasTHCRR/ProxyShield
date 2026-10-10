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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The per-address account history behind {@code /proxyshield alts}. */
class AltTrackerTest {

   @TempDir
   Path tempDir;

   @Test
   void accountsOnOneAddressAreListedNewestFirst() {
      AtomicLong now = new AtomicLong(1_000L);
      AltTracker tracker = new AltTracker(tempDir.resolve("alts.tsv"), now::get);
      tracker.record("8.8.4.4", UUID.randomUUID(), "Main");
      now.addAndGet(1_000L);
      tracker.record("8.8.4.4", UUID.randomUUID(), "Alt");
      tracker.record("1.1.1.1", UUID.randomUUID(), "Other");

      var accounts = tracker.accountsOn("8.8.4.4");
      assertEquals(2, accounts.size());
      assertEquals("Alt", accounts.get(0).name());
   }

   @Test
   void aPlayerNameFindsEveryAddressItUsed() {
      AltTracker tracker = new AltTracker(tempDir.resolve("alts.tsv"));
      UUID uuid = UUID.randomUUID();
      tracker.record("8.8.4.4", uuid, "Steve");
      tracker.record("1.1.1.1", uuid, "Steve");
      assertEquals(2, tracker.addressesOf("steve").size());
   }

   @Test
   void historySurvivesARestartAndOldSightingsArePruned() throws IOException {
      AtomicLong now = new AtomicLong(100L * 86_400_000L);
      Path file = tempDir.resolve("alts.tsv");
      AltTracker tracker = new AltTracker(file, now::get);
      tracker.record("8.8.4.4", UUID.randomUUID(), "Old");
      now.addAndGet(40L * 86_400_000L);
      tracker.record("8.8.4.4", UUID.randomUUID(), "Recent");
      tracker.save(30);

      AltTracker reloaded = new AltTracker(file, now::get);
      reloaded.load();
      var accounts = reloaded.accountsOn("8.8.4.4");
      assertEquals(1, accounts.size());
      assertEquals("Recent", accounts.get(0).name());
   }

   @Test
   void ipv6ClientsAreGroupedByTheirPrefix() {
      AltTracker tracker = new AltTracker(tempDir.resolve("alts.tsv"));
      tracker.record("2a00:1450:4001:1::1", UUID.randomUUID(), "A");
      tracker.record("2a00:1450:4001:1::2", UUID.randomUUID(), "B");
      assertTrue(tracker.accountsOn("2a00:1450:4001:1::99").size() >= 2);
   }
}
