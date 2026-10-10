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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Reasons, authors and expiry on in-game list entries. */
class ManagedListDetailsTest {

   @TempDir
   Path tempDir;

   @Test
   void aTimedEntryStopsMatchingWhenItRunsOut() throws IOException {
      AtomicLong now = new AtomicLong(1_000_000L);
      ManagedIpList list = new ManagedIpList(tempDir.resolve("w.txt"), now::get);
      list.load();
      assertTrue(list.add("8.8.4.4", "event", "Lucas", 60_000L));
      assertTrue(list.matches("8.8.4.4"));
      now.addAndGet(61_000L);
      assertFalse(list.matches("8.8.4.4"));
      assertTrue(list.runtimeEntries().isEmpty());
   }

   @Test
   void detailsSurviveARestart() throws IOException {
      Path file = tempDir.resolve("w.txt");
      ManagedIpList list = new ManagedIpList(file);
      list.load();
      list.add("10.1.0.0/16", "school network, ticket 42", "Lucas", 0L);

      ManagedIpList reloaded = new ManagedIpList(file);
      reloaded.load();
      ManagedIpList.Details details = reloaded.details("10.1.0.0/16");
      assertEquals("school network, ticket 42", details.reason());
      assertEquals("Lucas", details.addedBy());
      assertTrue(details.permanent());
      assertTrue(reloaded.matches("10.1.2.3"));
   }

   @Test
   void anOlderFileWithHandwrittenNotesStillLoads() throws IOException {
      Path file = tempDir.resolve("w.txt");
      Files.write(file, List.of("# header", "1.2.3.4", "5.6.7.8 # my office"),
            StandardCharsets.UTF_8);
      ManagedIpList list = new ManagedIpList(file);
      list.load();
      assertTrue(list.matches("1.2.3.4"));
      assertNull(list.details("1.2.3.4").reason());
      assertEquals("my office", list.details("5.6.7.8").reason());
   }

   @Test
   void purgeLeavesConfigEntriesAlone() throws IOException {
      ManagedIpList list = new ManagedIpList(tempDir.resolve("w.txt"));
      list.load();
      list.setConfigEntries(List.of("9.9.9.9"));
      list.add("8.8.4.4");
      list.add("8.8.8.8");
      assertEquals(2, list.purge());
      assertTrue(list.matches("9.9.9.9"));
      assertFalse(list.matches("8.8.4.4"));
   }
}
