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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.Test;

class IntelDatabaseTest {

   // Gebaut mit intel-build aus vier Mini-Listen
   private static IntelDatabase database() throws IOException {
      try (InputStream in = new GZIPInputStream(
            IntelDatabaseTest.class.getClassLoader().getResourceAsStream("intel-test.mmdb.gz"))) {
         return new IntelDatabase(in.readAllBytes());
      }
   }

   @Test
   void operatorRelayIsVpnWithTopScore() throws IOException {
      IntelDatabase.Hit hit = database().lookup("1.2.3.77");
      assertTrue(hit.vpn());
      assertEquals(100, hit.score());
      assertEquals(List.of("vpn-operator"), hit.reasons());
   }

   @Test
   void torProxyAndHostingAreTold() throws IOException {
      IntelDatabase db = database();
      assertTrue(db.lookup("5.5.5.5").tor());
      assertTrue(db.lookup("7.7.7.7").proxy());
      IntelDatabase.Hit hosting = db.lookup("9.9.9.200");
      assertTrue(hosting.hosting());
      assertFalse(hosting.vpn());
      assertEquals(55, hosting.score());
   }

   @Test
   void unknownAddressesGiveNothing() throws IOException {
      IntelDatabase db = database();
      assertNull(db.lookup("8.8.8.8"));
      assertNull(db.lookup("1.2.4.1"));
      assertNull(db.lookup("2a01:4f8::1"));
      assertNull(db.lookup("not an ip"));
   }

   @Test
   void metadataIsRead() throws IOException {
      IntelDatabase db = database();
      assertTrue(db.loaded());
      assertTrue(db.buildEpoch() > 1_700_000_000L);
      assertTrue(db.nodeCount() > 0);
   }

   @Test
   void shippedSnapshotIsSignedByIntel() throws IOException {
      // Der Snapshot wird erst beim Release geladen und liegt nicht im Repo
      org.junit.jupiter.api.Assumptions.assumeTrue(
            IntelDatabaseTest.class.getClassLoader().getResource("intel-snapshot.sig") != null);
      byte[] snapshot = IntelDatabaseTest.class.getClassLoader().getResourceAsStream("intel-snapshot.mmdb.gz").readAllBytes();
      String signature = new String(IntelDatabaseTest.class.getClassLoader()
            .getResourceAsStream("intel-snapshot.sig").readAllBytes(), java.nio.charset.StandardCharsets.US_ASCII);
      assertTrue(IntelDatabase.verify(snapshot, signature));
      snapshot[100] ^= 1;
      assertFalse(IntelDatabase.verify(snapshot, signature));
      assertFalse(IntelDatabase.verify(snapshot, "not base64 !"));
   }

   @Test
   void garbageIsRefused() {
      assertThrows(IOException.class, () -> new IntelDatabase(new byte[] {1, 2, 3}));
   }
}
