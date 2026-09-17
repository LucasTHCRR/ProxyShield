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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** What the built-in PTR patterns do and do not catch. */
class ReverseDnsTest {

   private static Optional<String> match(String hostname) {
      return ReverseDns.matchName(hostname, ReverseDns.defaultPatterns());
   }

   @Nested
   @DisplayName("Real PTR records from VPN exits")
   class KnownExits {

      /**
       * ProtonVPN names its exits after the mail brand. The list carried "protonvpn", which
       * matched none of the seventeen ranges Proton announces, so the one pattern aimed at
       * Proton never fired on Proton.
       */
      @Test
      @DisplayName("A ProtonVPN exit resolves to protonmail.ch and has to match")
      void protonExitsAreCaught() {
         assertTrue(match("185-70-41-1.protonmail.ch").isPresent());
         assertTrue(match("109-224-244-1.protonmail.ch").isPresent());
         assertTrue(match("176-119-200-1.protonmail.ch").isPresent());
      }

      @Test
      @DisplayName("hosted-by-<name> is as much a hoster as hosting is")
      void hostedByIsCaught() {
         assertTrue(match("62-112-9-243.hosted-by-worldstream.net").isPresent());
      }

      @Test
      void theOldPatternsStillWork() {
         assertTrue(match("mad-01.torguard.io").isPresent());
         assertTrue(match("vpn-gw3.example.net").isPresent());
         assertTrue(match("static.hosting.provider").isPresent());
      }
   }

   @Nested
   @DisplayName("Ordinary connections stay clean")
   class Residential {

      @Test
      void aGermanHomeLineDoesNotMatch() {
         assertEquals(Optional.empty(), match("p5dcb1234.dip0.t-ipconnect.de"));
      }

      @Test
      void aBritishHomeLineDoesNotMatch() {
         assertEquals(Optional.empty(), match("host-92-22-10-5.as13285.net"));
      }

      @Test
      void aMobileCarrierDoesNotMatch() {
         assertEquals(Optional.empty(), match("mm-12-34-56-78.dynamic.pppoe.byfly.by"));
      }
   }

   @Nested
   @DisplayName("The name a PTR record lives under")
   class ArpaNames {

      /**
       * The lookup asks for this name directly rather than going through
       * InetAddress.getCanonicalHostName(), which drops any PTR whose name has no matching A
       * record. VPN operators publish exactly that kind of PTR, so the JDK call reported no name
       * at all for every ProtonVPN exit.
       */
      @Test
      void ipv4IsReversedOctetByOctet() {
         assertEquals("1.41.70.185.in-addr.arpa",
               ReverseDns.arpaName(new byte[] {(byte) 185, 70, 41, 1}));
      }

      @Test
      void ipv4HandlesOctetsAboveTheSignedRange() {
         assertEquals("255.255.255.255.in-addr.arpa",
               ReverseDns.arpaName(new byte[] {(byte) 255, (byte) 255, (byte) 255, (byte) 255}));
      }

      @Test
      void ipv6IsReversedNibbleByNibble() {
         byte[] one = new byte[16];
         one[15] = 1;
         assertEquals("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
               ReverseDns.arpaName(one));
      }

      @Test
      void anythingElseHasNoArpaName() {
         assertNull(ReverseDns.arpaName(new byte[] {1, 2, 3}));
      }
   }

   @Test
   @DisplayName("The pattern that matched is named, so the log says why")
   void reportsWhichPatternMatched() {
      assertEquals(Optional.of("protonmail"), match("185-70-41-1.protonmail.ch"));
   }

   @Test
   void anEmptyHostnameMatchesNothing() {
      assertEquals(Optional.empty(), match(""));
      assertEquals(Optional.empty(), ReverseDns.matchName("anything.example", List.of()));
   }
}
