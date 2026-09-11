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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class IpRangeSetTest {

   @Nested
   @DisplayName("CIDR blocks cover their whole range")
   class Cidr {

      /**
       * The defect that made v1's list check useless: the prefix was discarded and matching was a
       * string comparison, so only the network address itself ever matched.
       */
      @Test
      void slash24CoversEveryHost() {
         IpRangeSet set = IpRangeSet.of(List.of("1.2.3.0/24"));

         assertTrue(set.contains("1.2.3.0"), "network address");
         assertTrue(set.contains("1.2.3.1"), "first host");
         assertTrue(set.contains("1.2.3.128"), "middle host");
         assertTrue(set.contains("1.2.3.255"), "broadcast address");
         assertEquals(256, set.addressCount());
      }

      @Test
      void slash24ExcludesNeighbours() {
         IpRangeSet set = IpRangeSet.of(List.of("1.2.3.0/24"));

         assertFalse(set.contains("1.2.2.255"));
         assertFalse(set.contains("1.2.4.0"));
      }

      @Test
      void slash32IsASingleAddress() {
         IpRangeSet set = IpRangeSet.of(List.of("8.8.8.8/32"));

         assertTrue(set.contains("8.8.8.8"));
         assertFalse(set.contains("8.8.8.9"));
         assertEquals(1, set.addressCount());
      }

      @Test
      void slash0CoversEverything() {
         IpRangeSet set = IpRangeSet.of(List.of("0.0.0.0/0"));

         assertTrue(set.contains("0.0.0.0"));
         assertTrue(set.contains("203.0.113.7"));
         assertTrue(set.contains("255.255.255.255"));
      }

      /** Addresses above 127.x set the high bit, which breaks signed comparison. */
      @Test
      void handlesAddressesAboveSignedRange() {
         IpRangeSet set = IpRangeSet.of(List.of("240.0.0.0/4"));

         assertTrue(set.contains("240.0.0.0"));
         assertTrue(set.contains("250.1.2.3"));
         assertTrue(set.contains("255.255.255.255"));
         assertFalse(set.contains("239.255.255.255"));
      }
   }

   @Nested
   @DisplayName("Explicit ranges")
   class Ranges {

      @Test
      void inclusiveOnBothEnds() {
         IpRangeSet set = IpRangeSet.of(List.of("10.0.0.5-10.0.0.9"));

         assertFalse(set.contains("10.0.0.4"));
         assertTrue(set.contains("10.0.0.5"));
         assertTrue(set.contains("10.0.0.9"));
         assertFalse(set.contains("10.0.0.10"));
      }

      @Test
      void reversedBoundsAreNormalised() {
         IpRangeSet set = IpRangeSet.of(List.of("10.0.0.9-10.0.0.5"));

         assertTrue(set.contains("10.0.0.7"));
      }
   }

   @Nested
   @DisplayName("Merging")
   class Merging {

      @Test
      void adjacentBlocksCollapseIntoOne() {
         IpRangeSet set = IpRangeSet.of(List.of("1.0.0.0/24", "1.0.1.0/24", "1.0.2.0/24"));

         assertEquals(1, set.rangeCount());
         assertEquals(768, set.addressCount());
         assertTrue(set.contains("1.0.1.55"));
      }

      @Test
      void containedBlockIsAbsorbed() {
         IpRangeSet set = IpRangeSet.of(List.of("2.0.0.0/16", "2.0.5.0/24"));

         assertEquals(1, set.rangeCount());
         assertEquals(65536, set.addressCount());
         assertTrue(set.contains("2.0.5.5"));
      }

      @Test
      void disjointBlocksStaySeparate() {
         IpRangeSet set = IpRangeSet.of(List.of("1.0.0.0/24", "9.0.0.0/24"));

         assertEquals(2, set.rangeCount());
         assertFalse(set.contains("5.0.0.1"));
      }
   }

   @Nested
   @DisplayName("IPv6")
   class Ipv6 {

      @Test
      void cidrMatchesInsideAndNotOutside() {
         IpRangeSet set = IpRangeSet.of(List.of("2001:db8::/32"));

         assertTrue(set.contains("2001:db8::1"));
         assertTrue(set.contains("2001:db8:1234::1"));
         assertFalse(set.contains("2001:db9::1"));
      }

      @Test
      void singleAddressMatchesItsExpandedForm() {
         IpRangeSet set = IpRangeSet.of(List.of("::1"));

         assertTrue(set.contains("0:0:0:0:0:0:0:1"));
      }

      @Test
      void doesNotCrossOverWithIpv4() {
         IpRangeSet v6 = IpRangeSet.of(List.of("2001:db8::/32"));
         IpRangeSet v4 = IpRangeSet.of(List.of("1.2.3.0/24"));

         assertFalse(v6.contains("1.2.3.4"));
         assertFalse(v4.contains("2001:db8::1"));
      }
   }

   @Nested
   @DisplayName("Real world feed noise")
   class FeedNoise {

      @Test
      void ignoresCommentsAndBlankLines() {
         IpRangeSet set = IpRangeSet.of(List.of("# a comment", "// another", "", "   ", "; third"));

         assertTrue(set.isEmpty());
      }

      @Test
      void acceptsEntriesWithTrailingText() {
         IpRangeSet set = IpRangeSet.of(List.of(
               "5.5.5.0/24 SomeVpnProvider",
               "6.6.6.6 # inline comment",
               "7.7.7.0/24,"));

         assertTrue(set.contains("5.5.5.99"));
         assertTrue(set.contains("6.6.6.6"));
         assertTrue(set.contains("7.7.7.1"));
      }

      @Test
      void rejectsMalformedEntriesWithoutLosingGoodOnes() {
         IpRangeSet.Builder builder = IpRangeSet.builder();
         builder.add("not-an-ip");
         builder.add("999.999.999.999");
         builder.add("1.2.3.0/99");
         builder.add("1.1.1.1");

         assertEquals(1, builder.accepted());
         assertEquals(3, builder.rejected());
         assertTrue(builder.build().contains("1.1.1.1"));
      }
   }

   @Test
   void emptySetMatchesNothing() {
      assertTrue(IpRangeSet.EMPTY.isEmpty());
      assertFalse(IpRangeSet.EMPTY.contains("1.2.3.4"));
      assertEquals(0, IpRangeSet.EMPTY.addressCount());
   }
}
