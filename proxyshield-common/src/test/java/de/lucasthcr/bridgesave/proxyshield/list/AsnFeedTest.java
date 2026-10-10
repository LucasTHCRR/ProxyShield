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

package de.lucasthcr.bridgesave.proxyshield.list;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Set;
import org.junit.jupiter.api.Test;

/** The shapes a downloaded ASN list can come in. */
class AsnFeedTest {

   @Test
   void plainTextTakesTheFirstNumberOfEachLine() {
      Set<String> asns = AsnFeed.parse("""
            # VPN networks
            AS9009 M247 Europe
            62240
            as16276 OVH

            not a number""");
      assertEquals(Set.of("AS9009", "AS62240", "AS16276"), asns);
   }

   @Test
   void jsonArraysOfNumbersStringsAndObjects() {
      assertEquals(Set.of("AS9009", "AS62240"), AsnFeed.parse("[9009, \"AS62240\"]"));
      assertEquals(Set.of("AS212238"),
            AsnFeed.parse("[{\"asn\": 212238, \"name\": \"Datacamp\"}, {\"name\": \"none\"}]"));
   }

   @Test
   void leadingZerosAndCaseAreNormalised() {
      assertEquals(Set.of("AS9009"), AsnFeed.parse("[\"as09009\"]"));
   }
}
