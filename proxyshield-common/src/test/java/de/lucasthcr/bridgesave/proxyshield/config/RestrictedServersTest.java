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

package de.lucasthcr.bridgesave.proxyshield.config;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.lucasthcr.bridgesave.proxyshield.testing.MapConfigNode;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Which backends a flagged player may still reach on a proxy. */
class RestrictedServersTest {

   private static ShieldConfig config(String mode, List<String> servers) {
      Map<String, Object> values = new LinkedHashMap<>();
      values.put("restricted.enabled", true);
      values.put("restricted.mode", mode);
      values.put("restricted.servers", servers);
      return ShieldConfig.from(new MapConfigNode(values));
   }

   @Test
   void whitelistModeOnlyAllowsListedServers() {
      ShieldConfig config = config("whitelist", List.of("lobby-\\d+", "auth"));
      assertTrue(config.restrictedAllows("lobby-1"));
      assertTrue(config.restrictedAllows("AUTH"));
      assertFalse(config.restrictedAllows("survival"));
   }

   @Test
   void namesMatchWholeNotAsAPrefix() {
      ShieldConfig config = config("whitelist", List.of("lobby"));
      assertFalse(config.restrictedAllows("lobby-dev"));
   }

   @Test
   void blacklistModeAllowsEverythingElse() {
      ShieldConfig config = config("blacklist", List.of("survival", "skyblock"));
      assertFalse(config.restrictedAllows("survival"));
      assertTrue(config.restrictedAllows("lobby"));
   }

   @Test
   void anEmptyListSwitchesTheFeatureOff() {
      assertFalse(config("whitelist", List.of()).restrictedEnabled());
   }
}
