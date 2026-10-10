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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.list.ListManager;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupProvider;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import de.lucasthcr.bridgesave.proxyshield.net.IpAddresses;
import de.lucasthcr.bridgesave.proxyshield.net.ManagedIpList;
import de.lucasthcr.bridgesave.proxyshield.platform.ShieldPlayer;
import de.lucasthcr.bridgesave.proxyshield.testing.MapConfigNode;
import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform;
import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Bogon addresses, the ISP filter and the per-address connection limit. */
class NetworkRulesTest {

   private static final String PUBLIC_IP = "8.8.4.4";

   @TempDir
   Path tempDir;

   private CheckEngine engine(Map<String, Object> values, LookupProvider provider)
         throws IOException {
      ShieldConfig config = ShieldConfig.from(new MapConfigNode(values));
      ListManager lists = new ListManager(new RecordingPlatform(tempDir));
      lists.refresh(List.of(), 5, false);
      ManagedIpList whitelist = new ManagedIpList(tempDir.resolve("whitelist.txt"));
      ManagedIpList blacklist = new ManagedIpList(tempDir.resolve("blacklist.txt"));
      whitelist.load();
      blacklist.load();
      whitelist.setConfigEntries(config.whitelistIps());
      blacklist.setConfigEntries(config.blacklistIps());
      return new CheckEngine(config, lists, provider, whitelist, blacklist);
   }

   private static Map<String, Object> baseConfig() {
      Map<String, Object> values = new LinkedHashMap<>();
      values.put("detection.use-lists", false);
      values.put("detection.use-api", true);
      values.put("detection.rdns.enabled", false);
      values.put("heuristics.enabled", false);
      values.put("trust.enabled", false);
      return values;
   }

   private static LookupProvider cleanFrom(String isp) {
      return ip -> LookupResult.of(false, false, "DE", "Germany", isp);
   }

   @Nested
   @DisplayName("Bogon addresses")
   class Bogons {

      @Test
      void documentationAndReservedRangesAreBogons() {
         assertTrue(IpAddresses.isBogon("0.1.2.3"));
         assertTrue(IpAddresses.isBogon("192.0.2.10"));
         assertTrue(IpAddresses.isBogon("198.18.0.1"));
         assertTrue(IpAddresses.isBogon("198.51.100.4"));
         assertTrue(IpAddresses.isBogon("203.0.113.7"));
         assertTrue(IpAddresses.isBogon("239.1.1.1"));
         assertTrue(IpAddresses.isBogon("255.255.255.255"));
         assertTrue(IpAddresses.isBogon("2001:db8::1"));
         assertTrue(IpAddresses.isBogon("ff02::1"));
         assertTrue(IpAddresses.isBogon("100::1"));
      }

      @Test
      void routableAndPrivateAddressesAreNot() {
         assertFalse(IpAddresses.isBogon(PUBLIC_IP));
         assertFalse(IpAddresses.isBogon("2a00:1450:4001::1"));
         // Private and overlay space is handled by the local-address rule, not refused here.
         assertFalse(IpAddresses.isBogon("10.0.0.1"));
         assertFalse(IpAddresses.isBogon("100.100.1.1"));
         assertFalse(IpAddresses.isBogon("192.0.3.1"));
      }

      @Test
      void aBogonIsRefusedBeforeAnyLookup() throws IOException {
         boolean[] asked = {false};
         LookupProvider provider = ip -> {
            asked[0] = true;
            return LookupResult.UNKNOWN;
         };
         CheckVerdict verdict = engine(baseConfig(), provider)
               .check("Steve", null, "203.0.113.7", null);
         assertEquals(CheckVerdict.Reason.BOGON, verdict.reason());
         assertFalse(asked[0]);
      }

      @Test
      void theRuleCanBeTurnedOff() throws IOException {
         Map<String, Object> values = baseConfig();
         values.put("detection.block-bogon", false);
         CheckVerdict verdict = engine(values, cleanFrom("Example"))
               .check("Steve", null, "203.0.113.7", null);
         assertFalse(verdict.blocked());
      }

      @Test
      void aWhitelistedBogonStillGetsIn() throws IOException {
         Map<String, Object> values = baseConfig();
         values.put("whitelist.ips", List.of("203.0.113.7"));
         CheckVerdict verdict = engine(values, cleanFrom("Example"))
               .check("Steve", null, "203.0.113.7", null);
         assertEquals(CheckVerdict.Reason.WHITELISTED_IP, verdict.reason());
      }
   }

   @Nested
   @DisplayName("ISP filter")
   class IspFilter {

      @Test
      void aListedIspIsRefusedEvenWhenTheProvidersSayClean() throws IOException {
         Map<String, Object> values = baseConfig();
         values.put("detection.isp.blocked", List.of("m247"));
         CheckVerdict verdict = engine(values, cleanFrom("M247 Europe SRL"))
               .check("Steve", null, PUBLIC_IP, null);
         assertEquals(CheckVerdict.Reason.ISP, verdict.reason());
      }

      @Test
      void patternsAreRegularExpressions() throws IOException {
         Map<String, Object> values = baseConfig();
         values.put("detection.isp.blocked", List.of("^digital ?ocean"));
         assertTrue(engine(values, cleanFrom("DigitalOcean, LLC"))
               .check("Steve", null, PUBLIC_IP, null).blocked());
         assertFalse(engine(values, cleanFrom("Not DigitalOcean"))
               .check("Steve", null, PUBLIC_IP, null).blocked());
      }

      @Test
      void anInvalidRegexIsMatchedLiterally() throws IOException {
         Map<String, Object> values = baseConfig();
         values.put("detection.isp.blocked", List.of("Example (Hosting"));
         assertTrue(engine(values, cleanFrom("Example (Hosting) GmbH"))
               .check("Steve", null, PUBLIC_IP, null).blocked());
      }

      @Test
      void anAllowedIspOverridesAProxyFlag() throws IOException {
         Map<String, Object> values = baseConfig();
         values.put("detection.isp.allowed", List.of("Deutsche Telekom"));
         LookupProvider flagged = ip -> LookupResult.of(true, true, "DE", "Germany",
               "Deutsche Telekom AG");
         CheckVerdict verdict = engine(values, flagged).check("Steve", null, PUBLIC_IP, null);
         assertEquals(CheckVerdict.Reason.ALLOWED_ISP, verdict.reason());
      }
   }

   @Nested
   @DisplayName("Connection limit")
   class Limit {

      private ShieldPlayer online(String ip) {
         UUID uuid = UUID.randomUUID();
         return new ShieldPlayer() {
            @Override
            public UUID uuid() {
               return uuid;
            }

            @Override
            public String name() {
               return "p" + uuid.toString().substring(0, 4);
            }

            @Override
            public String ip() {
               return ip;
            }

            @Override
            public boolean hasPermission(String permission) {
               return false;
            }

            @Override
            public void sendMessage(String legacyMessage) {
            }

            @Override
            public void kick(String legacyMessage) {
            }
         };
      }

      @Test
      void onlineModeCountsPlayersCurrentlyConnected() {
         ConnectionLimiter limiter = new ConnectionLimiter();
         List<ShieldPlayer> players = List.of(online(PUBLIC_IP), online(PUBLIC_IP),
               online("1.1.1.1"));
         assertFalse(limiter.exceeds(PUBLIC_IP, UUID.randomUUID(), 3, 0, players));
         List<ShieldPlayer> full = List.of(online(PUBLIC_IP), online(PUBLIC_IP),
               online(PUBLIC_IP));
         assertTrue(limiter.exceeds(PUBLIC_IP, UUID.randomUUID(), 3, 0, full));
      }

      @Test
      void aReconnectingAccountDoesNotCountAgainstItself() {
         ConnectionLimiter limiter = new ConnectionLimiter();
         ShieldPlayer self = online(PUBLIC_IP);
         List<ShieldPlayer> players = List.of(self, online(PUBLIC_IP));
         assertFalse(limiter.exceeds(PUBLIC_IP, self.uuid(), 2, 0, players));
      }

      @Test
      void windowModeResetsAfterTheWindow() {
         AtomicLong now = new AtomicLong(1_000_000L);
         ConnectionLimiter limiter = new ConnectionLimiter(now::get);
         for (int i = 0; i < 3; i++) {
            assertFalse(limiter.exceeds(PUBLIC_IP, UUID.randomUUID(), 3, 30, List.of()));
         }
         assertTrue(limiter.exceeds(PUBLIC_IP, UUID.randomUUID(), 3, 30, List.of()));
         now.addAndGet(31 * 60_000L);
         assertFalse(limiter.exceeds(PUBLIC_IP, UUID.randomUUID(), 3, 30, List.of()));
      }

      @Test
      void windowModeLetsTheSameAccountRejoin() {
         ConnectionLimiter limiter = new ConnectionLimiter();
         UUID same = UUID.randomUUID();
         for (int i = 0; i < 5; i++) {
            assertFalse(limiter.exceeds(PUBLIC_IP, same, 1, 30, List.of()));
         }
      }

      @Test
      void windowStringsParse() {
         Map<String, Object> values = new LinkedHashMap<>();
         values.put("limiter.window", "2h");
         assertEquals(120, ShieldConfig.from(new MapConfigNode(values)).limiterWindowMinutes());
         values.put("limiter.window", "30m");
         assertEquals(30, ShieldConfig.from(new MapConfigNode(values)).limiterWindowMinutes());
         values.put("limiter.window", "DISABLE");
         assertEquals(0, ShieldConfig.from(new MapConfigNode(values)).limiterWindowMinutes());
      }
   }
}
