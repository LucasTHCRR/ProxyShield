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

import de.lucasthcr.bridgesave.proxyshield.config.ConfigNode;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.list.ListManager;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupProvider;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import de.lucasthcr.bridgesave.proxyshield.net.ManagedIpList;
import de.lucasthcr.bridgesave.proxyshield.testing.MapConfigNode;
import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** End-to-end tests for the decision pipeline, with the provider stubbed out. */
class CheckEngineTest {

   @TempDir
   Path tempDir;

   private CheckEngine engine(Map<String, Object> configValues, LookupProvider provider,
         List<String> listEntries) throws IOException {
      ConfigNode node = new MapConfigNode(configValues);
      ShieldConfig config = ShieldConfig.from(node);

      RecordingPlatform platform = new RecordingPlatform(tempDir);
      ListManager lists = new ListManager(platform);
      lists.refresh(List.of(), 5, false);
      // Feed the list manager without touching the network by writing a file:// source.
      if (!listEntries.isEmpty()) {
         Path file = tempDir.resolve("list.txt");
         java.nio.file.Files.write(file, listEntries);
         lists.refresh(List.of(file.toUri().toString()), 5, false);
      }

      ManagedIpList whitelist = new ManagedIpList(tempDir.resolve("whitelist.txt"));
      ManagedIpList blacklist = new ManagedIpList(tempDir.resolve("blacklist.txt"));
      whitelist.load();
      blacklist.load();
      whitelist.setConfigEntries(config.whitelistIps());
      blacklist.setConfigEntries(config.blacklistIps());

      return new CheckEngine(config, lists, provider, whitelist, blacklist);
   }

   private static Map<String, Object> baseConfig() {
      return new java.util.LinkedHashMap<>(Map.of(
            "detection.use-lists", true,
            "detection.use-api", true,
            "detection.block-proxy", true,
            "detection.block-hosting", true));
   }

   private static LookupProvider clean() {
      return ip -> LookupResult.of(false, false, "DE", "Germany", "Deutsche Telekom");
   }

   @Nested
   @DisplayName("Allow rules win over block rules")
   class AllowFirst {

      @Test
      void bypassPermissionSkipsEverything() throws IOException {
         CheckEngine engine = engine(baseConfig(), ip -> LookupResult.of(true, true, "RU", "", ""),
               List.of("1.2.3.0/24"));

         CheckVerdict verdict = engine.check("Steve", null, "1.2.3.4", permission -> true);

         assertFalse(verdict.blocked());
         assertEquals(CheckVerdict.Reason.BYPASS_PERMISSION, verdict.reason());
      }

      @Test
      void whitelistedPlayerSkipsEverything() throws IOException {
         Map<String, Object> config = baseConfig();
         config.put("whitelist.players", List.of("Steve"));

         CheckEngine engine = engine(config, ip -> LookupResult.of(true, true, "RU", "", ""),
               List.of("1.2.3.0/24"));

         CheckVerdict verdict = engine.check("steve", null, "1.2.3.4", CheckEngine.PermissionProbe.NONE);

         assertEquals(CheckVerdict.Reason.WHITELISTED_PLAYER, verdict.reason());
      }

      @Test
      void whitelistedIpBeatsTheBlacklist() throws IOException {
         Map<String, Object> config = baseConfig();
         config.put("whitelist.ips", List.of("1.2.3.0/24"));
         config.put("blacklist.ips", List.of("1.2.3.4"));

         CheckEngine engine = engine(config, clean(), List.of());

         CheckVerdict verdict = engine.check("Steve", null, "1.2.3.4", CheckEngine.PermissionProbe.NONE);

         assertFalse(verdict.blocked());
         assertEquals(CheckVerdict.Reason.WHITELISTED_IP, verdict.reason());
      }

      @Test
      void localAddressesAreNeverChecked() throws IOException {
         CheckEngine engine = engine(baseConfig(),
               ip -> {
                  throw new AssertionError("provider must not be queried for a local address");
               },
               List.of());

         CheckVerdict verdict = engine.check("Steve", null, "192.168.1.20",
               CheckEngine.PermissionProbe.NONE);

         assertEquals(CheckVerdict.Reason.LOCAL_ADDRESS, verdict.reason());
      }
   }

   @Nested
   @DisplayName("Blocking")
   class Blocking {

      @Test
      void blacklistBlocksBeforeAnyLookup() throws IOException {
         Map<String, Object> config = baseConfig();
         config.put("blacklist.ips", List.of("203.0.113.0/24"));

         CheckEngine engine = engine(config,
               ip -> {
                  throw new AssertionError("blacklist must short-circuit the provider");
               },
               List.of());

         CheckVerdict verdict = engine.check("Steve", null, "203.0.113.7",
               CheckEngine.PermissionProbe.NONE);

         assertTrue(verdict.blocked());
         assertEquals(CheckVerdict.Reason.BLACKLISTED, verdict.reason());
      }

      @Test
      void listHitBlocksWithoutALookup() throws IOException {
         CheckEngine engine = engine(baseConfig(),
               ip -> {
                  throw new AssertionError("a list hit must short-circuit the provider");
               },
               List.of("45.60.0.0/16"));

         CheckVerdict verdict = engine.check("Steve", null, "45.60.1.2",
               CheckEngine.PermissionProbe.NONE);

         assertTrue(verdict.blocked());
         assertEquals(CheckVerdict.Reason.IP_LIST, verdict.reason());
      }

      @Test
      void proxyFlagBlocks() throws IOException {
         CheckEngine engine = engine(baseConfig(),
               ip -> LookupResult.of(true, false, "NL", "Netherlands", "NordVPN"), List.of());

         CheckVerdict verdict = engine.check("Steve", null, "203.0.113.7",
               CheckEngine.PermissionProbe.NONE);

         assertTrue(verdict.blocked());
         assertEquals(CheckVerdict.Reason.PROXY, verdict.reason());
         assertTrue(verdict.describe().contains("NordVPN"));
      }

      @Test
      void hostingFlagCanBeAllowed() throws IOException {
         Map<String, Object> config = baseConfig();
         config.put("detection.block-hosting", false);

         CheckEngine engine = engine(config,
               ip -> LookupResult.of(false, true, "DE", "Germany", "Hetzner"), List.of());

         CheckVerdict verdict = engine.check("Steve", null, "203.0.113.7",
               CheckEngine.PermissionProbe.NONE);

         assertFalse(verdict.blocked());
      }
   }

   @Nested
   @DisplayName("Country filter")
   class Country {

      @Test
      void blacklistModeBlocksListedCountries() throws IOException {
         Map<String, Object> config = baseConfig();
         config.put("country.enabled", true);
         config.put("country.mode", "blacklist");
         config.put("country.codes", List.of("RU", "KP"));

         CheckEngine engine = engine(config,
               ip -> LookupResult.of(false, false, "RU", "Russia", "Rostelecom"), List.of());

         CheckVerdict verdict = engine.check("Steve", null, "203.0.113.7",
               CheckEngine.PermissionProbe.NONE);

         assertTrue(verdict.blocked());
         assertEquals(CheckVerdict.Reason.COUNTRY, verdict.reason());
         assertTrue(verdict.describe().contains("RU"));
      }

      @Test
      void blacklistModeAllowsEverythingElse() throws IOException {
         Map<String, Object> config = baseConfig();
         config.put("country.enabled", true);
         config.put("country.codes", List.of("RU"));

         CheckEngine engine = engine(config, clean(), List.of());

         assertFalse(engine.check("Steve", null, "203.0.113.7", CheckEngine.PermissionProbe.NONE)
               .blocked());
      }

      @Test
      void whitelistModeBlocksUnlistedCountries() throws IOException {
         Map<String, Object> config = baseConfig();
         config.put("country.enabled", true);
         config.put("country.mode", "whitelist");
         config.put("country.codes", List.of("DE", "AT", "CH"));

         CheckEngine allowed = engine(config, clean(), List.of());
         assertFalse(allowed.check("Steve", null, "203.0.113.7", CheckEngine.PermissionProbe.NONE)
               .blocked());

         CheckEngine blocked = engine(config,
               ip -> LookupResult.of(false, false, "US", "United States", "Comcast"), List.of());
         assertTrue(blocked.check("Steve", null, "203.0.113.7", CheckEngine.PermissionProbe.NONE)
               .blocked());
      }

      @Test
      void unknownCountryFollowsItsOwnSetting() throws IOException {
         Map<String, Object> config = baseConfig();
         config.put("country.enabled", true);
         config.put("country.block-unknown", true);

         CheckEngine engine = engine(config,
               ip -> LookupResult.of(false, false, null, null, "Some ISP"), List.of());

         CheckVerdict verdict = engine.check("Steve", null, "203.0.113.7",
               CheckEngine.PermissionProbe.NONE);

         assertTrue(verdict.blocked());
         assertEquals(CheckVerdict.Reason.COUNTRY, verdict.reason());
      }

      /** Country data comes from the provider, so it must be queried even with use-api off. */
      @Test
      void worksWithProxyDetectionDisabled() throws IOException {
         Map<String, Object> config = baseConfig();
         config.put("detection.use-api", false);
         config.put("country.enabled", true);
         config.put("country.codes", List.of("RU"));

         CheckEngine engine = engine(config,
               ip -> LookupResult.of(true, true, "RU", "Russia", "Rostelecom"), List.of());

         CheckVerdict verdict = engine.check("Steve", null, "203.0.113.7",
               CheckEngine.PermissionProbe.NONE);

         assertTrue(verdict.blocked());
         assertEquals(CheckVerdict.Reason.COUNTRY, verdict.reason(),
               "proxy flag must be ignored when use-api is off");
      }
   }

   @Nested
   @DisplayName("Failure policy")
   class FailurePolicy {

      @Test
      void failOpenLetsPlayersInWhenTheProviderIsDown() throws IOException {
         CheckEngine engine = engine(baseConfig(), ip -> LookupResult.failed("timeout"), List.of());

         CheckVerdict verdict = engine.check("Steve", null, "203.0.113.7",
               CheckEngine.PermissionProbe.NONE);

         assertFalse(verdict.blocked());
      }

      @Test
      void failClosedDeniesWhenTheProviderIsDown() throws IOException {
         Map<String, Object> config = baseConfig();
         config.put("settings.fail-closed", true);

         CheckEngine engine = engine(config, ip -> LookupResult.failed("timeout"), List.of());

         CheckVerdict verdict = engine.check("Steve", null, "203.0.113.7",
               CheckEngine.PermissionProbe.NONE);

         assertTrue(verdict.blocked());
         assertEquals(CheckVerdict.Reason.LOOKUP_FAILED, verdict.reason());
      }

      @Test
      void unreadableAddressIsNeverPunished() throws IOException {
         CheckEngine engine = engine(baseConfig(), clean(), List.of());

         assertFalse(engine.check("Steve", null, null, CheckEngine.PermissionProbe.NONE).blocked());
         assertFalse(engine.check("Steve", null, "not-an-ip", CheckEngine.PermissionProbe.NONE)
               .blocked());
      }
   }

   @Nested
   @DisplayName("Bedrock players")
   class Bedrock {

      /** Floodgate UUIDs have zero in the high 64 bits. */
      private static final UUID BEDROCK = new UUID(0L, 0x0901f588cbe8e0L);
      private static final UUID JAVA = UUID.fromString("069a79f4-44e9-4726-a5be-fca90e38aaf5");

      @Test
      @DisplayName("A Geyser player on a listed datacenter address is let through")
      void bedrockIsExemptByDefault() throws IOException {
         CheckEngine engine = engine(baseConfig(),
               ip -> LookupResult.of(false, true, "DE", "Germany", "Hetzner"),
               List.of("203.0.113.0/24"));

         CheckVerdict verdict = engine.check("Steve", BEDROCK, "203.0.113.7",
               CheckEngine.PermissionProbe.NONE);

         assertFalse(verdict.blocked());
         assertEquals(CheckVerdict.Reason.BEDROCK_PLAYER, verdict.reason());
      }

      @Test
      void aJavaPlayerOnTheSameAddressIsStillBlocked() throws IOException {
         CheckEngine engine = engine(baseConfig(), clean(), List.of("203.0.113.0/24"));

         CheckVerdict verdict = engine.check("Steve", JAVA, "203.0.113.7",
               CheckEngine.PermissionProbe.NONE);

         assertTrue(verdict.blocked(), "only Floodgate UUIDs may skip the check");
      }

      @Test
      void exemptionCanBeTurnedOff() throws IOException {
         Map<String, Object> config = baseConfig();
         config.put("whitelist.bedrock-players", false);

         CheckEngine engine = engine(config, clean(), List.of("203.0.113.0/24"));

         assertTrue(engine.check("Steve", BEDROCK, "203.0.113.7",
               CheckEngine.PermissionProbe.NONE).blocked());
      }

      @Test
      void missingUuidDoesNotCountAsBedrock() throws IOException {
         CheckEngine engine = engine(baseConfig(), clean(), List.of("203.0.113.0/24"));

         assertTrue(engine.check("Steve", null, "203.0.113.7",
               CheckEngine.PermissionProbe.NONE).blocked());
      }
   }

   @Test
   void nothingIsQueriedWhenAllDetectionIsOff() throws IOException {
      Map<String, Object> config = baseConfig();
      config.put("detection.use-lists", false);
      config.put("detection.use-api", false);

      CheckEngine engine = engine(config,
            ip -> {
               throw new AssertionError("no lookup should happen");
            },
            List.of("203.0.113.0/24"));

      assertFalse(engine.check("Steve", null, "203.0.113.7", CheckEngine.PermissionProbe.NONE)
            .blocked());
   }
}
