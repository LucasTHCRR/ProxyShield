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

         CheckVerdict verdict = engine.check("Steve", "1.2.3.4", permission -> true);

         assertFalse(verdict.blocked());
         assertEquals(CheckVerdict.Reason.BYPASS_PERMISSION, verdict.reason());
      }

      @Test
      void whitelistedPlayerSkipsEverything() throws IOException {
         Map<String, Object> config = baseConfig();
         config.put("whitelist.players", List.of("Steve"));

         CheckEngine engine = engine(config, ip -> LookupResult.of(true, true, "RU", "", ""),
               List.of("1.2.3.0/24"));

         CheckVerdict verdict = engine.check("steve", "1.2.3.4", CheckEngine.PermissionProbe.NONE);

         assertEquals(CheckVerdict.Reason.WHITELISTED_PLAYER, verdict.reason());
      }

      @Test
      void whitelistedIpBeatsTheBlacklist() throws IOException {
         Map<String, Object> config = baseConfig();
         config.put("whitelist.ips", List.of("1.2.3.0/24"));
         config.put("blacklist.ips", List.of("1.2.3.4"));

         CheckEngine engine = engine(config, clean(), List.of());

         CheckVerdict verdict = engine.check("Steve", "1.2.3.4", CheckEngine.PermissionProbe.NONE);

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

         CheckVerdict verdict = engine.check("Steve", "192.168.1.20",
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

         CheckVerdict verdict = engine.check("Steve", "203.0.113.7",
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

         CheckVerdict verdict = engine.check("Steve", "45.60.1.2",
               CheckEngine.PermissionProbe.NONE);

         assertTrue(verdict.blocked());
         assertEquals(CheckVerdict.Reason.IP_LIST, verdict.reason());
      }

      @Test
      void proxyFlagBlocks() throws IOException {
         CheckEngine engine = engine(baseConfig(),
               ip -> LookupResult.of(true, false, "NL", "Netherlands", "NordVPN"), List.of());

         CheckVerdict verdict = engine.check("Steve", "203.0.113.7",
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

         CheckVerdict verdict = engine.check("Steve", "203.0.113.7",
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

         CheckVerdict verdict = engine.check("Steve", "203.0.113.7",
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

         assertFalse(engine.check("Steve", "203.0.113.7", CheckEngine.PermissionProbe.NONE)
               .blocked());
      }

      @Test
      void whitelistModeBlocksUnlistedCountries() throws IOException {
         Map<String, Object> config = baseConfig();
         config.put("country.enabled", true);
         config.put("country.mode", "whitelist");
         config.put("country.codes", List.of("DE", "AT", "CH"));

         CheckEngine allowed = engine(config, clean(), List.of());
         assertFalse(allowed.check("Steve", "203.0.113.7", CheckEngine.PermissionProbe.NONE)
               .blocked());

         CheckEngine blocked = engine(config,
               ip -> LookupResult.of(false, false, "US", "United States", "Comcast"), List.of());
         assertTrue(blocked.check("Steve", "203.0.113.7", CheckEngine.PermissionProbe.NONE)
               .blocked());
      }

      @Test
      void unknownCountryFollowsItsOwnSetting() throws IOException {
         Map<String, Object> config = baseConfig();
         config.put("country.enabled", true);
         config.put("country.block-unknown", true);

         CheckEngine engine = engine(config,
               ip -> LookupResult.of(false, false, null, null, "Some ISP"), List.of());

         CheckVerdict verdict = engine.check("Steve", "203.0.113.7",
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

         CheckVerdict verdict = engine.check("Steve", "203.0.113.7",
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

         CheckVerdict verdict = engine.check("Steve", "203.0.113.7",
               CheckEngine.PermissionProbe.NONE);

         assertFalse(verdict.blocked());
      }

      @Test
      void failClosedDeniesWhenTheProviderIsDown() throws IOException {
         Map<String, Object> config = baseConfig();
         config.put("settings.fail-closed", true);

         CheckEngine engine = engine(config, ip -> LookupResult.failed("timeout"), List.of());

         CheckVerdict verdict = engine.check("Steve", "203.0.113.7",
               CheckEngine.PermissionProbe.NONE);

         assertTrue(verdict.blocked());
         assertEquals(CheckVerdict.Reason.LOOKUP_FAILED, verdict.reason());
      }

      @Test
      void unreadableAddressIsNeverPunished() throws IOException {
         CheckEngine engine = engine(baseConfig(), clean(), List.of());

         assertFalse(engine.check("Steve", null, CheckEngine.PermissionProbe.NONE).blocked());
         assertFalse(engine.check("Steve", "not-an-ip", CheckEngine.PermissionProbe.NONE)
               .blocked());
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

      assertFalse(engine.check("Steve", "203.0.113.7", CheckEngine.PermissionProbe.NONE)
            .blocked());
   }
}
