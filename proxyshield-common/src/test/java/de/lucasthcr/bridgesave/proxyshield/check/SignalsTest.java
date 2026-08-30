package de.lucasthcr.bridgesave.proxyshield.check;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.list.ListManager;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupProvider;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import de.lucasthcr.bridgesave.proxyshield.net.ManagedIpList;
import de.lucasthcr.bridgesave.proxyshield.net.ReverseDns;
import de.lucasthcr.bridgesave.proxyshield.testing.MapConfigNode;
import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform;
import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The signals that do not come from a provider: ASN rules, trust, behaviour and scoring. */
class SignalsTest {

   private static final String IP = "203.0.113.7";

   @TempDir
   Path tempDir;

   private CheckEngine engine(Map<String, Object> values, LookupProvider provider,
         TrustStore trust, JoinHeuristics heuristics) throws IOException {
      ShieldConfig config = ShieldConfig.from(new MapConfigNode(values));
      RecordingPlatform platform = new RecordingPlatform(tempDir);

      ListManager lists = new ListManager(platform);
      lists.refresh(List.of(), 5, false);

      ManagedIpList whitelist = new ManagedIpList(tempDir.resolve("whitelist.txt"));
      ManagedIpList blacklist = new ManagedIpList(tempDir.resolve("blacklist.txt"));
      whitelist.load();
      blacklist.load();
      whitelist.setConfigEntries(config.whitelistIps());
      blacklist.setConfigEntries(config.blacklistIps());

      return new CheckEngine(config, lists, provider, whitelist, blacklist, null, trust,
            heuristics);
   }

   private static Map<String, Object> baseConfig() {
      Map<String, Object> values = new LinkedHashMap<>();
      values.put("detection.use-lists", false);
      values.put("detection.use-api", true);
      values.put("detection.block-proxy", true);
      values.put("detection.block-hosting", true);
      values.put("detection.rdns.enabled", false);
      values.put("heuristics.enabled", false);
      values.put("trust.enabled", false);
      return values;
   }

   /** A provider answer with an ASN and a connection type attached. */
   private static LookupProvider answering(boolean proxy, boolean hosting, String asn,
         String type) {
      return ip -> LookupResult.of(proxy, hosting, false, "NL", "Netherlands", "Example",
            asn, type, proxy ? 1.0 : 0.0, proxy || hosting ? List.of("stub") : List.of());
   }

   @Nested
   @DisplayName("Network (ASN) rules")
   class AsnRules {

      @Test
      void aBlockedNetworkIsRefusedEvenWhenEveryProviderSaysClean() throws IOException {
         Map<String, Object> values = baseConfig();
         values.put("detection.asn.blocked", List.of("AS9009"));

         CheckVerdict verdict = engine(values, answering(false, false, "AS9009 M247", null),
               null, null)
               .check("Steve", null, IP, CheckEngine.PermissionProbe.NONE);

         assertTrue(verdict.blocked());
         assertEquals(CheckVerdict.Reason.ASN, verdict.reason());
      }

      @Test
      void anAllowedNetworkOverridesAProxyFlag() throws IOException {
         Map<String, Object> values = baseConfig();
         values.put("detection.asn.allowed", List.of("64500"));

         CheckVerdict verdict = engine(values, answering(true, true, "AS64500", null), null, null)
               .check("Steve", null, IP, CheckEngine.PermissionProbe.NONE);

         assertFalse(verdict.blocked(), "an explicitly allowed network wins");
         assertEquals(CheckVerdict.Reason.ALLOWED_ASN, verdict.reason());
      }
   }

   @Nested
   @DisplayName("Connection type")
   class ConnectionType {

      @Test
      void aMobileCarrierIsNotKickedByTheHostingRule() throws IOException {
         Map<String, Object> values = baseConfig();
         values.put("detection.allow-residential-hosting", true);

         CheckVerdict verdict = engine(values, answering(false, true, "AS3320", "mobile"),
               null, null)
               .check("Steve", null, IP, CheckEngine.PermissionProbe.NONE);

         assertFalse(verdict.blocked(),
               "a carrier listed in a hosting range is still a real player");
      }

      @Test
      void theExemptionCanBeTurnedOff() throws IOException {
         Map<String, Object> values = baseConfig();
         values.put("detection.allow-residential-hosting", false);

         CheckVerdict verdict = engine(values, answering(false, true, "AS3320", "mobile"),
               null, null)
               .check("Steve", null, IP, CheckEngine.PermissionProbe.NONE);

         assertTrue(verdict.blocked());
         assertEquals(CheckVerdict.Reason.HOSTING, verdict.reason());
      }
   }

   @Nested
   @DisplayName("Trust")
   class Trust {

      @Test
      void aRegularSurvivesAProviderHavingABadDay() throws IOException {
         Map<String, Object> values = baseConfig();
         values.put("trust.enabled", true);
         values.put("trust.min-logins", 2);
         values.put("trust.min-days", 0);

         TrustStore trust = new TrustStore(new RecordingPlatform(tempDir));
         UUID uuid = UUID.randomUUID();
         trust.recordCleanLogin(uuid);
         trust.recordCleanLogin(uuid);

         CheckVerdict verdict = engine(values, answering(true, true, null, null), trust, null)
               .check("Steve", uuid, IP, CheckEngine.PermissionProbe.NONE);

         assertFalse(verdict.blocked());
         assertEquals(CheckVerdict.Reason.TRUSTED_PLAYER, verdict.reason());
      }

      @Test
      void theManualBlacklistStillWins() throws IOException {
         Map<String, Object> values = baseConfig();
         values.put("trust.enabled", true);
         values.put("trust.min-logins", 1);
         values.put("trust.min-days", 0);
         values.put("blacklist.ips", List.of(IP));

         TrustStore trust = new TrustStore(new RecordingPlatform(tempDir));
         UUID uuid = UUID.randomUUID();
         trust.recordCleanLogin(uuid);

         CheckVerdict verdict = engine(values, answering(false, false, null, null), trust, null)
               .check("Steve", uuid, IP, CheckEngine.PermissionProbe.NONE);

         assertTrue(verdict.blocked(), "an operator's explicit decision outranks trust");
         assertEquals(CheckVerdict.Reason.BLACKLISTED, verdict.reason());
      }

      @Test
      void aNewcomerIsNotTrusted() {
         TrustStore trust = new TrustStore(new RecordingPlatform(tempDir));
         UUID uuid = UUID.randomUUID();
         trust.recordCleanLogin(uuid);

         assertFalse(trust.trusted(uuid, 5, 3), "one login on day one is not a history");
         assertFalse(trust.trusted(uuid, 1, 3), "the age requirement still applies");
         assertTrue(trust.trusted(uuid, 1, 0));
      }

      @Test
      void beingCaughtResetsTheHistory() {
         TrustStore trust = new TrustStore(new RecordingPlatform(tempDir));
         UUID uuid = UUID.randomUUID();
         trust.recordCleanLogin(uuid);
         trust.recordCleanLogin(uuid);
         trust.forget(uuid);

         assertFalse(trust.trusted(uuid, 1, 0));
      }
   }

   @Nested
   @DisplayName("Behavioural heuristics")
   class Behaviour {

      @Test
      void aBurstFromOneSubnetAddsWeight() throws IOException {
         Map<String, Object> values = baseConfig();
         values.put("heuristics.enabled", true);
         values.put("heuristics.max-joins-per-subnet-per-minute", 3);
         values.put("heuristics.weight", 1.0);
         values.put("api.required-score", 1.0);

         JoinHeuristics heuristics = new JoinHeuristics();
         CheckEngine engine = engine(values, answering(false, false, null, null), null, heuristics);

         // The first joins are below the limit and pass.
         for (int i = 0; i < 3; i++) {
            CheckVerdict early = engine.check("Bot" + i, UUID.randomUUID(), "203.0.113." + i,
                  CheckEngine.PermissionProbe.NONE);
            assertFalse(early.blocked(), "a normal join rate must not be punished");
         }

         CheckVerdict verdict = engine.check("Bot9", UUID.randomUUID(), "203.0.113.9",
               CheckEngine.PermissionProbe.NONE);

         assertTrue(verdict.blocked(), "a burst past the limit should reach the threshold");
         assertEquals(CheckVerdict.Reason.SUSPICIOUS, verdict.reason());
      }

      @Test
      void oneAddressCyclingThroughAccountsIsNoticed() {
         JoinHeuristics heuristics = new JoinHeuristics();
         JoinHeuristics.Signals last = null;
         for (int i = 0; i < 5; i++) {
            last = heuristics.observe(UUID.randomUUID(), IP, "NL", 100, 3, 0);
         }

         assertTrue(last.any());
         assertTrue(last.summary().contains("account sharing"));
      }

      @Test
      void anAccountTeleportingBetweenCountriesIsNoticed() {
         JoinHeuristics heuristics = new JoinHeuristics();
         UUID uuid = UUID.randomUUID();

         assertFalse(heuristics.observe(uuid, IP, "DE", 100, 100, 10).geoJump());
         assertTrue(heuristics.observe(uuid, "198.51.100.4", "BR", 100, 100, 10).geoJump(),
               "the same account cannot be in two countries a moment apart");
      }

      @Test
      void aQuietServerProducesNoSignals() {
         JoinHeuristics heuristics = new JoinHeuristics();
         JoinHeuristics.Signals signals =
               heuristics.observe(UUID.randomUUID(), IP, "DE", 12, 4, 10);

         assertFalse(signals.any());
      }
   }

   @Nested
   @DisplayName("Reverse DNS patterns")
   class Rdns {

      @Test
      void operatorNamesAreRecognised() {
         assertTrue(ReverseDns.matchName("mad-01.torguard.io", List.of()).isPresent());
         assertTrue(ReverseDns.matchName("vpn-gw3.example.net", List.of()).isPresent());
         assertTrue(ReverseDns.matchName("static.123.hosting.example", List.of()).isPresent());
      }

      @Test
      void anOrdinaryCustomerNameIsNot() {
         assertFalse(ReverseDns.matchName("dslb-088-070-123-004.pools.arcor-ip.net", List.of())
               .isPresent());
         assertFalse(ReverseDns.matchName("p5dcb1234.dip0.t-ipconnect.de", List.of()).isPresent());
      }

      @Test
      void customPatternsReplaceTheBuiltInList() {
         assertTrue(ReverseDns.matchName("host.example.net", List.of("example")).isPresent());
         assertFalse(ReverseDns.matchName("vpn.example.org", List.of("nothing-here")).isPresent());
      }
   }
}
