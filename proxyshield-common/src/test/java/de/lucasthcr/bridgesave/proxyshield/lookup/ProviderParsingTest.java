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

package de.lucasthcr.bridgesave.proxyshield.lookup;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.testing.MapConfigNode;
import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The response shapes the catalogued services actually return. */
class ProviderParsingTest {

   private static final String IP = "203.0.113.7";

   @TempDir
   Path tempDir;

   private IpLookupService reader(ProviderDefinition definition) {
      ShieldConfig config = ShieldConfig.from(new MapConfigNode(Map.of()));
      return new IpLookupService(new RecordingPlatform(tempDir), config, definition);
   }

   private LookupResult parse(String id, String body) {
      ProviderDefinition definition = ProviderCatalog.byId(id);
      assertNotNull(definition, id + " should be in the catalog");
      return reader(definition).parse(body, IP);
   }

   @Nested
   @DisplayName("Free tiers that answer without a verdict")
   class AnonymousTiers {

      /**
       * The exact body api.ipapi.is returns without a key. Every risk field the paid tier
       * documents is absent, and company and asn are flat strings rather than objects, so the
       * documented paths find nothing. Before this was handled the highest weighted provider in
       * the shipped configuration failed on every single request and said so nowhere.
       */
      private static final String IPAPI_IS_ANONYMOUS = """
            {"ip":"185.70.41.1","is_bogon":false,"company":"ProtonVPN CH2",
             "asn":"AS209103 Proton AG","city":"Plan-les-Ouates","region":"Geneva",
             "country":"Switzerland","lat":46.16789,"lon":6.11664,
             "timezone":"Europe/Zurich","docs":"https://ipapi.is/free-tier.html"}""";

      @Test
      @DisplayName("The unkeyed answer resolves and still identifies the network")
      void anonymousTierStillIdentifies() {
         LookupResult result = parse("ipapi-is", IPAPI_IS_ANONYMOUS);

         assertTrue(result.resolved(), "an answer we can read is not a failure");
         assertEquals("Switzerland", result.countryName());
         assertEquals("ProtonVPN CH2", result.isp());
         // The flat string carries the org name too; normalizeAsn keeps only the number, which
         // is what asn.blocked in config.yml is written against.
         assertEquals("AS209103", result.asn());
      }

      @Test
      @DisplayName("It carries no verdict, so it flags nothing and scores nothing")
      void anonymousTierFlagsNothing() {
         LookupResult result = parse("ipapi-is", IPAPI_IS_ANONYMOUS);

         assertFalse(result.proxy());
         assertFalse(result.hosting());
         assertFalse(result.tor());
         assertEquals(0.0, result.confidence());
      }

      @Test
      @DisplayName("The operator is told once that the provider cannot flag anything")
      void anonymousTierIsReportedOnce() {
         RecordingPlatform platform = new RecordingPlatform(tempDir);
         IpLookupService service = new IpLookupService(platform,
               ShieldConfig.from(new MapConfigNode(Map.of())),
               ProviderCatalog.byId("ipapi-is"));

         service.parse(IPAPI_IS_ANONYMOUS, IP);
         service.parse(IPAPI_IS_ANONYMOUS, IP);

         long warnings = platform.warnings().stream()
               .filter(line -> line.contains("ipapi-is") && line.contains("no proxy, VPN or "
                     + "hosting field"))
               .count();
         assertEquals(1, warnings, "a per-request warning would drown the console");
      }

      @Test
      @DisplayName("A keyed answer keeps the documented shape and is not warned about")
      void keyedAnswerIsUntouched() {
         RecordingPlatform platform = new RecordingPlatform(tempDir);
         IpLookupService service = new IpLookupService(platform,
               ShieldConfig.from(new MapConfigNode(Map.of())),
               ProviderCatalog.byId("ipapi-is"));

         LookupResult result = service.parse("""
               {"ip":"185.70.41.1","is_datacenter":true,"is_vpn":true,"is_proxy":false,
                "is_tor":false,"is_abuser":false,
                "location":{"country":"Switzerland","country_code":"CH"},
                "asn":{"asn":"AS62371","org":"Proton AG"},
                "company":{"name":"Proton AG","type":"hosting"}}""", IP);

         assertTrue(result.proxy(), "is_vpn still has to win");
         assertTrue(result.hosting());
         assertEquals("CH", result.countryCode());
         assertEquals("Proton AG", result.isp());
         assertEquals("AS62371", result.asn());
         assertEquals("hosting", result.connectionType());
         assertTrue(platform.warnings().stream().noneMatch(l -> l.contains("no proxy, VPN or")));
      }
   }

   @Nested
   @DisplayName("Nested paths")
   class NestedPaths {

      /** vpnapi.io puts every flag under "security", where a flat reader finds nothing. */
      @Test
      void readsVpnapiSecuritySection() {
         LookupResult result = parse("vpnapi", "{\"security\":{\"vpn\":true,\"proxy\":false,"
               + "\"tor\":false,\"relay\":false},\"location\":{\"country_code\":\"NL\","
               + "\"country\":\"Netherlands\"}}");

         assertTrue(result.resolved());
         assertTrue(result.proxy(), "security.vpn must be read");
         assertEquals("NL", result.countryCode());
      }

      @Test
      void readsIpqueryRiskSection() {
         LookupResult result = parse("ipquery", "{\"risk\":{\"is_vpn\":false,\"is_proxy\":false,"
               + "\"is_tor\":true,\"is_datacenter\":true},\"location\":{\"country_code\":\"DE\"},"
               + "\"isp\":{\"isp\":\"Example\",\"asn\":\"AS64500\"}}");

         assertTrue(result.tor());
         assertTrue(result.proxy(), "a Tor exit is a proxy for blocking purposes");
         assertTrue(result.hosting());
         assertEquals("AS64500", result.asn());
      }
   }

   @Nested
   @DisplayName("Numeric verdicts")
   class NumericVerdicts {

      /** iphub sends 0 residential, 1 block, 2 unclear. Only 1 may count. */
      @Test
      void iphubTreatsTwoAsUnclear() {
         assertTrue(parse("iphub", "{\"block\":1,\"countryCode\":\"NL\"}").proxy());
         assertFalse(parse("iphub", "{\"block\":2,\"countryCode\":\"NL\"}").proxy(),
               "block=2 means unclear, not a detection");
         assertFalse(parse("iphub", "{\"block\":0,\"countryCode\":\"DE\"}").proxy());
      }

      /**
       * getipintel returns its probability as a JSON string. Read as a boolean it is false, which
       * is exactly the silent miss this whole layer exists to prevent.
       */
      @Test
      void getipintelReadsAStringProbability() {
         assertTrue(parse("getipintel", "{\"status\":\"success\",\"result\":\"0.99\"}").proxy());
         assertFalse(parse("getipintel", "{\"status\":\"success\",\"result\":\"0.02\"}").proxy());
      }

      @Test
      void ipqualityscoreUsesItsFraudScore() {
         LookupResult flagged = parse("ipqualityscore",
               "{\"success\":true,\"proxy\":false,\"vpn\":false,\"tor\":false,"
                     + "\"fraud_score\":92,\"country_code\":\"US\"}");
         assertTrue(flagged.proxy(), "a fraud score past the threshold counts on its own");

         LookupResult clean = parse("ipqualityscore",
               "{\"success\":true,\"proxy\":false,\"vpn\":false,\"tor\":false,"
                     + "\"fraud_score\":10,\"country_code\":\"US\"}");
         assertFalse(clean.proxy());
      }
   }

   @Nested
   @DisplayName("Plain text services")
   class PlainText {

      @Test
      void blackboxAnswersASingleCharacter() {
         assertTrue(parse("blackbox", "Y").proxy());
         assertFalse(parse("blackbox", "N").proxy());
         assertFalse(parse("blackbox", "E").resolved(), "E is an error, not a clean address");
      }

      @Test
      void anUnknownTokenIsAFailureRatherThanClean() {
         LookupResult result = parse("blackbox", "<html>rate limited</html>");
         assertFalse(result.resolved());
      }
   }

   @Nested
   @DisplayName("Failure detection")
   class Failures {

      @Test
      void anAnswerWithoutAnyKnownFieldIsAFailure() {
         LookupResult result = parse("vpnapi", "{\"unrelated\":\"payload\"}");

         assertFalse(result.resolved(),
               "a changed API must surface as a failure, never as a clean address");
      }

      @Test
      void inBandErrorsAreReported() {
         LookupResult result = parse("ip-api",
               "{\"status\":\"fail\",\"message\":\"reserved range\"}");

         assertFalse(result.resolved());
         assertTrue(result.failureReason().contains("reserved range"));
      }

      @Test
      void proxycheckNestsUnderTheQueriedAddress() {
         LookupResult result = parse("proxycheck",
               "{\"status\":\"ok\",\"" + IP + "\":{\"proxy\":\"yes\",\"type\":\"VPN\","
                     + "\"isocode\":\"NL\",\"provider\":\"Some VPN Ltd\",\"asn\":\"AS9009\"}}");

         assertTrue(result.proxy(), "the string yes must count as true");
         assertEquals("NL", result.countryCode());
         assertEquals("AS9009", result.asn());
      }
   }

   @Nested
   @DisplayName("Catalog")
   class Catalog {

      @Test
      void everyEntryCarriesAnIpPlaceholderAndAWayToDecide() {
         for (ProviderDefinition definition : ProviderCatalog.all()) {
            assertTrue(definition.urlTemplate().contains("{ip}"),
                  definition.id() + " must substitute the address");
            assertTrue(!definition.proxyPaths().isEmpty()
                        || !definition.hostingPaths().isEmpty()
                        || definition.scorePath() != null
                        || definition.format() == ProviderDefinition.Format.PLAIN,
                  definition.id() + " has no way to reach a verdict");
         }
      }

      @Test
      void keyedServicesStayInertUntilConfigured() {
         ProviderDefinition vpnapi = ProviderCatalog.byId("vpnapi");

         assertFalse(vpnapi.usable(), "a key-only service without a key must not be queried");
         assertTrue(vpnapi.withCredentials("abc123", null).usable());
      }

      /**
       * An empty key must not be sent as an empty parameter: iplocate.io reads {@code ?apikey=}
       * as a wrong key and answers 401, which made a keyless-usable service look broken.
       */
      @Test
      void anUnsetKeyDropsItsQueryParameterEntirely() {
         assertEquals("https://iplocate.io/api/lookup/" + IP,
               ProviderCatalog.byId("iplocate").url(IP));
         assertEquals("https://api.ipapi.is/?q=" + IP,
               ProviderCatalog.byId("ipapi-is").url(IP));
         assertEquals("https://api.zowi.gay/" + IP + "?feature=security",
               ProviderCatalog.byId("zowi").url(IP));
         assertEquals("https://proxycheck.io/v2/" + IP + "?vpn=1&asn=1&risk=1",
               ProviderCatalog.byId("proxycheck").url(IP));
      }

      @Test
      void aConfiguredKeyIsStillSubstituted() {
         assertTrue(ProviderCatalog.byId("iplocate").withCredentials("abc123", null).url(IP)
               .endsWith("?apikey=abc123"));
      }

      @Test
      void headerKeysAreNotWrittenIntoTheUrl() {
         ProviderDefinition iphub = ProviderCatalog.byId("iphub").withCredentials("secret", null);

         assertEquals(ProviderDefinition.KeyStyle.HEADER, iphub.keyStyle());
         assertFalse(iphub.url(IP).contains("secret"), "a header key must not leak into the URL");
      }
   }

   @Nested
   @DisplayName("ASN normalisation")
   class Asn {

      /** Providers spell the same network four different ways. */
      @Test
      void everySpellingReducesToTheSameNumber() {
         assertEquals("AS9009", LookupResult.normalizeAsn("AS9009 M247 Europe SRL"));
         assertEquals("AS9009", LookupResult.normalizeAsn("9009"));
         assertEquals("AS9009", LookupResult.normalizeAsn("as9009"));
         assertEquals("AS9009", LookupResult.normalizeAsn(" AS9009 "));
      }

      @Test
      void nonsenseBecomesNull() {
         assertEquals(null, LookupResult.normalizeAsn("unknown"));
         assertEquals(null, LookupResult.normalizeAsn(""));
         assertEquals(null, LookupResult.normalizeAsn(null));
      }
   }

   @Nested
   @DisplayName("Zowi")
   class Zowi {

      private static final String FLAGGED = """
            {"ip":"203.0.113.9","malicious":true,"security":{"bogon":false,
             "vpn":{"detected":true,"source":"IVPN"},"proxy":{"detected":false},"hosting":true,
             "residential_proxy":{"detected":false,"message":"Unblock this tool for $1.99 USD."},
             "tor":false,"abuser":{"detected":false},"crawler":{"detected":false},
             "suspicious":false},"rateLimit":{"limit":150,"remaining":148}}""";

      private static final String CLEAN = """
            {"ip":"203.0.113.10","malicious":false,"security":{"bogon":false,
             "vpn":{"detected":false},"proxy":{"detected":false},"hosting":false,
             "residential_proxy":{"detected":false},"tor":false,"abuser":{"detected":false},
             "crawler":{"detected":false},"suspicious":false},"rateLimit":{"limit":150,"remaining":149}}""";

      @Test
      @DisplayName("A VPN answer from feature=security is read as VPN and hosting")
      void readsAVpn() {
         LookupResult result = parse("zowi", FLAGGED);

         assertTrue(result.resolved());
         assertTrue(result.proxy());
         assertTrue(result.hosting());
         assertFalse(result.tor());
      }

      @Test
      @DisplayName("A clean answer flags nothing")
      void readsAClean() {
         LookupResult result = parse("zowi", CLEAN);

         assertTrue(result.resolved());
         assertFalse(result.proxy());
         assertFalse(result.hosting());
      }
   }

   @Nested
   @DisplayName("paperstream")
   class PaperStream {

      private static final String CLEAN = "{\"ip\":\"80.187.100.44\",\"country\":\"DE\",\"asn\":3320,"
            + "\"network\":\"end_user\",\"vpn\":false,\"proxy\":false,\"tor\":false,\"hosting\":false,"
            + "\"seen_by\":0,\"community\":false}";
      private static final String COMMUNITY = "{\"ip\":\"203.0.113.9\",\"country\":\"NL\",\"asn\":9009,"
            + "\"network\":\"unknown\",\"vpn\":false,\"proxy\":false,\"tor\":false,\"hosting\":false,"
            + "\"seen_by\":4,\"community\":true}";

      @Test
      @DisplayName("A clean answer flags nothing and carries country and ASN")
      void readsAClean() {
         LookupResult result = parse("paperstream", CLEAN);

         assertTrue(result.resolved());
         assertFalse(result.proxy());
         assertFalse(result.hosting());
         assertFalse(result.tor());
         assertEquals("DE", result.countryCode());
      }

      @Test
      @DisplayName("An address other servers reported counts as a proxy")
      void readsTheCommunityVote() {
         LookupResult result = parse("paperstream", COMMUNITY);

         assertTrue(result.proxy());
      }

      @Test
      @DisplayName("The request goes to the intel service without a key")
      void urlHasNoKey() {
         assertEquals("https://intel.paperstream.dev/v1/ip/" + IP, ProviderCatalog.byId("paperstream").url(IP));
      }
   }
}
