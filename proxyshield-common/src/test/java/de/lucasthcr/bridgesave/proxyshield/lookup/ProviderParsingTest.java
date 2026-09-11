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
}
