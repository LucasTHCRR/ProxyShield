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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.testing.MapConfigNode;
import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform;
import de.lucasthcr.bridgesave.proxyshield.util.Json;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Operator-written conditions on provider answers, and custom request headers. */
class ResponseRuleTest {

   private static final String IP = "8.8.4.4";

   @TempDir
   Path tempDir;

   private static Object json(String body) {
      return Json.parse(body);
   }

   @Test
   void numbersCompareNumerically() {
      ResponseRule rule = ResponseRule.parse("risk", List.of("risk.score >= 75"));
      assertTrue(rule.matches(json("{\"risk\":{\"score\":80}}")));
      assertTrue(rule.matches(json("{\"risk\":{\"score\":\"75\"}}")));
      assertFalse(rule.matches(json("{\"risk\":{\"score\":9}}")));
   }

   @Test
   void everyConditionInAGroupMustHold() {
      ResponseRule rule = ResponseRule.parse("both", List.of("mobile = true", "score < 30"));
      assertTrue(rule.matches(json("{\"mobile\":true,\"score\":10}")));
      assertFalse(rule.matches(json("{\"mobile\":true,\"score\":50}")));
   }

   @Test
   void textComparesCaseInsensitively() {
      ResponseRule rule = ResponseRule.parse("type", List.of("type != \"Hosting\""));
      assertTrue(rule.matches(json("{\"type\":\"isp\"}")));
      assertFalse(rule.matches(json("{\"type\":\"hosting\"}")));
   }

   @Test
   void aMissingFieldNeverMatches() {
      ResponseRule rule = ResponseRule.parse("neg", List.of("score != 5"));
      assertFalse(rule.matches(json("{\"other\":1}")));
   }

   @Test
   void garbageIsRejected() {
      assertThrows(IllegalArgumentException.class,
            () -> ResponseRule.parse("bad", List.of("score is high")));
      assertThrows(IllegalArgumentException.class, () -> ResponseRule.parse("empty", List.of()));
   }

   private IpLookupService custom(Map<String, Object> extra) {
      Map<String, Object> values = new LinkedHashMap<>();
      values.put("api.providers.mine.enabled", true);
      values.put("api.providers.mine.url", "https://example.invalid/{ip}?k={key}");
      values.put("api.providers.mine.key", "secret");
      values.put("api.providers.mine.proxy-fields", List.of("security.vpn"));
      values.putAll(extra);
      ShieldConfig config = ShieldConfig.from(new MapConfigNode(values));
      ProviderDefinition definition = config.providers().get(0);
      return new IpLookupService(new RecordingPlatform(tempDir), config, definition);
   }

   @Test
   void aFlagRuleRaisesWhatTheMappingMissed() {
      IpLookupService service = custom(Map.of(
            "api.providers.mine.conditions.flag.fraud", List.of("fraud_score >= 85")));
      LookupResult result = service.parse(
            "{\"security\":{\"vpn\":false},\"fraud_score\":92}", IP);
      assertTrue(result.proxy());
   }

   @Test
   void aBypassRuleClearsEveryFlag() {
      IpLookupService service = custom(Map.of(
            "api.providers.mine.conditions.bypass.mobile", List.of("mobile = true")));
      LookupResult result = service.parse("{\"security\":{\"vpn\":true},\"mobile\":true}", IP);
      assertTrue(result.resolved());
      assertFalse(result.proxy());
   }

   @Test
   void aRuleOnlyAnswerIsNotTreatedAsEmpty() {
      Map<String, Object> extra = new LinkedHashMap<>();
      extra.put("api.providers.mine.proxy-fields", List.of("nothing.here"));
      extra.put("api.providers.mine.conditions.flag.f", List.of("level = high"));
      LookupResult result = custom(extra).parse("{\"level\":\"high\"}", IP);
      assertTrue(result.resolved());
      assertTrue(result.proxy());
   }

   @Test
   void anUnreadableRuleIsSkippedWithAWarning() {
      Map<String, Object> values = new LinkedHashMap<>();
      values.put("api.providers.mine.enabled", true);
      values.put("api.providers.mine.url", "https://example.invalid/{ip}");
      values.put("api.providers.mine.proxy-fields", List.of("vpn"));
      values.put("api.providers.mine.conditions.flag.broken", List.of("score is high"));
      ShieldConfig config = ShieldConfig.from(new MapConfigNode(values));
      assertEquals(1, config.providers().size());
      assertTrue(config.providers().get(0).flagRules().isEmpty());
      assertEquals(1, config.warnings().size());
   }

   @Test
   void headersFillInTheKeyAndAddress() {
      ProviderDefinition definition = custom(Map.of(
            "api.providers.mine.headers.Authorization", "Bearer {key}",
            "api.providers.mine.headers.X-Ip", "{ip}")).definition();
      Map<String, String> headers = definition.headers(IP);
      assertEquals("Bearer secret", headers.get("Authorization"));
      assertEquals(IP, headers.get("X-Ip"));
   }
}
