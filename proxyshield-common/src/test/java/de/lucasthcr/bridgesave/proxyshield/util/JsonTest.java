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

package de.lucasthcr.bridgesave.proxyshield.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class JsonTest {

   @Test
   @DisplayName("A crafted player name cannot inject fields into the webhook payload")
   void escapingBlocksInjection() {
      String hostile = "evil\",\"content\":\"@everyone";

      String body = new Json.Writer()
            .beginObject()
            .field("username", hostile)
            .endObject()
            .toString();

      Map<String, Object> parsed = Json.parseObject(body);
      assertEquals(1, parsed.size(), "payload must still have exactly one field");
      assertEquals(hostile, Json.stringOf(parsed, "username"), "value round-trips verbatim");
      assertFalse(parsed.containsKey("content"), "no injected key");
   }

   @Test
   void escapesControlCharacters() {
      String body = new Json.Writer()
            .beginObject()
            .field("text", "line\nbreak\ttab\\slash\"quote")
            .endObject()
            .toString();

      assertEquals("line\nbreak\ttab\\slash\"quote",
            Json.stringOf(Json.parseObject(body), "text"));
   }

   @Test
   void writesNestedStructures() {
      String body = new Json.Writer()
            .beginObject()
            .name("embeds").beginArray()
            .beginObject().field("title", "hi").field("color", 16711680L).endObject()
            .endArray()
            .field("flag", true)
            .endObject()
            .toString();

      Map<String, Object> parsed = Json.parseObject(body);
      assertTrue(parsed.containsKey("embeds"));
      assertTrue(Json.boolOf(parsed, "flag"));
   }

   /**
    * v1 asked whether the raw response contained the substring "true", which an ISP or country name
    * could satisfy on its own.
    */
   @Test
   @DisplayName("proxy=false is not confused by the word 'True' elsewhere in the response")
   void substringCannotFakeAFlag() {
      Map<String, Object> parsed = Json.parseObject(
            "{\"status\":\"success\",\"proxy\":false,\"hosting\":false,"
                  + "\"countryCode\":\"DE\",\"isp\":\"Truesomething GmbH\"}");

      assertFalse(Json.boolOf(parsed, "proxy"));
      assertFalse(Json.boolOf(parsed, "hosting"));
      assertEquals("DE", Json.stringOf(parsed, "countryCode"));
   }

   @Test
   void readsProviderFlags() {
      Map<String, Object> parsed = Json.parseObject("{\"status\":\"success\",\"proxy\":true}");
      assertTrue(Json.boolOf(parsed, "proxy"));

      Map<String, Object> failure = Json.parseObject(
            "{\"status\":\"fail\",\"message\":\"reserved range\"}");
      assertEquals("fail", Json.stringOf(failure, "status"));
      assertEquals("reserved range", Json.stringOf(failure, "message"));
   }

   @Test
   void parsesUnicodeEscapes() {
      Map<String, Object> parsed = Json.parseObject("{\"a\":\"\\u00e4\\u00f6\\u00fc\"}");
      assertEquals("äöü", Json.stringOf(parsed, "a"));
   }

   @Test
   void rejectsMalformedInput() {
      assertThrows(Json.JsonException.class, () -> Json.parse("{"));
      assertThrows(Json.JsonException.class, () -> Json.parse("{\"a\":}"));
      assertThrows(Json.JsonException.class, () -> Json.parse("{\"a\":1} trailing"));
      assertThrows(Json.JsonException.class, () -> Json.parse(""));
   }

   @Test
   void nonObjectDocumentYieldsEmptyMap() {
      assertTrue(Json.parseObject("[1,2,3]").isEmpty());
      assertTrue(Json.parseObject("\"just a string\"").isEmpty());
   }
}
