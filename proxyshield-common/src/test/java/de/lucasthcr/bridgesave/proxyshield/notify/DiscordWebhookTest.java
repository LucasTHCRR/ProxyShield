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

package de.lucasthcr.bridgesave.proxyshield.notify;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.testing.MapConfigNode;
import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The webhook payload: what Discord refuses, and what the operator gets to decide.
 * <p>
 * Discord answers {@code 400} for the whole request when a string it expects to be filled arrives
 * empty, and the plugin only sees the status code, so the mistake looks like a broken token. Most
 * of these pin a case where a value can legitimately be blank.
 */
class DiscordWebhookTest {

   private static final UUID PLAYER_ID = UUID.fromString("11111111-2222-3333-4444-555555555555");

   private RecordingPlatform platform;

   @BeforeEach
   void setUp(@TempDir Path tempDir) {
      platform = new RecordingPlatform(tempDir);
   }

   private String body(Map<String, Object> settings, boolean enforced) {
      return body(settings, payload("Notch", "M247", enforced));
   }

   private String body(Map<String, Object> settings, DiscordWebhook.Payload payload) {
      ShieldConfig config = ShieldConfig.from(new MapConfigNode(settings));
      return new DiscordWebhook(platform, config).buildBody(config, payload);
   }

   private static DiscordWebhook.Payload payload(String player, String isp, boolean enforced) {
      return new DiscordWebhook.Payload(player, PLAYER_ID, "1.2.3.4", "VPN list", "DE", isp,
            "AS9009", 2.5, "ip-api, iphub", enforced);
   }

   @Nested
   @DisplayName("What Discord refuses")
   class Rejections {

      @Test
      @DisplayName("A cleared username is left out rather than sent as an empty string")
      void blankUsernameIsOmitted() {
         String json = body(Map.of("discord.username", ""), true);

         assertFalse(json.contains("\"username\""),
               "an empty username is what Discord answers 400 to: " + json);
      }

      @Test
      @DisplayName("A cleared title is left out of an enforced alert")
      void blankTitleIsOmittedWhenEnforced() {
         String json = body(Map.of("discord.title", ""), true);

         assertFalse(json.contains("\"title\""), json);
      }

      @Test
      @DisplayName("A cleared title still says something on a dry run")
      void blankTitleStillLabelsADryRun() {
         String json = body(Map.of("discord.title", ""), false);

         assertTrue(json.contains("\"title\":\"Dry run\""), json);
      }

      @Test
      @DisplayName("A provider answering with a blank ISP does not cost the alert")
      void blankFieldValuesAreFilled() {
         String json = body(Map.of(), payload("Notch", "", true));

         assertFalse(json.contains("\"value\":\"\""),
               "an empty field value is refused the same way an empty title is: " + json);
      }
   }

   @Nested
   @DisplayName("The shipped layout")
   class Defaults {

      @Test
      @DisplayName("Configured values are sent as configured")
      void keepsConfiguredValues() {
         String json = body(Map.of(
               "discord.username", "Guard",
               "discord.title", "Blocked"), true);

         assertTrue(json.contains("\"username\":\"Guard\""), json);
         assertTrue(json.contains("\"title\":\"Blocked\""), json);
      }

      @Test
      @DisplayName("The dry-run marker is appended once, not twice")
      void marksDryRunOnlyOnce() {
         assertTrue(body(Map.of("discord.title", "Blocked"), false)
               .contains("\"title\":\"Blocked (dry run)\""));
         assertTrue(body(Map.of("discord.title", "Alert (dry run)"), false)
               .contains("\"title\":\"Alert (dry run)\""),
               "a layout that already says it must not get a second marker");
      }

      @Test
      @DisplayName("Underscores in a name survive Discord's Markdown")
      void underscoresInNamesAreNotEaten() {
         String json = body(Map.of(), payload("__Maki_Alt__", "M247", true));

         assertTrue(json.contains("\"value\":\"`__Maki_Alt__`\""),
               "the name has to reach Discord as written, not underlined: " + json);
      }

      @Test
      @DisplayName("show-ip: false hides the address without emptying the field")
      void hiddenIpStaysPresent() {
         String json = body(Map.of("discord.show-ip", false), true);

         assertTrue(json.contains("\"value\":\"`hidden`\""), json);
         assertFalse(json.contains("1.2.3.4"), json);
      }

      @Test
      @DisplayName("A config without an embed section keeps the six classic boxes")
      void classicLayoutIsTheFallback() {
         String json = body(Map.of(), true);

         for (String name : new String[] {"Player", "IP", "Country", "Reason", "ISP", "Action"}) {
            assertTrue(json.contains("\"name\":\"" + name + "\""), name + " missing from " + json);
         }
         assertFalse(json.contains("\"description\""), json);
         assertFalse(json.contains("\"thumbnail\""), json);
      }
   }

   @Nested
   @DisplayName("A layout the operator wrote")
   class CustomLayout {

      /** The single-block style, i.e. a title, a description and no boxes. */
      private Map<String, Object> singleBlock() {
         return Map.of(
               "discord.embed.title", "`{player}`",
               "discord.embed.description",
               "```ansi\nIP: `{ip}`\nCountry: {country}\nAction: {action}\n```",
               "discord.embed.thumbnail", "https://example.com/alert.gif",
               "discord.embed.footer", "");
      }

      @Test
      @DisplayName("Title, description and thumbnail replace the boxes")
      void rendersTheSingleBlockStyle() {
         String json = body(singleBlock(), true);

         assertTrue(json.contains("\"title\":\"`Notch`\""), json);
         assertTrue(json.contains("IP: `1.2.3.4`"), json);
         assertTrue(json.contains("Country: DE"), json);
         assertTrue(json.contains("Action: Connection denied"), json);
         assertTrue(json.contains("\"thumbnail\":{\"url\":\"https://example.com/alert.gif\"}"),
               json);
         assertFalse(json.contains("\"fields\""), "no field was configured: " + json);
         assertFalse(json.contains("\"footer\""), "the footer was cleared: " + json);
      }

      @Test
      @DisplayName("A plain http thumbnail is dropped rather than sent")
      void thumbnailMustBeHttps() {
         String json = body(Map.of("discord.embed.thumbnail", "http://example.com/a.png"), true);

         assertFalse(json.contains("\"thumbnail\""), json);
      }

      @Test
      @DisplayName("Named fields are rendered in the order they are written")
      void rendersNamedFields() {
         // Insertion ordered on purpose: the file order is what decides the order in the message,
         // and Map.of would not have one.
         Map<String, Object> settings = new LinkedHashMap<>();
         settings.put("discord.embed.fields.Who.value", "`{player}`");
         settings.put("discord.embed.fields.Who.inline", false);
         settings.put("discord.embed.fields.Network.value", "{asn} scored {score}");

         String json = body(settings, true);

         int who = json.indexOf("\"name\":\"Who\"");
         int network = json.indexOf("\"name\":\"Network\"");
         assertTrue(who >= 0 && network > who, "expected Who before Network in " + json);
         assertTrue(json.contains("\"value\":\"AS9009 scored 2.50\""), json);
         assertTrue(json.contains("\"inline\":false"), json);
      }

      @Test
      @DisplayName("Every documented placeholder resolves")
      void allPlaceholdersResolve() {
         String json = body(Map.of("discord.embed.description",
               "{player} {uuid} {ip} {reason} {country} {isp} {asn} {score} {sources} "
                     + "{action} {action_id} {platform} {version}"), true);

         String description = json.substring(json.indexOf("\"description\":\""));
         description = description.substring(15, description.indexOf("\",\""));

         assertFalse(description.contains("{"),
               "an unresolved placeholder is left in " + description);
         assertTrue(description.contains(PLAYER_ID.toString()), description);
         assertTrue(description.contains("kicked"), description);
      }

      @Test
      @DisplayName("A backtick from a provider cannot close a span the layout opened")
      void backticksInProviderTextAreDropped() {
         String json = body(Map.of("discord.embed.description", "ISP: `{isp}`"),
               payload("Notch", "ev`il", true));

         assertTrue(json.contains("ISP: `evil`"), json);
      }
   }
}
