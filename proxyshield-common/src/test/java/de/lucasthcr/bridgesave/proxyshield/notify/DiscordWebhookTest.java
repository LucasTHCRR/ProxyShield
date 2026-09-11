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
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The shape of the webhook payload.
 * <p>
 * Discord answers {@code 400} for the whole request when a string it expects to be filled arrives
 * empty, and the plugin only sees the status code, so the mistake looks like a broken token. These
 * pin the cases where a value can legitimately be blank.
 */
class DiscordWebhookTest {

   private RecordingPlatform platform;

   @BeforeEach
   void setUp(@TempDir Path tempDir) {
      platform = new RecordingPlatform(tempDir);
   }

   private String body(Map<String, Object> settings, boolean enforced) {
      ShieldConfig config = ShieldConfig.from(new MapConfigNode(settings));
      DiscordWebhook webhook = new DiscordWebhook(platform, config);
      return webhook.buildBody(config, new DiscordWebhook.Payload(
            "Notch", "1.2.3.4", "VPN list", "DE", "M247", enforced));
   }

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
   @DisplayName("Configured values are sent as configured")
   void keepsConfiguredValues() {
      String json = body(Map.of(
            "discord.username", "Guard",
            "discord.title", "Blocked"), true);

      assertTrue(json.contains("\"username\":\"Guard\""), json);
      assertTrue(json.contains("\"title\":\"Blocked\""), json);
   }

   @Test
   @DisplayName("The dry-run suffix is appended to a configured title")
   void marksDryRunOnConfiguredTitle() {
      String json = body(Map.of("discord.title", "Blocked"), false);

      assertTrue(json.contains("\"title\":\"Blocked (dry run)\""), json);
   }

   @Test
   @DisplayName("A provider answering with a blank ISP does not cost the alert")
   void blankFieldValuesAreFilled() {
      ShieldConfig config = ShieldConfig.from(new MapConfigNode(Map.of()));
      String json = new DiscordWebhook(platform, config).buildBody(config,
            new DiscordWebhook.Payload("Notch", "1.2.3.4", "VPN list", "DE", "", true));

      assertFalse(json.contains("\"value\":\"\""),
            "an empty embed field value is refused the same way an empty title is: " + json);
   }

   @Test
   @DisplayName("show-ip: false hides the address without emptying the field")
   void hiddenIpStaysPresent() {
      String json = body(Map.of("discord.show-ip", false), true);

      assertTrue(json.contains("\"value\":\"`hidden`\""), json);
      assertFalse(json.contains("1.2.3.4"), json);
   }

   @Test
   @DisplayName("Underscores in a name survive Discord's Markdown")
   void underscoresInNamesAreNotEaten() {
      ShieldConfig config = ShieldConfig.from(new MapConfigNode(Map.of()));
      String json = new DiscordWebhook(platform, config).buildBody(config,
            new DiscordWebhook.Payload("__Maki_Alt__", "1.2.3.4", "VPN list", "DE", "M247", true));

      assertTrue(json.contains("\"value\":\"`__Maki_Alt__`\""),
            "the name has to reach Discord as written, not underlined: " + json);
   }

   @Test
   @DisplayName("A backtick from a provider cannot break out of the code span")
   void backticksInProviderTextAreDropped() {
      ShieldConfig config = ShieldConfig.from(new MapConfigNode(Map.of()));
      String json = new DiscordWebhook(platform, config).buildBody(config,
            new DiscordWebhook.Payload("Notch", "1.2.3.4", "VPN list", "DE", "ev`il", true));

      assertTrue(json.contains("\"value\":\"`evil`\""), json);
   }
}
