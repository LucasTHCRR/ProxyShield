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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.lucasthcr.bridgesave.proxyshield.check.CheckVerdict;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import de.lucasthcr.bridgesave.proxyshield.message.Messages;
import de.lucasthcr.bridgesave.proxyshield.testing.MapConfigNode;
import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The fan-out itself, wired the way the core wires it.
 * <p>
 * Covers the part the {@link CommandActions} unit tests cannot: that a detection reaching the
 * dispatcher carries the account through to the commands, and which channels silent mode does and
 * does not switch off.
 */
class AlertDispatcherTest {

   private static final UUID PLAYER_ID = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

   private RecordingPlatform platform;

   @BeforeEach
   void setUp(@TempDir Path tempDir) {
      platform = new RecordingPlatform(tempDir);
   }

   private AlertDispatcher dispatcher(Map<String, Object> settings) {
      ShieldConfig config = ShieldConfig.from(new MapConfigNode(settings));
      return new AlertDispatcher(platform, config, Messages.builtIn(),
            new DiscordWebhook(platform, config), new CommandActions(platform, config));
   }

   private static CheckVerdict verdict() {
      return CheckVerdict.deny(CheckVerdict.Reason.PROXY, "score 2.0",
            LookupResult.of(true, false, "de", "Germany", "M247"));
   }

   @Test
   @DisplayName("A detection reaches the alert channels and the commands alike")
   void fansOutToCommands() {
      dispatcher(Map.of(
            "notifications.log-file", false,
            "actions.on-flag", List.of("verify {player} {uuid}")))
            .alert("Notch", PLAYER_ID, "1.2.3.4", verdict(), false);

      assertEquals(1, platform.consoleMessages().size());
      assertEquals(1, platform.dispatchedCommands().size());
      assertEquals("verify Notch " + PLAYER_ID,
            platform.dispatchedCommands().get(0).command());
   }

   @Test
   @DisplayName("Silent mode hides the alert but still runs the commands")
   void silentModeKeepsActions() {
      dispatcher(Map.of(
            "notifications.silent", true,
            "notifications.log-file", false,
            "actions.on-flag", List.of("verify {player}")))
            .alert("Notch", PLAYER_ID, "1.2.3.4", verdict(), false);

      assertTrue(platform.consoleMessages().isEmpty(), "silent mode must not print the alert");
      assertEquals(1, platform.dispatchedCommands().size(),
            "silent is about who reads it, not about whether the action happens");
   }

   @Test
   @DisplayName("Reload swaps the commands through the dispatcher")
   void reloadReachesCommands() {
      AlertDispatcher dispatcher = dispatcher(Map.of(
            "notifications.log-file", false,
            "actions.on-flag", List.of("before {player}")));

      dispatcher.applyConfig(ShieldConfig.from(new MapConfigNode(Map.of(
            "notifications.log-file", false,
            "actions.on-flag", List.of("after {player}")))), Messages.builtIn());
      dispatcher.alert("Notch", PLAYER_ID, "1.2.3.4", verdict(), false);

      assertEquals("after Notch", platform.dispatchedCommands().get(0).command());
   }

   @Test
   @DisplayName("Without commands configured nothing is dispatched")
   void quietWhenUnconfigured() {
      dispatcher(Map.of("notifications.log-file", false))
            .alert("Notch", PLAYER_ID, "1.2.3.4", verdict(), true);

      assertFalse(platform.consoleMessages().isEmpty());
      assertTrue(platform.dispatchedCommands().isEmpty());
   }
}
