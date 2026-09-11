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
import de.lucasthcr.bridgesave.proxyshield.testing.MapConfigNode;
import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform;
import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform.DispatchedCommand;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The {@code actions.on-flag} hook: what runs, with what substituted, and when it stays quiet. */
class CommandActionsTest {

   private static final UUID PLAYER_ID = UUID.fromString("11111111-2222-3333-4444-555555555555");

   private RecordingPlatform platform;

   @BeforeEach
   void setUp(@TempDir Path tempDir) {
      platform = new RecordingPlatform(tempDir);
   }

   private CommandActions actions(Map<String, Object> settings) {
      return new CommandActions(platform, ShieldConfig.from(new MapConfigNode(settings)));
   }

   private static CheckVerdict proxyVerdict() {
      LookupResult lookup = LookupResult.of(true, false, false, "de", "Germany", "M247",
            "AS9009", "hosting", 2.5, List.of("ip-api", "iphub"));
      return CheckVerdict.deny(CheckVerdict.Reason.PROXY, "score 2.5", lookup);
   }

   private List<DispatchedCommand> dispatched() {
      return platform.dispatchedCommands();
   }

   @Test
   @DisplayName("Nothing runs when no command is configured")
   void emptyByDefault() {
      actions(Map.of()).onFlag("Notch", PLAYER_ID, "1.2.3.4", proxyVerdict(), false);
      assertTrue(dispatched().isEmpty());
   }

   @Test
   @DisplayName("Placeholders are filled and the leading slash is dropped")
   void fillsPlaceholders() {
      actions(Map.of("actions.on-flag",
            List.of("/lp user {player} permission set flagged true",
                  "webhook {player} {uuid} {ip} {reason_id} {country} {asn} {action}")))
            .onFlag("Notch", PLAYER_ID, "1.2.3.4", proxyVerdict(), true);

      assertEquals(2, dispatched().size());
      assertEquals("lp user Notch permission set flagged true", dispatched().get(0).command());
      assertEquals("webhook Notch " + PLAYER_ID + " 1.2.3.4 proxy DE AS9009 kicked",
            dispatched().get(1).command());
   }

   @Test
   @DisplayName("The configured delay is handed to the platform unchanged")
   void passesDelayThrough() {
      actions(Map.of("actions.on-flag", List.of("link {player}"), "actions.delay-seconds", 5))
            .onFlag("Notch", PLAYER_ID, "1.2.3.4", proxyVerdict(), false);

      assertEquals(5L, dispatched().get(0).delaySeconds());
   }

   @Test
   @DisplayName("A delay beyond the cap is clamped rather than trusted")
   void clampsAbsurdDelay() {
      actions(Map.of("actions.on-flag", List.of("link {player}"),
            "actions.delay-seconds", 99_999))
            .onFlag("Notch", PLAYER_ID, "1.2.3.4", proxyVerdict(), false);

      assertEquals(300L, dispatched().get(0).delaySeconds());
   }

   @Test
   @DisplayName("run-when: allowed skips the players who were actually kicked")
   void runWhenAllowed() {
      CommandActions actions = actions(Map.of("actions.on-flag", List.of("link {player}"),
            "actions.run-when", "allowed"));

      actions.onFlag("Kicked", PLAYER_ID, "1.2.3.4", proxyVerdict(), true);
      assertTrue(dispatched().isEmpty(), "an enforced kick must not trigger an allowed-only action");

      actions.onFlag("Stayed", PLAYER_ID, "1.2.3.4", proxyVerdict(), false);
      assertEquals(1, dispatched().size());
      assertEquals("link Stayed", dispatched().get(0).command());
   }

   @Test
   @DisplayName("run-when: kicked is the mirror image")
   void runWhenKicked() {
      CommandActions actions = actions(Map.of("actions.on-flag", List.of("log {player}"),
            "actions.run-when", "kicked"));

      actions.onFlag("Stayed", PLAYER_ID, "1.2.3.4", proxyVerdict(), false);
      assertTrue(dispatched().isEmpty());

      actions.onFlag("Kicked", PLAYER_ID, "1.2.3.4", proxyVerdict(), true);
      assertEquals(1, dispatched().size());
   }

   @Test
   @DisplayName("A provider-supplied ISP cannot smuggle a second command in")
   void sanitisesUntrustedValues() {
      LookupResult hostile = LookupResult.of(true, false, false, "de", "Germany",
            "Evil; op Notch", "AS1", null, 1.0, List.of("ip-api"));
      CheckVerdict verdict = CheckVerdict.deny(CheckVerdict.Reason.PROXY, "x", hostile);

      actions(Map.of("actions.on-flag", List.of("note {isp}")))
            .onFlag("Notch", PLAYER_ID, "1.2.3.4", verdict, false);

      String command = dispatched().get(0).command();
      assertFalse(command.contains(";"), "a separator in provider text must not survive: " + command);
      assertEquals("note Evil  op Notch", command);
   }

   @Test
   @DisplayName("{action_id} means the same here as in the Discord layout")
   void actionIdMatchesTheEmbedSpelling() {
      CommandActions actions = actions(Map.of("actions.on-flag",
            List.of("log {action} {action_id}")));

      actions.onFlag("Notch", PLAYER_ID, "1.2.3.4", proxyVerdict(), true);
      assertEquals("log kicked kicked", dispatched().get(0).command());
   }

   @Test
   @DisplayName("An unknown placeholder is left for whatever plugin owns it")
   void leavesUnknownPlaceholders() {
      actions(Map.of("actions.on-flag", List.of("other {not_ours} {player}")))
            .onFlag("Notch", PLAYER_ID, "1.2.3.4", proxyVerdict(), false);

      assertEquals("other {not_ours} Notch", dispatched().get(0).command());
   }

   @Test
   @DisplayName("A missing name or address still produces a runnable command")
   void toleratesMissingValues() {
      actions(Map.of("actions.on-flag", List.of("check {player} {ip} {uuid}")))
            .onFlag(null, null, null, proxyVerdict(), false);

      assertEquals("check unknown unknown ", dispatched().get(0).command());
   }

   @Test
   @DisplayName("Reload swaps the command list without rebuilding the dispatcher")
   void appliesReloadedConfig() {
      CommandActions actions = actions(Map.of("actions.on-flag", List.of("before {player}")));
      actions.applyConfig(ShieldConfig.from(new MapConfigNode(
            Map.of("actions.on-flag", List.of("after {player}")))));

      actions.onFlag("Notch", PLAYER_ID, "1.2.3.4", proxyVerdict(), false);
      assertEquals("after Notch", dispatched().get(0).command());
   }

   @Test
   @DisplayName("A runaway command list is cut off instead of flooding the scheduler")
   void capsCommandCount() {
      List<String> many = new java.util.ArrayList<>();
      for (int i = 0; i < 40; i++) {
         many.add("cmd" + i);
      }

      actions(Map.of("actions.on-flag", many))
            .onFlag("Notch", PLAYER_ID, "1.2.3.4", proxyVerdict(), false);

      assertEquals(20, dispatched().size());
      assertFalse(platform.warnings().isEmpty(), "the operator has to be told it was cut off");
   }
}
