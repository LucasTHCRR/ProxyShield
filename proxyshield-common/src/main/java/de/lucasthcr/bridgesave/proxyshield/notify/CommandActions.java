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

import de.lucasthcr.bridgesave.proxyshield.check.CheckVerdict;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Runs the console commands configured under {@code actions.on-flag}.
 * <p>
 * This is the hook for everything ProxyShield deliberately does not implement itself. A server that
 * would rather mark a flagged player than drop them, by putting them in a restricted group, making
 * them verify through Discord or handing the name to another plugin's webhook command, writes that
 * as a command here instead of waiting for it to become a setting.
 * <p>
 * Nothing in here decides anything: the verdict is already final by the time the commands run, so a
 * command cannot let a blocked player in or keep an allowed one out.
 */
public final class CommandActions {

   /** Guards against a config that would flood the scheduler from a single detection. */
   private static final int MAX_COMMANDS_PER_FLAG = 20;

   private final Platform platform;

   private volatile ShieldConfig config;

   public CommandActions(Platform platform, ShieldConfig config) {
      this.platform = platform;
      this.config = config;
   }

   public void applyConfig(ShieldConfig config) {
      this.config = config;
   }

   /**
    * Dispatches the configured commands for one detection.
    *
    * @param enforced {@code false} when dry-run kept the player connected
    */
   public void onFlag(String player, UUID uuid, String ip, CheckVerdict verdict, boolean enforced) {
      ShieldConfig current = config;
      List<String> commands = current.flagCommands();
      if (commands.isEmpty() || !current.flagCommandTrigger().matches(enforced)) {
         return;
      }

      Map<String, String> values = placeholders(player, uuid, ip, verdict, enforced);
      long delay = current.flagCommandDelaySeconds();
      int dispatched = 0;

      for (String template : commands) {
         if (dispatched++ >= MAX_COMMANDS_PER_FLAG) {
            platform.warn("actions.on-flag lists more than " + MAX_COMMANDS_PER_FLAG
                  + " commands; the rest were skipped.");
            break;
         }
         String command = fill(template, values);
         try {
            platform.dispatchCommand(command, delay);
         } catch (RuntimeException failure) {
            // One broken command must not cost the detection its alert or its webhook.
            platform.warn("Could not run the flag command '" + command + "': "
                  + failure.getMessage());
         }
      }
   }

   private Map<String, String> placeholders(String player, UUID uuid, String ip,
         CheckVerdict verdict, boolean enforced) {
      return Map.ofEntries(
            Map.entry("player", player == null ? "unknown" : player),
            Map.entry("uuid", uuid == null ? "" : uuid.toString()),
            Map.entry("ip", ip == null ? "unknown" : ip),
            Map.entry("reason", verdict.describe()),
            Map.entry("reason_id", verdict.reason().name().toLowerCase(Locale.ROOT)),
            Map.entry("country", verdict.lookup().countryOrUnknown()),
            Map.entry("isp", verdict.lookup().ispOrUnknown()),
            Map.entry("asn", verdict.lookup().asnOrUnknown()),
            Map.entry("score", String.format(Locale.ROOT, "%.2f", verdict.lookup().confidence())),
            Map.entry("sources", verdict.lookup().sourceSummary()),
            Map.entry("action", enforced ? "kicked" : "allowed"),
            // Same spelling the embed layout uses, so one name means one thing in both places.
            // {action} stays as it shipped in 2.3.0 rather than changing under anyone.
            Map.entry("action_id", enforced ? "kicked" : "allowed"),
            Map.entry("platform", platform.name()));
   }

   /**
    * Substitutes {@code {key}} placeholders, the same spelling the message files use.
    * <p>
    * Values are sanitised rather than inserted verbatim: an ISP name is provider-controlled text,
    * and a newline or a second command inside one would otherwise turn a single configured command
    * into several. Unknown placeholders are left alone, so a command meant for another plugin's own
    * {@code {}} syntax survives.
    */
   private static String fill(String template, Map<String, String> values) {
      String result = template;
      for (Map.Entry<String, String> entry : values.entrySet()) {
         String token = "{" + entry.getKey() + "}";
         if (result.contains(token)) {
            result = result.replace(token, sanitize(entry.getValue()));
         }
      }
      return result;
   }

   /** Strips what a command dispatcher would read as a separator or a new command. */
   private static String sanitize(String value) {
      if (value == null || value.isEmpty()) {
         return "";
      }
      StringBuilder out = new StringBuilder(value.length());
      for (int i = 0; i < value.length(); i++) {
         char c = value.charAt(i);
         if (c == '\n' || c == '\r' || c == ';' || c == '&' || c == '|' || c == '"'
               || c == '\'' || c == '`') {
            out.append(' ');
         } else {
            out.append(c);
         }
      }
      return out.toString().trim();
   }
}
