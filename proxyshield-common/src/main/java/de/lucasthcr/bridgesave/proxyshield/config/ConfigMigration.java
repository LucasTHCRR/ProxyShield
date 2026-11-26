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

package de.lucasthcr.bridgesave.proxyshield.config;

import de.empireblocks.updaterapi.config.VersionedUpgrader;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Brings an existing config.yml up to the current release. Only options a release really brought
 * are added, so what an admin deleted stays deleted. A file without the version marker counts as
 * the oldest release in the history. Every release that changes config.yml adds its shipped file
 * to config-history and raises the number here and in config.yml.
 */
public final class ConfigMigration {

   /** Version number to the resource holding that release's default file, the newest last. */
   static final Map<Integer, String> HISTORY = Map.of(
         1, "config-history/1.yml",
         2, "config-history/2.yml",
         3, "config-history/3.yml",
         4, "config.yml");

   private static final Pattern FAST_ADMIT_AUTO = Pattern.compile("(?m)^(\\s+fast-admit:\\s*)\"?auto\"?[ \\t]*$");

   private ConfigMigration() {
   }

   public static void run(Platform platform) {
      Path file = platform.dataFolder().resolve("config.yml");
      VersionedUpgrader.Result result = VersionedUpgrader.upgradeFromResources(file,
            name -> ConfigMigration.class.getClassLoader().getResourceAsStream(name), HISTORY, null);
      if (result.failure() != null) {
         platform.warn("config.yml was not upgraded, it stays as it is: " + result.failure());
         return;
      } else if (!result.added().isEmpty()) {
         platform.info("config.yml upgraded from version " + result.fromVersion() + " to " + result.toVersion()
               + ", added: " + String.join(", ", result.added()) + ". The old file is kept as config.yml.bak.");
      }
      if (result.fromVersion() < 4 && shortenTimeouts(file)) {
         platform.info("api.timeout-seconds and api.total-timeout-seconds now use the new defaults 1.5 and 2.5.");
      }
      if (result.fromVersion() < 4 && switchOffFastAdmit(file)) {
         platform.info("detection.network-data.fast-admit is now \"never\", the new default. Set it to auto for the old behaviour.");
      }
   }


   private static final Pattern OLD_TIMEOUT = Pattern.compile("(?m)^(  timeout-seconds:\\s*)4[ \\t]*$");
   private static final Pattern OLD_TOTAL = Pattern.compile("(?m)^(  total-timeout-seconds:\\s*)6[ \\t]*$");

   // Alte Standard-Timeouts (4 s / 6 s) werden auf die neuen (1,5 s / 2,5 s) gesetzt, eigene Werte bleiben
   static boolean shortenTimeouts(Path file) {
      try {
         String text = Files.readString(file);
         String changed = OLD_TOTAL.matcher(OLD_TIMEOUT.matcher(text).replaceFirst("$11.5")).replaceFirst("$12.5");
         if (changed.equals(text)) {
            return false;
         }
         Files.writeString(file, changed);
         return true;
      } catch (IOException | RuntimeException failed) {
         return false;
      }
   }

   // Ab Version 4 ist fast-admit aus, der fruehere Standard "auto" wird umgestellt
   static boolean switchOffFastAdmit(Path file) {
      try {
         String text = Files.readString(file);
         String changed = FAST_ADMIT_AUTO.matcher(text).replaceFirst("$1never");
         if (changed.equals(text)) {
            return false;
         }
         Files.writeString(file, changed);
         return true;
      } catch (IOException | RuntimeException failed) {
         return false;
      }
   }
}
