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
import java.nio.file.Path;
import java.util.Map;

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
         3, "config.yml");

   private ConfigMigration() {
   }

   public static void run(Platform platform) {
      Path file = platform.dataFolder().resolve("config.yml");
      VersionedUpgrader.Result result = VersionedUpgrader.upgradeFromResources(file,
            name -> ConfigMigration.class.getClassLoader().getResourceAsStream(name), HISTORY, null);
      if (result.failure() != null) {
         platform.warn("config.yml was not upgraded, it stays as it is: " + result.failure());
      } else if (!result.added().isEmpty()) {
         platform.info("config.yml upgraded from version " + result.fromVersion() + " to " + result.toVersion()
               + ", added: " + String.join(", ", result.added()) + ". The old file is kept as config.yml.bak.");
      }
   }
}
