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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigMigrationTest {

   private static final String ZOWI = "    zowi:\n      enabled: true\n      weight: 1.5\n      key: \"\"\n";

   @TempDir
   Path tempDir;

   private static String resource(String name) throws IOException {
      try (InputStream in = ConfigMigrationTest.class.getClassLoader().getResourceAsStream(name)) {
         return new String(in.readAllBytes(), StandardCharsets.UTF_8);
      }
   }

   private String migrate(String installed, RecordingPlatform platform) throws IOException {
      Path file = tempDir.resolve("config.yml");
      Files.writeString(file, installed);
      ConfigMigration.run(platform);
      return Files.readString(file);
   }

   @Test
   @DisplayName("An install of 3.0.2 gets the new blocks, but not the provider the admin deleted")
   void addsNewAndKeepsDeletions() throws IOException {
      String installed = resource("config-history/2.yml");
      assertTrue(installed.contains(ZOWI), "the test needs the provider it deletes");
      installed = installed.replace(ZOWI, "").replace("hosting-min-score: 0.5", "hosting-min-score: 1.5");
      RecordingPlatform platform = new RecordingPlatform(tempDir);

      String upgraded = migrate(installed, platform);

      assertTrue(upgraded.contains("\nupdates:\n"), "new section updates");
      assertTrue(upgraded.contains("\nreporting:\n"), "new section reporting");
      assertTrue(upgraded.contains("    paperstream:\n"), "new provider");
      assertFalse(upgraded.contains(ZOWI), "the deleted provider stays deleted");
      assertTrue(upgraded.contains("hosting-min-score: 1.5"), "the admin's value stays");
      assertTrue(upgraded.contains("version: 3"));
      assertTrue(Files.exists(tempDir.resolve("config.yml.bak")));
      assertTrue(platform.infos().stream().anyMatch(line -> line.contains("upgraded from version")));
   }

   @Test
   @DisplayName("A second start changes nothing")
   void runsOnce() throws IOException {
      RecordingPlatform platform = new RecordingPlatform(tempDir);
      String once = migrate(resource("config-history/2.yml"), platform);
      platform.infos().clear();

      ConfigMigration.run(platform);

      assertEquals(once, Files.readString(tempDir.resolve("config.yml")));
      assertTrue(platform.infos().isEmpty());
   }

   @Test
   @DisplayName("A fresh install, which already has the current file, is left alone")
   void freshInstallUntouched() throws IOException {
      RecordingPlatform platform = new RecordingPlatform(tempDir);
      String current = resource("config.yml");

      assertEquals(current, migrate(current, platform));
      assertTrue(platform.infos().isEmpty());
      assertTrue(platform.warnings().isEmpty());
   }

   @Test
   @DisplayName("An install of 3.0.0 without a marker goes through every step")
   void fromTheFirstRelease() throws IOException {
      RecordingPlatform platform = new RecordingPlatform(tempDir);

      String upgraded = migrate(resource("config-history/1.yml"), platform);

      assertTrue(upgraded.contains("version: 3"));
      assertTrue(upgraded.contains("\nreporting:\n"));
      assertTrue(platform.warnings().isEmpty(), platform.warnings().toString());
   }
}
