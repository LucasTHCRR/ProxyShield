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

package de.lucasthcr.bridgesave.proxyshield.update;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.empireblocks.updaterapi.AutoUpdater;
import de.empireblocks.updaterapi.UpdateProvider;
import de.empireblocks.updaterapi.UpdateVersion;
import de.empireblocks.updaterapi.UpdaterAPI;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.testing.MapConfigNode;
import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class UpdateServiceTest {

   @TempDir
   Path tempDir;

   private static UpdateProvider newest(String version) {
      return new UpdateProvider() {
         @Override
         public String name() {
            return "Fake";
         }

         @Override
         public UpdateVersion fetchLatest(String minecraftVersion, Set<String> acceptedTypes) {
            return new UpdateVersion(version, "ProxyShield-Universal-" + version + ".jar",
                  "https://example.invalid/proxyshield.jar", 100L, "Fake");
         }
      };
   }

   private UpdateService service(RecordingPlatform platform, String running, String newest) {
      ShieldConfig config = ShieldConfig.from(new MapConfigNode(new LinkedHashMap<>()));
      UpdaterAPI updater = UpdaterAPI.builder(running, "test").addProvider(newest(newest))
            .acceptedTypes(Set.of("release", "beta")).build();
      return new UpdateService(platform, () -> config, updater);
   }

   @Test
   @DisplayName("Notifying is on and installing is off unless the owner changes it")
   void defaults() {
      ShieldConfig config = ShieldConfig.from(new MapConfigNode(new LinkedHashMap<>()));

      assertTrue(config.updatesNotify());
      assertFalse(config.updatesAutoInstall());
   }

   @Test
   @DisplayName("A newer version is announced once, not on every check")
   void announcesOnce() {
      RecordingPlatform platform = new RecordingPlatform(tempDir);
      UpdateService service = service(platform, "3.1.0-BETA", "3.1.1-RELEASE");

      service.runCheck();
      service.runCheck();

      assertEquals("3.1.1-RELEASE", service.announced());
      assertEquals(1, platform.infos().stream().filter(line -> line.contains("3.1.1-RELEASE")).count());
   }

   @Test
   @DisplayName("The version a server runs, or an older one, is not announced")
   void staysQuietWhenCurrent() {
      RecordingPlatform platform = new RecordingPlatform(tempDir);
      UpdateService service = service(platform, "3.1.0-BETA", "3.0.2+universal");

      service.runCheck();

      assertNull(service.announced());
      assertTrue(platform.infos().isEmpty());
   }

   @Test
   @DisplayName("A release after the beta of the same number counts as an update")
   void releaseBeatsBeta() {
      RecordingPlatform platform = new RecordingPlatform(tempDir);
      UpdateService service = service(platform, "3.1.0-BETA", "3.1.0-RELEASE");

      service.runCheck();

      assertEquals("3.1.0-RELEASE", service.announced());
   }

   @Test
   @DisplayName("Without an update folder nothing is staged")
   void noFolderNoStaging() {
      RecordingPlatform platform = new RecordingPlatform(tempDir);
      UpdateService service = service(platform, "3.1.0-BETA", "3.1.1-RELEASE");

      assertEquals(AutoUpdater.Status.DISABLED, service.stage().status());
   }

   @Test
   @DisplayName("A check that cannot reach any source is reported as not found")
   void nothingFound() {
      RecordingPlatform platform = new RecordingPlatform(tempDir);
      UpdateProvider silent = new UpdateProvider() {
         @Override
         public String name() {
            return "Silent";
         }

         @Override
         public UpdateVersion fetchLatest(String minecraftVersion, Set<String> acceptedTypes) {
            return null;
         }
      };
      UpdaterAPI updater = UpdaterAPI.builder("3.1.0-BETA", "test").addProvider(silent).build();
      UpdateService service = new UpdateService(platform,
            () -> ShieldConfig.from(new MapConfigNode(new LinkedHashMap<>())), updater);

      assertFalse(service.checkNow().found());
   }
}
