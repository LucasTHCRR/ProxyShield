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

import de.empireblocks.updaterapi.AutoUpdater;
import de.empireblocks.updaterapi.UpdateNotifier;
import de.empireblocks.updaterapi.UpdateVersion;
import de.empireblocks.updaterapi.UpdaterAPI;
import de.empireblocks.updaterapi.provider.CodebergProvider;
import de.empireblocks.updaterapi.provider.HangarProvider;
import de.empireblocks.updaterapi.provider.ModrinthProvider;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import de.lucasthcr.bridgesave.proxyshield.platform.UpdateTarget;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Tells the console when a newer ProxyShield is out and, where the server has an update folder and
 * the owner switched it on, stages the new jar there. The running jar is never touched.
 */
public final class UpdateService {

   private static final String MODRINTH_PROJECT = "nqiuEiMp";
   private static final Duration INTERVAL = Duration.ofHours(12);

   private final Platform platform;
   private final Supplier<ShieldConfig> config;
   private final UpdaterAPI updater;
   private final UpdateNotifier notifier;
   private volatile String announced;

   public UpdateService(Platform platform, Supplier<ShieldConfig> config) {
      this(platform, config, defaultUpdater(platform));
   }

   UpdateService(Platform platform, Supplier<ShieldConfig> config, UpdaterAPI updater) {
      this.platform = platform;
      this.config = config;
      this.updater = updater;
      this.notifier = UpdateNotifier.builder(updater)
            .executor(platform::runAsync)
            .interval(INTERVAL)
            .initialDelay(Duration.ofMinutes(2))
            .onUpdate(this::announce)
            .build();
   }

   private static UpdaterAPI defaultUpdater(Platform platform) {
      String version = platform.version();
      String agent = userAgent(platform);
      // One universal jar carries every loader, so any of them counts as the newest version.
      Set<String> loaders = Set.of("paper", "bukkit", "spigot", "folia", "purpur", "bungeecord", "velocity",
            "waterfall", "sponge");
      Set<String> types = version.toUpperCase(Locale.ROOT).endsWith("-RELEASE")
            ? Set.of("release") : Set.of("release", "beta");
      return UpdaterAPI.builder(version, agent)
            .acceptedTypes(types)
            .logger(logger(platform))
            .addProvider(ModrinthProvider.builder(MODRINTH_PROJECT).userAgent(agent).loaders(loaders)
                  .requireMatchingGameVersion(false).build())
            .addProvider(new HangarProvider("LucasTHCR", "ProxyShield", agent))
            .addProvider(new CodebergProvider("LucasTHCR", "ProxyShield", agent))
            .build();
   }

   private static String userAgent(Platform platform) {
      return "ProxyShield/" + platform.version() + " (support@paperstream.dev)";
   }

   private static Logger logger(Platform platform) {
      Logger logger = Logger.getAnonymousLogger();
      logger.setUseParentHandlers(false);
      logger.addHandler(new Handler() {
         @Override
         public void publish(LogRecord record) {
            if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
               platform.warn(record.getMessage());
            } else {
               platform.info(record.getMessage());
            }
         }

         @Override
         public void flush() {
         }

         @Override
         public void close() {
         }
      });
      return logger;
   }

   /** Called every minute, checks when the interval has passed. Does nothing when notifying is off. */
   public void tick() {
      if (config.get().updatesNotify()) {
         notifier.tick();
      }
   }

   /** Runs the check now instead of waiting for the interval, for tests. */
   void runCheck() {
      notifier.checkNow();
   }

   private void announce(UpdateVersion version) {
      announced = version.versionNumber();
      platform.info("ProxyShield " + version.versionNumber() + " is out on " + version.sourceName()
            + ", this server runs " + updater.currentVersion() + ". /proxyshield update shows more.");
      if (config.get().updatesAutoInstall()) {
         Result result = stage();
         if (result.status() == AutoUpdater.Status.STAGED) {
            platform.info("ProxyShield " + result.version() + " is staged, it takes effect on the next restart.");
         }
      }
   }

   /** The newest version that was announced since the start, or null. */
   public String announced() {
      return announced;
   }

   /** Blocking, never call it from the main thread. */
   public UpdaterAPI.UpdateCheckResult checkNow() {
      return updater.checkForUpdates();
   }

   /** Blocking. Stages the newest version into the update folder when this platform has one. */
   public Result stage() {
      Optional<UpdateTarget> target = platform.updateTarget();
      if (target.isEmpty()) {
         return new Result(AutoUpdater.Status.DISABLED, null, "no update folder on this platform");
      }
      AutoUpdater.Result result = new AutoUpdater(updater, userAgent(platform))
            .checkAndStage(target.get().jar().toFile(), target.get().folder().toFile());
      return new Result(result.status(), result.version(), result.detail());
   }

   public record Result(AutoUpdater.Status status, String version, String detail) {
   }
}
