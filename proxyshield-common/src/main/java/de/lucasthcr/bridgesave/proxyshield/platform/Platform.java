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

package de.lucasthcr.bridgesave.proxyshield.platform;

import de.lucasthcr.bridgesave.proxyshield.config.ConfigNode;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;

/**
 * Everything the detection core needs from the server it runs on.
 * <p>
 * One implementation exists per platform (Paper, BungeeCord, Velocity); the core itself never
 * touches a platform API directly, which is what allows the exact same detection behaviour on
 * all three.
 */
public interface Platform {

   /** Human readable platform name, used in log output and {@code /proxyshield info}. */
   String name();

   /** Plugin version, taken from the platform's own plugin descriptor. */
   String version();

   /** Directory the plugin may write its config, caches and logs to. */
   Path dataFolder();

   /**
    * Copies a resource bundled in the plugin jar into {@link #dataFolder()}, unless a file of that
    * name is already there. Used for config.yml and the message files.
    */
   void saveResource(String resourceName);

   /**
    * Reads a YAML file from {@link #dataFolder()}.
    *
    * @throws IllegalStateException if the file is missing or malformed
    */
   ConfigNode loadYaml(String fileName);

   /** Writes the bundled default config.yml if none exists yet. */
   default void saveDefaultConfig() {
      saveResource("config.yml");
   }

   /** Re-reads config.yml from disk. */
   default ConfigNode loadConfig() {
      return loadYaml("config.yml");
   }

   void info(String message);

   void warn(String message);

   void error(String message, Throwable error);

   /** Runs the task off the main thread. */
   void runAsync(Runnable task);

   /** Runs the task off the main thread every {@code intervalSeconds}, starting after one interval. */
   void runAsyncTimer(Runnable task, long intervalSeconds);

   /** Cancels all timers and pending tasks owned by the plugin. */
   void cancelTasks();

   /** Sends an already colourised message to the console. */
   void sendConsole(String legacyMessage);

   Collection<ShieldPlayer> onlinePlayers();

   Optional<ShieldPlayer> player(UUID uuid);

   Optional<ShieldPlayer> player(String name);
}
