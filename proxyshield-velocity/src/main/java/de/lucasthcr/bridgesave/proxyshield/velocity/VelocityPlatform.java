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

package de.lucasthcr.bridgesave.proxyshield.velocity;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.scheduler.ScheduledTask;
import de.lucasthcr.bridgesave.proxyshield.config.ConfigNode;
import de.lucasthcr.bridgesave.proxyshield.config.YamlConfigNode;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import de.lucasthcr.bridgesave.proxyshield.platform.ShieldPlayer;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.slf4j.Logger;

/** Velocity implementation of {@link Platform}. */
final class VelocityPlatform implements Platform {

   private final VelocityMain plugin;
   private final ProxyServer server;
   private final Logger logger;
   private final Path dataDirectory;

   VelocityPlatform(VelocityMain plugin, ProxyServer server, Logger logger, Path dataDirectory) {
      this.plugin = plugin;
      this.server = server;
      this.logger = logger;
      this.dataDirectory = dataDirectory;
   }

   static Component color(String legacyMessage) {
      return LegacyComponentSerializer.legacyAmpersand().deserialize(legacyMessage);
   }

   @Override
   public String name() {
      return "Velocity";
   }

   @Override
   public String version() {
      return server.getPluginManager().fromInstance(plugin)
            .flatMap(container -> container.getDescription().getVersion())
            .orElse(VelocityMain.VERSION);
   }

   @Override
   public Path dataFolder() {
      return dataDirectory;
   }

   @Override
   public void saveResource(String resourceName) {
      try {
         Files.createDirectories(dataDirectory);
         Path target = dataDirectory.resolve(resourceName);
         if (Files.exists(target)) {
            return;
         }
         try (InputStream bundled =
               getClass().getClassLoader().getResourceAsStream(resourceName)) {
            if (bundled == null) {
               warn("No bundled " + resourceName + " found in the plugin jar.");
               return;
            }
            Files.copy(bundled, target);
         }
      } catch (IOException failure) {
         error("Could not write " + resourceName, failure);
      }
   }

   @Override
   public ConfigNode loadYaml(String fileName) {
      try {
         return YamlConfigNode.load(dataDirectory.resolve(fileName));
      } catch (IOException | RuntimeException failure) {
         throw new IllegalStateException(fileName + " could not be read: " + failure.getMessage(),
               failure);
      }
   }

   @Override
   public void info(String message) {
      logger.info(message);
   }

   @Override
   public void warn(String message) {
      logger.warn(message);
   }

   @Override
   public void error(String message, Throwable error) {
      logger.error(message, error);
   }

   @Override
   public void runAsync(Runnable task) {
      server.getScheduler().buildTask(plugin, task).schedule();
   }

   @Override
   public void runAsyncTimer(Runnable task, long intervalSeconds) {
      server.getScheduler().buildTask(plugin, task)
            .delay(intervalSeconds, TimeUnit.SECONDS)
            .repeat(intervalSeconds, TimeUnit.SECONDS)
            .schedule();
   }

   @Override
   public void cancelTasks() {
      for (ScheduledTask task : server.getScheduler().tasksByPlugin(plugin)) {
         task.cancel();
      }
   }

   @Override
   public void sendConsole(String legacyMessage) {
      server.getConsoleCommandSource().sendMessage(color(legacyMessage));
   }

   @Override
   public void dispatchCommand(String command, long delaySeconds) {
      // Velocity runs commands on its own executor, so there is no thread to hop back to.
      Runnable dispatch = () -> server.getCommandManager()
            .executeAsync(server.getConsoleCommandSource(), command);
      if (delaySeconds <= 0L) {
         dispatch.run();
      } else {
         server.getScheduler().buildTask(plugin, dispatch)
               .delay(delaySeconds, TimeUnit.SECONDS)
               .schedule();
      }
   }

   @Override
   public Collection<ShieldPlayer> onlinePlayers() {
      List<ShieldPlayer> players = new ArrayList<>();
      for (Player player : server.getAllPlayers()) {
         players.add(new VelocityShieldPlayer(player));
      }
      return players;
   }

   @Override
   public Optional<ShieldPlayer> player(UUID uuid) {
      return server.getPlayer(uuid).map(VelocityShieldPlayer::new);
   }

   @Override
   public Optional<ShieldPlayer> player(String name) {
      return server.getPlayer(name).map(VelocityShieldPlayer::new);
   }
}
