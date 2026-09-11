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

package de.lucasthcr.bridgesave.proxyshield.sponge;

import de.lucasthcr.bridgesave.proxyshield.config.ConfigNode;
import de.lucasthcr.bridgesave.proxyshield.config.YamlConfigNode;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import de.lucasthcr.bridgesave.proxyshield.platform.ShieldPlayer;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.apache.logging.log4j.Logger;
import org.spongepowered.api.Game;
import org.spongepowered.api.command.exception.CommandException;
import org.spongepowered.api.entity.living.player.server.ServerPlayer;
import org.spongepowered.api.scheduler.ScheduledTask;
import org.spongepowered.api.scheduler.Task;
import org.spongepowered.plugin.PluginContainer;

/** Sponge implementation of {@link Platform}. */
final class SpongePlatform implements Platform {

   private final PluginContainer container;
   private final Game game;
   private final Logger logger;
   private final Path configDirectory;

   SpongePlatform(PluginContainer container, Game game, Logger logger, Path configDirectory) {
      this.container = container;
      this.game = game;
      this.logger = logger;
      this.configDirectory = configDirectory;
   }

   static Component color(String legacyMessage) {
      return LegacyComponentSerializer.legacyAmpersand().deserialize(legacyMessage);
   }

   @Override
   public String name() {
      return "Sponge";
   }

   @Override
   public String version() {
      return container.metadata().version().toString();
   }

   @Override
   public Path dataFolder() {
      return configDirectory;
   }

   @Override
   public void saveResource(String resourceName) {
      try {
         Files.createDirectories(configDirectory);
         Path target = configDirectory.resolve(resourceName);
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
         return YamlConfigNode.load(configDirectory.resolve(fileName));
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
      game.asyncScheduler().submit(Task.builder()
            .execute(task)
            .plugin(container)
            .build());
   }

   @Override
   public void runAsyncTimer(Runnable task, long intervalSeconds) {
      Duration interval = Duration.ofSeconds(intervalSeconds);
      game.asyncScheduler().submit(Task.builder()
            .execute(task)
            .delay(interval)
            .interval(interval)
            .plugin(container)
            .build());
   }

   @Override
   public void cancelTasks() {
      for (ScheduledTask task : game.asyncScheduler().tasks(container)) {
         task.cancel();
      }
   }

   @Override
   public void sendConsole(String legacyMessage) {
      game.systemSubject().sendMessage(color(legacyMessage));
   }

   @Override
   public void dispatchCommand(String command, long delaySeconds) {
      // Sponge wants commands on the server thread, so this goes to the sync scheduler rather than
      // the async one the rest of the plugin uses.
      Task.Builder task = Task.builder().execute(() -> process(command)).plugin(container);
      if (delaySeconds > 0L) {
         task.delay(Duration.ofSeconds(delaySeconds));
      }
      game.server().scheduler().submit(task.build());
   }

   private void process(String command) {
      try {
         game.server().commandManager().process(game.systemSubject(), command);
      } catch (CommandException failure) {
         warn("Flag command '/" + command + "' failed: " + failure.getMessage());
      }
   }

   @Override
   public Collection<ShieldPlayer> onlinePlayers() {
      if (!game.isServerAvailable()) {
         return List.of();
      }
      List<ShieldPlayer> players = new ArrayList<>();
      for (ServerPlayer player : game.server().onlinePlayers()) {
         players.add(new SpongeShieldPlayer(player));
      }
      return players;
   }

   @Override
   public Optional<ShieldPlayer> player(UUID uuid) {
      if (!game.isServerAvailable()) {
         return Optional.empty();
      }
      return game.server().player(uuid).map(SpongeShieldPlayer::new);
   }

   @Override
   public Optional<ShieldPlayer> player(String name) {
      if (!game.isServerAvailable()) {
         return Optional.empty();
      }
      return game.server().player(name).map(SpongeShieldPlayer::new);
   }
}
