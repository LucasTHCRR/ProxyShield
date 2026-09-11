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

package de.lucasthcr.bridgesave.proxyshield.testing;

import de.lucasthcr.bridgesave.proxyshield.config.ConfigNode;
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

/**
 * A {@link Platform} for tests.
 * <p>
 * Tasks run inline rather than on a scheduler so assertions do not have to wait, and every log line
 * is kept so a test can assert on what was reported.
 */
public final class RecordingPlatform implements Platform {

   private final Path dataFolder;
   private final List<String> infos = new ArrayList<>();
   private final List<String> warnings = new ArrayList<>();
   private final List<String> errors = new ArrayList<>();
   private final List<String> console = new ArrayList<>();
   private final List<DispatchedCommand> commands = new ArrayList<>();
   private final List<ShieldPlayer> players = new ArrayList<>();

   public RecordingPlatform(Path dataFolder) {
      this.dataFolder = dataFolder;
   }

   public void addPlayer(ShieldPlayer player) {
      players.add(player);
   }

   public List<String> infos() {
      return infos;
   }

   public List<String> warnings() {
      return warnings;
   }

   public List<String> errors() {
      return errors;
   }

   public List<String> consoleMessages() {
      return console;
   }

   /** Every command dispatched so far, in order. */
   public List<DispatchedCommand> dispatchedCommands() {
      return commands;
   }

   @Override
   public String name() {
      return "Test";
   }

   @Override
   public String version() {
      return "2.0-test";
   }

   @Override
   public Path dataFolder() {
      return dataFolder;
   }

   @Override
   public void saveResource(String resourceName) {
      Path target = dataFolder.resolve(resourceName);
      if (Files.exists(target)) {
         return;
      }
      try (InputStream bundled =
            getClass().getClassLoader().getResourceAsStream(resourceName)) {
         if (bundled == null) {
            warn("no bundled " + resourceName);
            return;
         }
         Files.createDirectories(dataFolder);
         Files.copy(bundled, target);
      } catch (IOException failure) {
         throw new IllegalStateException(failure);
      }
   }

   @Override
   public ConfigNode loadYaml(String fileName) {
      Path file = dataFolder.resolve(fileName);
      if (!Files.isRegularFile(file)) {
         throw new IllegalStateException(fileName + " does not exist");
      }
      try {
         return de.lucasthcr.bridgesave.proxyshield.config.YamlConfigNode.load(file);
      } catch (IOException failure) {
         throw new IllegalStateException(failure);
      }
   }

   @Override
   public void info(String message) {
      infos.add(message);
   }

   @Override
   public void warn(String message) {
      warnings.add(message);
   }

   @Override
   public void error(String message, Throwable error) {
      errors.add(message + ": " + error);
   }

   @Override
   public void runAsync(Runnable task) {
      task.run();
   }

   @Override
   public void runAsyncTimer(Runnable task, long intervalSeconds) {
      // Timers are not exercised by the tests; running once would skew the assertions.
   }

   @Override
   public void cancelTasks() {
      // nothing to cancel, tasks run inline
   }

   @Override
   public void sendConsole(String legacyMessage) {
      console.add(legacyMessage);
   }

   @Override
   public void dispatchCommand(String command, long delaySeconds) {
      commands.add(new DispatchedCommand(command, delaySeconds));
   }

   /** One command the core asked the platform to run, with the delay it asked for. */
   public record DispatchedCommand(String command, long delaySeconds) {
   }

   @Override
   public Collection<ShieldPlayer> onlinePlayers() {
      return List.copyOf(players);
   }

   @Override
   public Optional<ShieldPlayer> player(UUID uuid) {
      return players.stream().filter(p -> p.uuid().equals(uuid)).findFirst();
   }

   @Override
   public Optional<ShieldPlayer> player(String name) {
      return players.stream().filter(p -> p.name().equalsIgnoreCase(name)).findFirst();
   }
}
