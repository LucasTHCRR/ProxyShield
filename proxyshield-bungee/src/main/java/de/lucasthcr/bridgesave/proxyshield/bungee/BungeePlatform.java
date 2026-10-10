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

package de.lucasthcr.bridgesave.proxyshield.bungee;

import de.lucasthcr.bridgesave.proxyshield.config.ConfigNode;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import de.lucasthcr.bridgesave.proxyshield.platform.ShieldPlayer;
import java.io.File;
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
import net.md_5.bungee.api.ChatColor;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.config.Configuration;
import net.md_5.bungee.config.ConfigurationProvider;
import net.md_5.bungee.config.YamlConfiguration;

/** BungeeCord implementation of {@link Platform}. */
final class BungeePlatform implements Platform {

   private final BungeeMain plugin;

   BungeePlatform(BungeeMain plugin) {
      this.plugin = plugin;
   }

   static String color(String legacyMessage) {
      return ChatColor.translateAlternateColorCodes('&', legacyMessage);
   }

   @Override
   public String name() {
      return "BungeeCord";
   }

   @Override
   public boolean proxy() {
      return true;
   }

   @Override
   public String version() {
      return plugin.getDescription().getVersion();
   }

   @Override
   public Path dataFolder() {
      return plugin.getDataFolder().toPath();
   }

   @Override
   public void saveResource(String resourceName) {
      try {
         Path folder = dataFolder();
         Files.createDirectories(folder);

         Path target = folder.resolve(resourceName);
         if (Files.exists(target)) {
            return;
         }
         try (InputStream bundled = plugin.getResourceAsStream(resourceName)) {
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
      File file = dataFolder().resolve(fileName).toFile();
      Configuration configuration;
      try {
         configuration = ConfigurationProvider.getProvider(YamlConfiguration.class).load(file);
      } catch (IOException failure) {
         throw new IllegalStateException(fileName + " could not be read: " + failure.getMessage(),
               failure);
      }

      return new ConfigNode() {
         @Override
         public String getString(String path, String def) {
            return configuration.getString(path, def);
         }

         @Override
         public boolean getBoolean(String path, boolean def) {
            return configuration.getBoolean(path, def);
         }

         @Override
         public int getInt(String path, int def) {
            return configuration.getInt(path, def);
         }

         @Override
         public long getLong(String path, long def) {
            return configuration.getLong(path, def);
         }

         @Override
         public List<String> getStringList(String path) {
            return configuration.getStringList(path);
         }

         @Override
         public double getDouble(String path, double def) {
            return configuration.getDouble(path, def);
         }

         @Override
         public List<String> getKeys(String path) {
            Configuration section = configuration.getSection(path);
            return section == null ? List.of() : new ArrayList<>(section.getKeys());
         }
      };
   }

   @Override
   public void info(String message) {
      plugin.getLogger().info(message);
   }

   @Override
   public void warn(String message) {
      plugin.getLogger().warning(message);
   }

   @Override
   public void error(String message, Throwable error) {
      plugin.getLogger().severe(message + ": " + error);
   }

   @Override
   public void runAsync(Runnable task) {
      ProxyServer.getInstance().getScheduler().runAsync(plugin, task);
   }

   @Override
   public void runAsyncTimer(Runnable task, long intervalSeconds) {
      ProxyServer.getInstance().getScheduler()
            .schedule(plugin, task, intervalSeconds, intervalSeconds, TimeUnit.SECONDS);
   }

   @Override
   public void cancelTasks() {
      ProxyServer.getInstance().getScheduler().cancel(plugin);
   }

   @Override
   public void sendConsole(String legacyMessage) {
      ProxyServer.getInstance().getConsole()
            .sendMessage(TextComponent.fromLegacyText(color(legacyMessage)));
   }

   @Override
   public void dispatchCommand(String command, long delaySeconds) {
      ProxyServer proxy = ProxyServer.getInstance();
      // BungeeCord has no main thread to get back onto, so an immediate dispatch runs right here.
      Runnable dispatch = () -> proxy.getPluginManager().dispatchCommand(proxy.getConsole(),
            command);
      if (delaySeconds <= 0L) {
         dispatch.run();
      } else {
         proxy.getScheduler().schedule(plugin, dispatch, delaySeconds, TimeUnit.SECONDS);
      }
   }

   @Override
   public Collection<ShieldPlayer> onlinePlayers() {
      List<ShieldPlayer> players = new ArrayList<>();
      for (ProxiedPlayer player : ProxyServer.getInstance().getPlayers()) {
         players.add(new BungeeShieldPlayer(player));
      }
      return players;
   }

   @Override
   public Optional<ShieldPlayer> player(UUID uuid) {
      ProxiedPlayer player = ProxyServer.getInstance().getPlayer(uuid);
      return player == null ? Optional.empty() : Optional.of(new BungeeShieldPlayer(player));
   }

   @Override
   public Optional<ShieldPlayer> player(String name) {
      ProxiedPlayer player = ProxyServer.getInstance().getPlayer(name);
      return player == null ? Optional.empty() : Optional.of(new BungeeShieldPlayer(player));
   }
}
