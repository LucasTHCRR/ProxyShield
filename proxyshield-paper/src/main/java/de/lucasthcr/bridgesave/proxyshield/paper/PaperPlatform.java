package de.lucasthcr.bridgesave.proxyshield.paper;

import de.lucasthcr.bridgesave.proxyshield.config.ConfigNode;
import de.lucasthcr.bridgesave.proxyshield.paper.compat.ServerBridge;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import de.lucasthcr.bridgesave.proxyshield.platform.ShieldPlayer;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.bukkit.Bukkit;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;

/**
 * Bukkit implementation of {@link Platform}, covering Paper, Folia, Purpur and Spigot.
 * <p>
 * The three calls that differ between those servers - async scheduling, disconnecting a player and
 * sending a message - go through a {@link ServerBridge} chosen at startup.
 */
final class PaperPlatform implements Platform {

   private final PaperMain plugin;
   private final ServerBridge bridge;

   PaperPlatform(PaperMain plugin) {
      this.plugin = plugin;
      this.bridge = ServerBridge.detect();
   }

   ServerBridge bridge() {
      return bridge;
   }

   @Override
   public String name() {
      return bridge.flavour();
   }

   @Override
   @SuppressWarnings("deprecation")
   public String version() {
      // getDescription() is deprecated on Paper but is the only variant Spigot has.
      return plugin.getDescription().getVersion();
   }

   @Override
   public Path dataFolder() {
      return plugin.getDataFolder().toPath();
   }

   @Override
   public void saveResource(String resourceName) {
      if (!dataFolder().resolve(resourceName).toFile().exists()) {
         plugin.saveResource(resourceName, false);
      }
   }

   @Override
   public ConfigNode loadYaml(String fileName) {
      File file = dataFolder().resolve(fileName).toFile();
      if (!file.isFile()) {
         throw new IllegalStateException(fileName + " does not exist");
      }
      return wrap(YamlConfiguration.loadConfiguration(file));
   }

   @Override
   public ConfigNode loadConfig() {
      plugin.reloadConfig();
      return wrap(plugin.getConfig());
   }

   private static ConfigNode wrap(FileConfiguration configuration) {
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
            ConfigurationSection section = configuration.getConfigurationSection(path);
            return section == null ? List.of() : new ArrayList<>(section.getKeys(false));
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
      if (!plugin.isEnabled()) {
         return;
      }
      bridge.runAsync(plugin, task);
   }

   @Override
   public void runAsyncTimer(Runnable task, long intervalSeconds) {
      if (!plugin.isEnabled()) {
         return;
      }
      bridge.runAsyncTimer(plugin, task, intervalSeconds);
   }

   @Override
   public void cancelTasks() {
      bridge.cancelTasks(plugin);
   }

   @Override
   public void sendConsole(String legacyMessage) {
      bridge.send(Bukkit.getConsoleSender(), legacyMessage);
   }

   @Override
   public Collection<ShieldPlayer> onlinePlayers() {
      List<ShieldPlayer> players = new ArrayList<>();
      for (Player player : Bukkit.getOnlinePlayers()) {
         players.add(new PaperShieldPlayer(plugin, bridge, player));
      }
      return players;
   }

   @Override
   public Optional<ShieldPlayer> player(UUID uuid) {
      Player player = Bukkit.getPlayer(uuid);
      return player == null ? Optional.empty() : Optional.of(new PaperShieldPlayer(plugin, bridge, player));
   }

   @Override
   public Optional<ShieldPlayer> player(String name) {
      Player player = Bukkit.getPlayerExact(name);
      return player == null ? Optional.empty() : Optional.of(new PaperShieldPlayer(plugin, bridge, player));
   }
}
