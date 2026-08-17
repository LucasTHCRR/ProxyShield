package de.lucasthcr.bridgesave.proxyshield.paper;

import de.lucasthcr.bridgesave.proxyshield.ProxyShieldCore;
import de.lucasthcr.bridgesave.proxyshield.check.CheckEngine;
import de.lucasthcr.bridgesave.proxyshield.command.CommandHandler;
import de.lucasthcr.bridgesave.proxyshield.paper.compat.ServerBridge;
import java.util.List;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.OfflinePlayer;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.plugin.java.JavaPlugin;
import org.jetbrains.annotations.NotNull;

/**
 * Bukkit entry point, shared by the Paper, Folia and Spigot builds.
 * <p>
 * The check runs inside {@link AsyncPlayerPreLoginEvent}, which every one of those servers already
 * fires off the main thread, so the blocking lookup is safe here and the player is rejected before
 * they ever enter the world.
 */
public final class PaperMain extends JavaPlugin implements Listener, CommandExecutor, TabCompleter {

   private ProxyShieldCore core;
   private CommandHandler commands;
   private ServerBridge bridge;

   @Override
   public void onEnable() {
      PaperPlatform platform = new PaperPlatform(this);
      bridge = platform.bridge();

      core = new ProxyShieldCore(platform);
      core.start();
      commands = new CommandHandler(core);

      getServer().getPluginManager().registerEvents(this, this);
      var command = getCommand("proxyshield");
      if (command != null) {
         command.setExecutor(this);
         command.setTabCompleter(this);
      }
   }

   @Override
   public void onDisable() {
      if (core != null) {
         core.shutdown();
      }
   }

   @EventHandler(priority = EventPriority.HIGH, ignoreCancelled = true)
   public void onPreLogin(AsyncPlayerPreLoginEvent event) {
      String ip = event.getAddress() == null ? null : event.getAddress().getHostAddress();
      ProxyShieldCore.ConnectionDecision decision =
            core.handleLogin(event.getName(), event.getUniqueId(), ip, probeFor(event));

      if (decision.deny()) {
         // The String overload is the one Spigot has; Paper's Component variant would not link.
         event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
               ChatColor.translateAlternateColorCodes('&', decision.kickMessage()));
      }
   }

   /**
    * Best effort permission test during pre-login.
    * <p>
    * No {@code Player} exists this early, so only the op flag and an already online session can be
    * consulted. For anything finer grained use {@code whitelist.players} in config.yml.
    */
   private CheckEngine.PermissionProbe probeFor(AsyncPlayerPreLoginEvent event) {
      return permission -> {
         OfflinePlayer offline = Bukkit.getOfflinePlayer(event.getUniqueId());
         if (offline.isOp()) {
            return true;
         }
         Player online = offline.getPlayer();
         return online != null && online.hasPermission(permission);
      };
   }

   @Override
   public boolean onCommand(@NotNull CommandSender sender, @NotNull Command command,
         @NotNull String label, @NotNull String[] args) {
      commands.execute(wrap(sender), args);
      return true;
   }

   @Override
   public List<String> onTabComplete(@NotNull CommandSender sender, @NotNull Command command,
         @NotNull String label, @NotNull String[] args) {
      return commands.tabComplete(wrap(sender), args);
   }

   private CommandHandler.Sender wrap(CommandSender sender) {
      return new CommandHandler.Sender() {
         @Override
         public void send(String legacyMessage) {
            bridge.send(sender, legacyMessage);
         }

         @Override
         public boolean hasPermission(String permission) {
            return sender.hasPermission(permission);
         }
      };
   }
}
