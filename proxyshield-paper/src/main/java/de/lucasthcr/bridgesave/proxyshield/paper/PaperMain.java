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

package de.lucasthcr.bridgesave.proxyshield.paper;

import de.lucasthcr.bridgesave.proxyshield.ProxyShieldCore;
import de.lucasthcr.bridgesave.proxyshield.check.CheckEngine;
import de.lucasthcr.bridgesave.proxyshield.command.CommandHandler;
import de.lucasthcr.bridgesave.proxyshield.metrics.MetricsData;
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

   /**
    * Undoes the PlaceholderAPI registration, or {@code null} when there was none.
    * <p>
    * Held as a {@link Runnable} rather than as the expansion itself: naming that type in a field
    * or a call outside the guard below is enough to make the JVM resolve it, and resolving it
    * without PlaceholderAPI installed is exactly the crash this avoids.
    */
   private Runnable placeholderCleanup;

   @Override
   public void onEnable() {
      PaperPlatform platform = new PaperPlatform(this);
      bridge = platform.bridge();

      core = new ProxyShieldCore(platform);
      core.start();
      commands = new CommandHandler(core);

      startMetrics();
      placeholderCleanup = hookPlaceholders();

      getServer().getPluginManager().registerEvents(this, this);
      var command = getCommand("proxyshield");
      if (command != null) {
         command.setExecutor(this);
         command.setTabCompleter(this);
      }
   }

   @Override
   public void onDisable() {
      if (placeholderCleanup != null) {
         placeholderCleanup.run();
      }
      if (core != null) {
         core.shutdown();
      }
   }

   /**
    * Registers the placeholder expansion, but only where PlaceholderAPI actually is.
    * <p>
    * The check has to live here rather than inside the expansion class. Touching that class at all
    * makes the JVM load it, loading it resolves its superclass {@code PlaceholderExpansion}, and on
    * a server without PlaceholderAPI that throws {@link NoClassDefFoundError} before any code of
    * ours runs - which took the whole plugin down with it in 2.2.
    *
    * @return a callback that unregisters the expansion, or {@code null} if none was registered
    */
   private Runnable hookPlaceholders() {
      if (getServer().getPluginManager().getPlugin("PlaceholderAPI") == null) {
         return null;
      }
      try {
         return ShieldPlaceholders.register(this, core);
      } catch (Throwable incompatible) {
         // Also catches a PlaceholderAPI too old for this expansion API.
         getLogger().warning("Could not register the PlaceholderAPI expansion: " + incompatible);
         return null;
      }
   }

   /**
    * Starts bStats when the operator left it on.
    * <p>
    * Wrapped because the metrics library is optional at runtime: a jar stripped of it, or a
    * network that blocks the endpoint, must not stop the plugin from protecting the server.
    */
   private void startMetrics() {
      if (!core.config().metricsEnabled()) {
         return;
      }
      try {
         int id = core.config().metricsPluginId() > 0
               ? core.config().metricsPluginId()
               : MetricsData.BUKKIT_PLUGIN_ID;
         org.bstats.bukkit.Metrics metrics = new org.bstats.bukkit.Metrics(this, id);
         MetricsData.pies(core).forEach((chart, value) ->
               metrics.addCustomChart(new org.bstats.charts.SimplePie(chart,
                     () -> MetricsData.pies(core).get(chart))));
         metrics.addCustomChart(new org.bstats.charts.SingleLineChart("connections_blocked",
               () -> MetricsData.blockedSinceLastReport(core)));
         metrics.addCustomChart(new org.bstats.charts.SingleLineChart("lookups_performed",
               () -> MetricsData.lookupsSinceLastReport(core)));
      } catch (Throwable unavailable) {
         getLogger().info("bStats metrics are not available: " + unavailable.getMessage());
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
