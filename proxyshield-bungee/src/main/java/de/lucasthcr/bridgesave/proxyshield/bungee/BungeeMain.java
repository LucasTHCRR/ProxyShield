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

import de.lucasthcr.bridgesave.proxyshield.ProxyShieldCore;
import de.lucasthcr.bridgesave.proxyshield.check.CheckEngine;
import de.lucasthcr.bridgesave.proxyshield.command.CommandHandler;
import de.lucasthcr.bridgesave.proxyshield.metrics.MetricsData;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.config.ServerInfo;
import net.md_5.bungee.api.connection.PendingConnection;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.event.LoginEvent;
import net.md_5.bungee.api.event.PlayerDisconnectEvent;
import net.md_5.bungee.api.event.ServerConnectEvent;
import net.md_5.bungee.api.plugin.Command;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.api.plugin.TabExecutor;
import net.md_5.bungee.event.EventHandler;
import net.md_5.bungee.event.EventPriority;

/**
 * BungeeCord entry point.
 * <p>
 * {@link LoginEvent} is fired on a netty thread, so the check is moved onto the proxy's async pool
 * and the event is held open with {@code registerIntent}/{@code completeIntent}. v1 ran the HTTP
 * lookup inline, which stalled the connection thread for the duration of every request.
 */
public final class BungeeMain extends Plugin implements Listener {

   private ProxyShieldCore core;
   private CommandHandler commands;

   @Override
   public void onEnable() {
      core = new ProxyShieldCore(new BungeePlatform(this));
      core.start();
      commands = new CommandHandler(core);

      startMetrics();
      getProxy().getPluginManager().registerListener(this, this);
      getProxy().getPluginManager().registerCommand(this, new ShieldCommand());
   }

   @Override
   public void onDisable() {
      if (core != null) {
         core.shutdown();
      }
   }

   /**
    * Starts bStats when it is switched on and an id is configured.
    * <p>
    * bStats ids are per platform, so the BungeeCord project has its own; without one configured
    * there is nothing to report to, and starting anyway would only produce errors in the log.
    */
   private void startMetrics() {
      int id = core.config().metricsPluginId();
      if (!core.config().metricsEnabled() || id <= 0) {
         return;
      }
      try {
         org.bstats.bungeecord.Metrics metrics = new org.bstats.bungeecord.Metrics(this, id);
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

   @EventHandler(priority = EventPriority.HIGH)
   public void onLogin(LoginEvent event) {
      if (event.isCancelled()) {
         return;
      }

      PendingConnection connection = event.getConnection();
      String ip = addressOf(connection);
      String name = connection.getName();
      java.util.UUID uuid = connection.getUniqueId();

      event.registerIntent(this);
      getProxy().getScheduler().runAsync(this, () -> {
         try {
            ProxyShieldCore.ConnectionDecision decision =
                  core.handleLogin(name, uuid, ip, probeFor(name));
            if (decision.deny()) {
               event.setCancelReason(TextComponent.fromLegacyText(
                     BungeePlatform.color(decision.kickMessage())));
               event.setCancelled(true);
            }
         } catch (RuntimeException unexpected) {
            getLogger().severe("ProxyShield check failed for " + name + ": " + unexpected);
         } finally {
            // Must always run, otherwise the connection hangs until it times out.
            event.completeIntent(this);
         }
      });
   }

   /**
    * Keeps a restricted player on the allowed backends. On the first connect there is no server
    * to fall back to, so the player is redirected to the first allowed one, or disconnected if
    * none exists.
    */
   @EventHandler(priority = EventPriority.HIGH)
   public void onServerConnect(ServerConnectEvent event) {
      ProxiedPlayer player = event.getPlayer();
      ServerInfo target = event.getTarget();
      if (event.isCancelled() || target == null
            || core.mayJoinServer(player.getUniqueId(), target.getName())) {
         return;
      }
      if (player.getServer() == null) {
         for (ServerInfo candidate : getProxy().getServers().values()) {
            if (core.mayJoinServer(player.getUniqueId(), candidate.getName())) {
               event.setTarget(candidate);
               return;
            }
         }
         player.disconnect(TextComponent.fromLegacyText(
               BungeePlatform.color(core.restrictedMessage(target.getName()))));
         event.setCancelled(true);
         return;
      }
      event.setCancelled(true);
      player.sendMessage(TextComponent.fromLegacyText(
            BungeePlatform.color(core.restrictedMessage(target.getName()))));
   }

   @EventHandler
   public void onDisconnect(PlayerDisconnectEvent event) {
      core.playerLeft(event.getPlayer().getUniqueId());
   }

   private String addressOf(PendingConnection connection) {
      SocketAddress address = connection.getSocketAddress();
      if (address instanceof InetSocketAddress inet && inet.getAddress() != null) {
         return inet.getAddress().getHostAddress();
      }
      return null;
   }

   /**
    * BungeeCord has no permission data for a connection that has not finished logging in, so this
    * only resolves for a player who is somehow already on the proxy. Use {@code whitelist.players}
    * for reliable exemptions here.
    */
   private CheckEngine.PermissionProbe probeFor(String name) {
      return permission -> {
         ProxiedPlayer online = ProxyServer.getInstance().getPlayer(name);
         return online != null && online.hasPermission(permission);
      };
   }

   private final class ShieldCommand extends Command implements TabExecutor {

      ShieldCommand() {
         super("proxyshield", null, "ps", "antivpn");
      }

      @Override
      public void execute(CommandSender sender, String[] args) {
         commands.execute(wrap(sender), args);
      }

      @Override
      public Iterable<String> onTabComplete(CommandSender sender, String[] args) {
         return commands.tabComplete(wrap(sender), args);
      }

      private CommandHandler.Sender wrap(CommandSender sender) {
         return new CommandHandler.Sender() {
            @Override
            public void send(String legacyMessage) {
               sender.sendMessage(TextComponent.fromLegacyText(
                     BungeePlatform.color(legacyMessage)));
            }

            @Override
            public boolean hasPermission(String permission) {
               return sender.hasPermission(permission);
            }

            @Override
            public String name() {
               return sender.getName();
            }
         };
      }
   }
}
