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

import com.google.inject.Inject;
import com.velocitypowered.api.command.CommandManager;
import com.velocitypowered.api.command.CommandMeta;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.ResultedEvent;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import de.lucasthcr.bridgesave.proxyshield.ProxyShieldCore;
import de.lucasthcr.bridgesave.proxyshield.command.CommandHandler;
import de.lucasthcr.bridgesave.proxyshield.metrics.MetricsData;
import org.bstats.velocity.Metrics;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.List;
import org.slf4j.Logger;

/**
 * Velocity entry point.
 * <p>
 * The check runs from an {@link EventTask#async} continuation on {@link LoginEvent}, so the
 * connection is denied before the player reaches a backend server. v1 used {@code PostLoginEvent}
 * and kicked afterwards, which meant a blocked player was briefly fully connected.
 */
@Plugin(
      id = "proxyshield",
      name = "ProxyShield",
      // Keep in sync with the version in pom.xml; annotation values must be compile-time constants.
      version = VelocityMain.VERSION,
      description = "Anti-VPN and anti-proxy protection with country filtering and webhook alerts.",
      authors = {"LucasTHCR"}
)
public final class VelocityMain {

   public static final String VERSION = "3.0.0";

   private final ProxyServer server;
   private final Logger logger;
   private final Path dataDirectory;
   private final Metrics.Factory metricsFactory;

   private ProxyShieldCore core;
   private CommandHandler commands;

   @Inject
   public VelocityMain(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory,
         Metrics.Factory metricsFactory) {
      this.server = server;
      this.logger = logger;
      this.dataDirectory = dataDirectory;
      this.metricsFactory = metricsFactory;
   }

   @Subscribe
   public void onInit(ProxyInitializeEvent event) {
      core = new ProxyShieldCore(new VelocityPlatform(this, server, logger, dataDirectory));
      core.start();
      commands = new CommandHandler(core);

      startMetrics();

      CommandManager manager = server.getCommandManager();
      CommandMeta meta = manager.metaBuilder("proxyshield")
            .aliases("ps", "antivpn")
            .plugin(this)
            .build();
      manager.register(meta, new ShieldCommand());
   }

   /**
    * Starts bStats when it is switched on and an id is configured.
    * <p>
    * bStats ids are per platform, so the Velocity project has its own; without one configured
    * there is nothing to report to.
    */
   private void startMetrics() {
      int id = core.config().metricsPluginId();
      if (!core.config().metricsEnabled() || id <= 0) {
         return;
      }
      try {
         Metrics metrics = metricsFactory.make(this, id);
         MetricsData.pies(core).forEach((chart, value) ->
               metrics.addCustomChart(new org.bstats.charts.SimplePie(chart,
                     () -> MetricsData.pies(core).get(chart))));
         metrics.addCustomChart(new org.bstats.charts.SingleLineChart("connections_blocked",
               () -> MetricsData.blockedSinceLastReport(core)));
         metrics.addCustomChart(new org.bstats.charts.SingleLineChart("lookups_performed",
               () -> MetricsData.lookupsSinceLastReport(core)));
      } catch (Throwable unavailable) {
         logger.info("bStats metrics are not available: {}", unavailable.getMessage());
      }
   }

   @Subscribe
   public void onShutdown(ProxyShutdownEvent event) {
      if (core != null) {
         core.shutdown();
      }
   }

   @Subscribe
   public EventTask onLogin(LoginEvent event) {
      Player player = event.getPlayer();
      InetSocketAddress address = player.getRemoteAddress();
      String ip = address == null || address.getAddress() == null
            ? null
            : address.getAddress().getHostAddress();

      return EventTask.async(() -> {
         ProxyShieldCore.ConnectionDecision decision = core.handleLogin(
               player.getUsername(), player.getUniqueId(), ip, player::hasPermission);
         if (decision.deny()) {
            event.setResult(ResultedEvent.ComponentResult.denied(
                  VelocityPlatform.color(decision.kickMessage())));
         }
      });
   }

   /**
    * Keeps a restricted player on the allowed backends. On the first connect there is no server
    * to fall back to, so the player is redirected to the first allowed one, or disconnected if
    * none exists.
    */
   @Subscribe
   public void onServerPreConnect(ServerPreConnectEvent event) {
      Player player = event.getPlayer();
      RegisteredServer target = event.getResult().getServer().orElse(null);
      if (target == null || core.mayJoinServer(player.getUniqueId(),
            target.getServerInfo().getName())) {
         return;
      }
      String name = target.getServerInfo().getName();
      if (event.getPreviousServer() == null) {
         for (RegisteredServer candidate : server.getAllServers()) {
            if (core.mayJoinServer(player.getUniqueId(), candidate.getServerInfo().getName())) {
               event.setResult(ServerPreConnectEvent.ServerResult.allowed(candidate));
               return;
            }
         }
         event.setResult(ServerPreConnectEvent.ServerResult.denied());
         player.disconnect(VelocityPlatform.color(core.restrictedMessage(name)));
         return;
      }
      event.setResult(ServerPreConnectEvent.ServerResult.denied());
      player.sendMessage(VelocityPlatform.color(core.restrictedMessage(name)));
   }

   @Subscribe
   public void onDisconnect(DisconnectEvent event) {
      core.playerLeft(event.getPlayer().getUniqueId());
   }

   private final class ShieldCommand implements SimpleCommand {

      @Override
      public void execute(Invocation invocation) {
         commands.execute(wrap(invocation), invocation.arguments());
      }

      @Override
      public List<String> suggest(Invocation invocation) {
         return commands.tabComplete(wrap(invocation), invocation.arguments());
      }

      @Override
      public boolean hasPermission(Invocation invocation) {
         return invocation.source().hasPermission(CommandHandler.PERMISSION);
      }

      private CommandHandler.Sender wrap(Invocation invocation) {
         return new CommandHandler.Sender() {
            @Override
            public void send(String legacyMessage) {
               invocation.source().sendMessage(VelocityPlatform.color(legacyMessage));
            }

            @Override
            public boolean hasPermission(String permission) {
               return invocation.source().hasPermission(permission);
            }

            @Override
            public String name() {
               return invocation.source() instanceof Player player
                     ? player.getUsername()
                     : "console";
            }
         };
      }
   }
}
