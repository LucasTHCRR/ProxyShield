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

import com.google.inject.Inject;
import de.lucasthcr.bridgesave.proxyshield.ProxyShieldCore;
import de.lucasthcr.bridgesave.proxyshield.check.CheckEngine;
import de.lucasthcr.bridgesave.proxyshield.command.CommandHandler;
import de.lucasthcr.bridgesave.proxyshield.metrics.MetricsData;
import org.bstats.sponge.Metrics;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import net.kyori.adventure.text.Component;
import org.apache.logging.log4j.Logger;
import org.spongepowered.api.Game;
import org.spongepowered.api.Server;
import org.spongepowered.api.command.Command;
import org.spongepowered.api.command.CommandCause;
import org.spongepowered.api.command.CommandCompletion;
import org.spongepowered.api.command.CommandResult;
import org.spongepowered.api.command.parameter.ArgumentReader;
import org.spongepowered.api.config.ConfigDir;
import org.spongepowered.api.event.Listener;
import org.spongepowered.api.event.Order;
import org.spongepowered.api.event.lifecycle.ConstructPluginEvent;
import org.spongepowered.api.event.lifecycle.RegisterCommandEvent;
import org.spongepowered.api.event.lifecycle.StartedEngineEvent;
import org.spongepowered.api.event.lifecycle.StoppingEngineEvent;
import org.spongepowered.api.event.network.ServerSideConnectionEvent;
import org.spongepowered.plugin.PluginContainer;
import org.spongepowered.plugin.builtin.jvm.Plugin;

/**
 * Sponge entry point.
 * <p>
 * The check hangs off {@link ServerSideConnectionEvent.Auth}, which fires on the connection's own
 * thread during the login handshake. Blocking there delays only that one connection, never the
 * server tick, which is the same trade-off the Paper build makes with its pre-login event.
 */
@Plugin("proxyshield")
public final class SpongeMain {

   private final PluginContainer container;
   private final Game game;
   private final Logger logger;
   private final Path configDirectory;

   private ProxyShieldCore core;
   private CommandHandler commands;

   @Inject
   private Metrics.Factory metricsFactory;

   @Inject
   public SpongeMain(PluginContainer container, Game game, Logger logger,
         @ConfigDir(sharedRoot = false) Path configDirectory) {
      this.container = container;
      this.game = game;
      this.logger = logger;
      this.configDirectory = configDirectory;
   }

   /**
    * Commands are registered before the engine starts, so the core has to exist by then. Only the
    * construction happens here; {@link #onStarted} does the actual start-up work.
    */
   @Listener
   public void onConstruct(ConstructPluginEvent event) {
      core = new ProxyShieldCore(new SpongePlatform(container, game, logger, configDirectory));
      commands = new CommandHandler(core);
   }

   @Listener
   public void onRegisterCommands(RegisterCommandEvent<Command.Raw> event) {
      event.register(container, new ShieldCommand(), "proxyshield", "ps", "antivpn");
   }

   @Listener
   public void onStarted(StartedEngineEvent<Server> event) {
      core.start();
      startMetrics();
   }

   /**
    * Starts bStats when it is switched on and an id is configured.
    * <p>
    * bStats ids are per platform, so the Sponge project has its own; without one configured there
    * is nothing to report to.
    */
   private void startMetrics() {
      int id = core.config().metricsPluginId();
      if (!core.config().metricsEnabled() || id <= 0 || metricsFactory == null) {
         return;
      }
      try {
         Metrics metrics = metricsFactory.make(id);
         MetricsData.pies(core).forEach((chart, value) ->
               metrics.addCustomChart(new org.bstats.charts.SimplePie(chart,
                     () -> MetricsData.pies(core).get(chart))));
         metrics.addCustomChart(new org.bstats.charts.SingleLineChart("connections_blocked",
               () -> MetricsData.blockedSinceLastReport(core)));
         metrics.addCustomChart(new org.bstats.charts.SingleLineChart("lookups_performed",
               () -> MetricsData.lookupsSinceLastReport(core)));
      } catch (Throwable unavailable) {
         logger.info("bStats metrics are not available: " + unavailable.getMessage());
      }
   }

   @Listener
   public void onStopping(StoppingEngineEvent<Server> event) {
      if (core != null) {
         core.shutdown();
      }
   }

   @Listener(order = Order.EARLY)
   public void onAuth(ServerSideConnectionEvent.Auth event) {
      if (core == null || core.config() == null) {
         return;
      }

      InetSocketAddress address = event.connection().address();
      String ip = address == null || address.getAddress() == null
            ? null
            : address.getAddress().getHostAddress();
      String name = event.profile().name().orElse("unknown");

      // No Subject exists during the auth handshake, so permission based bypass cannot be
      // evaluated here. Use whitelist.players or whitelist.ips on Sponge.
      ProxyShieldCore.ConnectionDecision decision =
            core.handleLogin(name, event.profile().uniqueId(), ip,
                  CheckEngine.PermissionProbe.NONE);

      if (decision.deny()) {
         event.setCancelled(true);
         event.setMessage(SpongePlatform.color(decision.kickMessage()));
      }
   }

   private final class ShieldCommand implements Command.Raw {

      @Override
      public CommandResult process(CommandCause cause, ArgumentReader.Mutable arguments) {
         commands.execute(wrap(cause), split(arguments.remaining()));
         return CommandResult.success();
      }

      @Override
      public List<CommandCompletion> complete(CommandCause cause, ArgumentReader.Mutable arguments) {
         List<CommandCompletion> completions = new ArrayList<>();
         for (String suggestion : commands.tabComplete(wrap(cause),
               splitForCompletion(arguments.remaining()))) {
            completions.add(CommandCompletion.of(suggestion));
         }
         return completions;
      }

      @Override
      public boolean canExecute(CommandCause cause) {
         return cause.hasPermission(CommandHandler.PERMISSION);
      }

      @Override
      public Optional<Component> shortDescription(CommandCause cause) {
         return Optional.of(Component.text("Manage ProxyShield"));
      }

      @Override
      public Optional<Component> extendedDescription(CommandCause cause) {
         return Optional.empty();
      }

      @Override
      public Component usage(CommandCause cause) {
         return Component.text("/proxyshield help");
      }

      private CommandHandler.Sender wrap(CommandCause cause) {
         return new CommandHandler.Sender() {
            @Override
            public void send(String legacyMessage) {
               cause.audience().sendMessage(SpongePlatform.color(legacyMessage));
            }

            @Override
            public boolean hasPermission(String permission) {
               return cause.hasPermission(permission);
            }
         };
      }
   }

   private static String[] split(String raw) {
      String trimmed = raw.trim();
      return trimmed.isEmpty() ? new String[0] : trimmed.split("\\s+");
   }

   /**
    * Tab completion needs to know the user has started a fresh argument, which a plain split cannot
    * express: "whitelist " and "whitelist" produce the same array otherwise.
    */
   private static String[] splitForCompletion(String raw) {
      String[] parts = split(raw);
      if (raw.isEmpty() || Character.isWhitespace(raw.charAt(raw.length() - 1))) {
         String[] extended = Arrays.copyOf(parts, parts.length + 1);
         extended[parts.length] = "";
         return extended;
      }
      return parts;
   }
}
