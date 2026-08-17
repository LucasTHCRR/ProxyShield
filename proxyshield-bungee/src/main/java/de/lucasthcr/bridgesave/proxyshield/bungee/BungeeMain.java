package de.lucasthcr.bridgesave.proxyshield.bungee;

import de.lucasthcr.bridgesave.proxyshield.ProxyShieldCore;
import de.lucasthcr.bridgesave.proxyshield.check.CheckEngine;
import de.lucasthcr.bridgesave.proxyshield.command.CommandHandler;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.PendingConnection;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.event.LoginEvent;
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

      getProxy().getPluginManager().registerListener(this, this);
      getProxy().getPluginManager().registerCommand(this, new ShieldCommand());
   }

   @Override
   public void onDisable() {
      if (core != null) {
         core.shutdown();
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
         };
      }
   }
}
