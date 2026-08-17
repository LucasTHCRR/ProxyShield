package de.lucasthcr.bridgesave.proxyshield.paper;

import de.lucasthcr.bridgesave.proxyshield.paper.compat.ServerBridge;
import de.lucasthcr.bridgesave.proxyshield.platform.ShieldPlayer;
import java.net.InetSocketAddress;
import java.util.UUID;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;

/**
 * A Bukkit player.
 * <p>
 * Messaging and disconnecting go through the {@link ServerBridge}, because Paper uses Adventure
 * components and a per-region scheduler where Spigot only has the string API and the main thread.
 */
record PaperShieldPlayer(Plugin plugin, ServerBridge bridge, Player handle) implements ShieldPlayer {

   @Override
   public UUID uuid() {
      return handle.getUniqueId();
   }

   @Override
   public String name() {
      return handle.getName();
   }

   @Override
   public String ip() {
      InetSocketAddress address = handle.getAddress();
      return address == null || address.getAddress() == null
            ? null
            : address.getAddress().getHostAddress();
   }

   @Override
   public boolean hasPermission(String permission) {
      return handle.hasPermission(permission);
   }

   @Override
   public void sendMessage(String legacyMessage) {
      bridge.send(handle, legacyMessage);
   }

   @Override
   public void kick(String legacyMessage) {
      if (!plugin.isEnabled()) {
         return;
      }
      bridge.kick(plugin, handle, legacyMessage);
   }
}
