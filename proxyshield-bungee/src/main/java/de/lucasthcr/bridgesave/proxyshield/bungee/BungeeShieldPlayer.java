package de.lucasthcr.bridgesave.proxyshield.bungee;

import de.lucasthcr.bridgesave.proxyshield.platform.ShieldPlayer;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.UUID;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.ProxiedPlayer;

record BungeeShieldPlayer(ProxiedPlayer handle) implements ShieldPlayer {

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
      SocketAddress address = handle.getSocketAddress();
      if (address instanceof InetSocketAddress inet && inet.getAddress() != null) {
         return inet.getAddress().getHostAddress();
      }
      return null;
   }

   @Override
   public boolean hasPermission(String permission) {
      return handle.hasPermission(permission);
   }

   @Override
   public void sendMessage(String legacyMessage) {
      handle.sendMessage(TextComponent.fromLegacyText(BungeePlatform.color(legacyMessage)));
   }

   @Override
   public void kick(String legacyMessage) {
      handle.disconnect(TextComponent.fromLegacyText(BungeePlatform.color(legacyMessage)));
   }
}
