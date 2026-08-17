package de.lucasthcr.bridgesave.proxyshield.velocity;

import com.velocitypowered.api.proxy.Player;
import de.lucasthcr.bridgesave.proxyshield.platform.ShieldPlayer;
import java.net.InetSocketAddress;
import java.util.UUID;

record VelocityShieldPlayer(Player handle) implements ShieldPlayer {

   @Override
   public UUID uuid() {
      return handle.getUniqueId();
   }

   @Override
   public String name() {
      return handle.getUsername();
   }

   @Override
   public String ip() {
      InetSocketAddress address = handle.getRemoteAddress();
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
      handle.sendMessage(VelocityPlatform.color(legacyMessage));
   }

   @Override
   public void kick(String legacyMessage) {
      handle.disconnect(VelocityPlatform.color(legacyMessage));
   }
}
