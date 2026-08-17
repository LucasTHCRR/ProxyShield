package de.lucasthcr.bridgesave.proxyshield.sponge;

import de.lucasthcr.bridgesave.proxyshield.platform.ShieldPlayer;
import java.net.InetSocketAddress;
import java.util.UUID;
import org.spongepowered.api.entity.living.player.server.ServerPlayer;

record SpongeShieldPlayer(ServerPlayer handle) implements ShieldPlayer {

   @Override
   public UUID uuid() {
      return handle.uniqueId();
   }

   @Override
   public String name() {
      return handle.name();
   }

   @Override
   public String ip() {
      InetSocketAddress address = handle.connection().address();
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
      handle.sendMessage(SpongePlatform.color(legacyMessage));
   }

   @Override
   public void kick(String legacyMessage) {
      handle.kick(SpongePlatform.color(legacyMessage));
   }
}
