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
