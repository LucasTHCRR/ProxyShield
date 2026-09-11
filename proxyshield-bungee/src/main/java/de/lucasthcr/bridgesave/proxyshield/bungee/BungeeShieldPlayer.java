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
