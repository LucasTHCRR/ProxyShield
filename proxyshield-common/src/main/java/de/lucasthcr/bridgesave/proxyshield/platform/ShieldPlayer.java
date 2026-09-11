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

package de.lucasthcr.bridgesave.proxyshield.platform;

import java.util.UUID;

/** A connected player, reduced to what the detection core actually uses. */
public interface ShieldPlayer {

   UUID uuid();

   String name();

   /** Remote address as a plain literal, without port and without a leading slash. */
   String ip();

   boolean hasPermission(String permission);

   /** Sends an already colourised message. */
   void sendMessage(String legacyMessage);

   /** Disconnects the player with an already colourised reason. */
   void kick(String legacyMessage);
}
