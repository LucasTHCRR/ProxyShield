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

package de.lucasthcr.bridgesave.proxyshield.check;

import java.util.UUID;

/**
 * Recognises players who joined from Bedrock Edition through Geyser/Floodgate.
 * <p>
 * Floodgate hands every Bedrock player a UUID built from their Xbox Live ID in the low 64 bits,
 * leaving the high 64 bits zero - so {@code 00000000-0000-0000-0009-01f588cbe8e0} is a Bedrock
 * player while a Java account never is. Checking that costs nothing and needs no Floodgate API on
 * the classpath, which matters because the same core has to run on five platforms.
 * <p>
 * This exists because of a failure mode that is easy to miss: when Geyser runs anywhere other than
 * the player's own machine, the address ProxyShield sees is Geyser's, and a Geyser instance on
 * rented hardware sits in exactly the datacenter ranges the feeds list. Without an exemption a
 * server would drop every single Bedrock player the moment hosting detection is switched on.
 */
public final class BedrockPlayers {

   private BedrockPlayers() {
   }

   /**
    * True when the UUID has Floodgate's shape.
    * <p>
    * A client cannot choose its own UUID here - Floodgate derives it server side from the
    * authenticated Xbox Live account - so this is not something a Java player can spoof to skip
    * the check.
    */
   public static boolean isBedrock(UUID uuid) {
      return uuid != null && uuid.getMostSignificantBits() == 0L;
   }
}
