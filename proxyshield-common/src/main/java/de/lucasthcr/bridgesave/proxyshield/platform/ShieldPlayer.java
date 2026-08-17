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
