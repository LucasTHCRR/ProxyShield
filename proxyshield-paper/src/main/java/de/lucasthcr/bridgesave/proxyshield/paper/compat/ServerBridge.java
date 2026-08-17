package de.lucasthcr.bridgesave.proxyshield.paper.compat;

import org.bukkit.Bukkit;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;

/**
 * The handful of server calls that differ between Paper and Spigot.
 * <p>
 * Paper and Folia offer {@code AsyncScheduler}, a per-entity scheduler and Adventure components.
 * Spigot has none of the three, so every one of those calls has to be routed through an
 * implementation picked at startup. Keeping them behind this interface means the Paper-only types
 * are never loaded on a Spigot server, which is what a plain {@code if} could not guarantee.
 */
public interface ServerBridge {

   /** Picks the implementation this server can actually run. */
   static ServerBridge detect() {
      return hasModernSchedulers() ? new ModernBridge() : new LegacyBridge();
   }

   private static boolean hasModernSchedulers() {
      try {
         // Paper 1.20.1+ and every Folia build. Absent on Spigot and CraftBukkit.
         Bukkit.class.getMethod("getAsyncScheduler");
         return true;
      } catch (NoSuchMethodException spigot) {
         return false;
      }
   }

   /** Short label for {@code /proxyshield info}, e.g. "Paper" or "Spigot". */
   String flavour();

   void runAsync(Plugin plugin, Runnable task);

   void runAsyncTimer(Plugin plugin, Runnable task, long intervalSeconds);

   void cancelTasks(Plugin plugin);

   /** Sends an {@code &}-coded message. */
   void send(CommandSender target, String legacyMessage);

   /** Disconnects the player on whichever thread owns them. */
   void kick(Plugin plugin, Player player, String legacyMessage);
}
