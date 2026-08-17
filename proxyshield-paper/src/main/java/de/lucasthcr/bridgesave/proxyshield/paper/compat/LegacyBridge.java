package de.lucasthcr.bridgesave.proxyshield.paper.compat;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;

/**
 * Spigot and CraftBukkit.
 * <p>
 * Falls back to {@code BukkitScheduler} and the string based chat API. Everything here has existed
 * for a decade, so it also works on Paper — it is simply not used there, because the modern
 * schedulers behave better and are the only ones Folia has.
 */
final class LegacyBridge implements ServerBridge {

   /** 20 ticks per second, which is what the legacy scheduler counts in. */
   private static final long TICKS_PER_SECOND = 20L;

   @SuppressWarnings("deprecation")
   private static String color(String legacyMessage) {
      return ChatColor.translateAlternateColorCodes('&', legacyMessage);
   }

   @Override
   public String flavour() {
      return Bukkit.getName();
   }

   @Override
   public void runAsync(Plugin plugin, Runnable task) {
      Bukkit.getScheduler().runTaskAsynchronously(plugin, task);
   }

   @Override
   public void runAsyncTimer(Plugin plugin, Runnable task, long intervalSeconds) {
      long ticks = intervalSeconds * TICKS_PER_SECOND;
      Bukkit.getScheduler().runTaskTimerAsynchronously(plugin, task, ticks, ticks);
   }

   @Override
   public void cancelTasks(Plugin plugin) {
      Bukkit.getScheduler().cancelTasks(plugin);
   }

   @Override
   public void send(CommandSender target, String legacyMessage) {
      target.sendMessage(color(legacyMessage));
   }

   @Override
   @SuppressWarnings("deprecation")
   public void kick(Plugin plugin, Player player, String legacyMessage) {
      // Disconnecting is a main-thread operation on a non-regionised server.
      Bukkit.getScheduler().runTask(plugin, () -> player.kickPlayer(color(legacyMessage)));
   }
}
