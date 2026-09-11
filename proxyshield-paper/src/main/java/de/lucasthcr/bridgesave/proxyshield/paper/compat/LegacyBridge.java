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
 * for a decade, so it also works on Paper - it is simply not used there, because the modern
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
