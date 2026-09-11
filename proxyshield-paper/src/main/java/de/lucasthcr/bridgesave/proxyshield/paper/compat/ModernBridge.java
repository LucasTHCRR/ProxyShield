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

import java.util.concurrent.TimeUnit;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.bukkit.Bukkit;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;

/**
 * Paper and Folia.
 * <p>
 * Scheduling goes through {@code AsyncScheduler} and the per-entity scheduler, which is what lets
 * one jar work on a regionised Folia server where a player may only be touched from the thread that
 * owns their region. This class references Adventure and the Paper schedulers, so it is only ever
 * loaded when {@link ServerBridge#detect()} has confirmed they exist.
 */
final class ModernBridge implements ServerBridge {

   /** The global region scheduler counts in ticks, twenty to the second. */
   private static final long TICKS_PER_SECOND = 20L;

   private static Component color(String legacyMessage) {
      return LegacyComponentSerializer.legacyAmpersand().deserialize(legacyMessage);
   }

   @Override
   public String flavour() {
      return isFolia() ? "Folia" : Bukkit.getName();
   }

   private static boolean isFolia() {
      try {
         Class.forName("io.papermc.paper.threadedregions.RegionizedServer");
         return true;
      } catch (ClassNotFoundException notFolia) {
         return false;
      }
   }

   @Override
   public void runAsync(Plugin plugin, Runnable task) {
      Bukkit.getAsyncScheduler().runNow(plugin, scheduled -> task.run());
   }

   @Override
   public void runAsyncTimer(Plugin plugin, Runnable task, long intervalSeconds) {
      Bukkit.getAsyncScheduler().runAtFixedRate(plugin, scheduled -> task.run(),
            intervalSeconds, intervalSeconds, TimeUnit.SECONDS);
   }

   @Override
   public void cancelTasks(Plugin plugin) {
      Bukkit.getAsyncScheduler().cancelTasks(plugin);
   }

   @Override
   public void send(CommandSender target, String legacyMessage) {
      target.sendMessage(color(legacyMessage));
   }

   @Override
   public void kick(Plugin plugin, Player player, String legacyMessage) {
      // On Folia the player belongs to a region thread, so the kick has to be scheduled there.
      player.getScheduler().run(plugin, scheduled -> player.kick(color(legacyMessage)), null);
   }

   @Override
   public void dispatchCommand(Plugin plugin, String command, long delaySeconds) {
      // Console commands are not tied to a region, so they belong on the global scheduler. That is
      // the one Folia requires here, and Paper accepts it too, which keeps this to a single path.
      if (delaySeconds <= 0L) {
         Bukkit.getGlobalRegionScheduler().run(plugin, scheduled -> run(command));
      } else {
         Bukkit.getGlobalRegionScheduler().runDelayed(plugin, scheduled -> run(command),
               delaySeconds * TICKS_PER_SECOND);
      }
   }

   private static void run(String command) {
      Bukkit.dispatchCommand(Bukkit.getConsoleSender(), command);
   }
}
