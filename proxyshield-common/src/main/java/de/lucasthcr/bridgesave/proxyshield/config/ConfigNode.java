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

package de.lucasthcr.bridgesave.proxyshield.config;

import java.util.List;

/**
 * Minimal read-only view of a YAML config, addressed by dotted paths.
 * <p>
 * Each platform ships its own implementation on top of its native config API so the core never
 * has to care whether it is talking to Bukkit's {@code FileConfiguration}, BungeeCord's
 * {@code Configuration} or a plain SnakeYAML map.
 */
public interface ConfigNode {

   String getString(String path, String def);

   boolean getBoolean(String path, boolean def);

   int getInt(String path, int def);

   long getLong(String path, long def);

   List<String> getStringList(String path);

   /**
    * Reads a fractional value, e.g. a provider weight.
    * <p>
    * Defaulted rather than abstract so the platform adapters that predate it keep compiling; every
    * shipped implementation overrides it.
    */
   default double getDouble(String path, double def) {
      String raw = getString(path, null);
      if (raw == null) {
         return def;
      }
      try {
         return Double.parseDouble(raw.trim());
      } catch (NumberFormatException notANumber) {
         return def;
      }
   }

   /**
    * The immediate child keys of a section, in file order, or an empty list when the path is not a
    * section.
    * <p>
    * Needed for {@code api.providers}, where the operator names the services rather than listing
    * fixed keys, so the config can be a menu of everything supported instead of a schema baked
    * into the code.
    */
   default List<String> getKeys(String path) {
      return List.of();
   }
}
