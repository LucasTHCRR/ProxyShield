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

package de.lucasthcr.bridgesave.proxyshield.testing;

import de.lucasthcr.bridgesave.proxyshield.config.ConfigNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A {@link ConfigNode} backed by a flat map of dotted keys, so a test can state only the settings
 * it cares about and let everything else fall back to the production default.
 */
public final class MapConfigNode implements ConfigNode {

   private final Map<String, Object> values;

   public MapConfigNode(Map<String, Object> values) {
      this.values = values;
   }

   @Override
   public String getString(String path, String def) {
      Object value = values.get(path);
      return value == null ? def : String.valueOf(value);
   }

   @Override
   public boolean getBoolean(String path, boolean def) {
      Object value = values.get(path);
      if (value instanceof Boolean flag) {
         return flag;
      }
      return value == null ? def : Boolean.parseBoolean(String.valueOf(value));
   }

   @Override
   public int getInt(String path, int def) {
      Object value = values.get(path);
      return value instanceof Number number ? number.intValue() : def;
   }

   @Override
   public long getLong(String path, long def) {
      Object value = values.get(path);
      return value instanceof Number number ? number.longValue() : def;
   }

   @Override
   public double getDouble(String path, double def) {
      Object value = values.get(path);
      return value instanceof Number number ? number.doubleValue() : def;
   }

   /** Derives the child keys from the dotted keys already present in the map. */
   @Override
   public List<String> getKeys(String path) {
      String prefix = path.endsWith(".") ? path : path + ".";
      List<String> out = new ArrayList<>();
      for (String key : values.keySet()) {
         if (!key.startsWith(prefix)) {
            continue;
         }
         String remainder = key.substring(prefix.length());
         int dot = remainder.indexOf('.');
         String child = dot < 0 ? remainder : remainder.substring(0, dot);
         if (!child.isEmpty() && !out.contains(child)) {
            out.add(child);
         }
      }
      return out;
   }

   @Override
   public List<String> getStringList(String path) {
      Object value = values.get(path);
      if (!(value instanceof List<?> list)) {
         return List.of();
      }
      List<String> out = new ArrayList<>(list.size());
      for (Object element : list) {
         out.add(String.valueOf(element));
      }
      return out;
   }
}
