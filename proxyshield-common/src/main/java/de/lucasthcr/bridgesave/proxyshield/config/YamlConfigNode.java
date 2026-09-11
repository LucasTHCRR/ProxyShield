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


import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * Dotted-path view over a SnakeYAML document.
 * <p>
 * Used by the platforms that ship no config API of their own, currently Velocity and Sponge. Bukkit
 * and BungeeCord wrap their native readers instead. All of them end up reading the exact same
 * config.yml, unlike v1 where Velocity used a flat {@code config.properties} with a different set of
 * options entirely.
 */
public final class YamlConfigNode implements ConfigNode {

   private final Map<String, Object> root;

   private YamlConfigNode(Map<String, Object> root) {
      this.root = root;
   }

   @SuppressWarnings("unchecked")
   public static YamlConfigNode load(Path file) throws IOException {
      LoaderOptions options = new LoaderOptions();
      options.setAllowDuplicateKeys(false);
      // A config file has no business pulling in arbitrary Java types.
      Yaml yaml = new Yaml(new SafeConstructor(options));

      try (InputStream in = Files.newInputStream(file)) {
         Object loaded = yaml.load(new String(in.readAllBytes(), StandardCharsets.UTF_8));
         if (loaded instanceof Map<?, ?> map) {
            return new YamlConfigNode((Map<String, Object>) map);
         }
         return new YamlConfigNode(Map.of());
      }
   }

   private Object resolve(String path) {
      Object current = root;
      int start = 0;
      while (start <= path.length()) {
         int dot = path.indexOf('.', start);
         String key = dot < 0 ? path.substring(start) : path.substring(start, dot);
         if (!(current instanceof Map<?, ?> map)) {
            return null;
         }
         current = map.get(key);
         if (current == null || dot < 0) {
            return dot < 0 ? current : null;
         }
         start = dot + 1;
      }
      return current;
   }

   @Override
   public String getString(String path, String def) {
      Object value = resolve(path);
      return value == null ? def : String.valueOf(value);
   }

   @Override
   public boolean getBoolean(String path, boolean def) {
      Object value = resolve(path);
      if (value instanceof Boolean flag) {
         return flag;
      }
      return value == null ? def : Boolean.parseBoolean(String.valueOf(value));
   }

   @Override
   public int getInt(String path, int def) {
      Object value = resolve(path);
      if (value instanceof Number number) {
         return number.intValue();
      }
      try {
         return value == null ? def : Integer.parseInt(String.valueOf(value).trim());
      } catch (NumberFormatException notANumber) {
         return def;
      }
   }

   @Override
   public long getLong(String path, long def) {
      Object value = resolve(path);
      if (value instanceof Number number) {
         return number.longValue();
      }
      try {
         return value == null ? def : Long.parseLong(String.valueOf(value).trim());
      } catch (NumberFormatException notANumber) {
         return def;
      }
   }

   @Override
   public double getDouble(String path, double def) {
      Object value = resolve(path);
      if (value instanceof Number number) {
         return number.doubleValue();
      }
      try {
         return value == null ? def : Double.parseDouble(String.valueOf(value).trim());
      } catch (NumberFormatException notANumber) {
         return def;
      }
   }

   @Override
   public List<String> getKeys(String path) {
      Object value = resolve(path);
      if (!(value instanceof Map<?, ?> section)) {
         return List.of();
      }
      List<String> out = new ArrayList<>(section.size());
      for (Object key : section.keySet()) {
         out.add(String.valueOf(key));
      }
      return out;
   }

   @Override
   public List<String> getStringList(String path) {
      Object value = resolve(path);
      if (!(value instanceof List<?> list)) {
         return List.of();
      }
      List<String> out = new ArrayList<>(list.size());
      for (Object element : list) {
         if (element != null) {
            out.add(String.valueOf(element));
         }
      }
      return out;
   }
}
