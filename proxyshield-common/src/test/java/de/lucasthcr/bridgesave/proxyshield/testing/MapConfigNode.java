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
