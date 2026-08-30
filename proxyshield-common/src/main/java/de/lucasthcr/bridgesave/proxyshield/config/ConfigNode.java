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
