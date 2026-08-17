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
}
