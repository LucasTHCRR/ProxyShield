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

package de.lucasthcr.bridgesave.proxyshield.storage;

import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import java.util.Locale;

/**
 * Builds the store named in {@code storage.type}.
 * <p>
 * Falls back to the file store whenever the configured one cannot be reached, because an anti-VPN
 * that stops working when a database is down has traded one outage for a worse one.
 */
public final class StorageFactory {

   private StorageFactory() {
   }

   public static ShieldStorage create(Platform platform, ShieldConfig config) {
      String type = config.storageType().toLowerCase(Locale.ROOT).trim();

      return switch (type) {
         case "none", "memory" -> new NoStorage();
         case "redis" -> redis(platform, config);
         case "mysql", "mariadb", "postgresql", "postgres", "sqlite", "h2" ->
               sql(platform, config, type);
         default -> new FileStorage(platform);
      };
   }

   private static ShieldStorage redis(Platform platform, ShieldConfig config) {
      RedisStorage redis = new RedisStorage(platform, config.redisHost(), config.redisPort(),
            config.redisUsername(), config.redisPassword(), config.redisDatabase(),
            config.redisTimeoutMillis(), config.redisPrefix(), config.serverId());
      if (redis.available()) {
         return redis;
      }

      redis.close();
      platform.warn("Redis is unreachable, falling back to file storage. Verdicts will not be "
            + "shared with the other servers until it comes back and the plugin is reloaded.");
      return new FileStorage(platform);
   }

   private static ShieldStorage sql(Platform platform, ShieldConfig config, String type) {
      String url = config.sqlUrl().isBlank()
            ? SqlStorage.urlFor(type, config.sqlHost(), config.sqlPort(), config.sqlDatabase(),
                  platform.dataFolder(), config.sqlParameters())
            : config.sqlUrl();

      if (!SqlStorage.hasDriverFor(url) && config.sqlDriverPath().isBlank()) {
         platform.warn("No JDBC driver for " + url + " is available on this server. Put the "
               + "driver jar in the ProxyShield folder and set storage.sql.driver-path to its "
               + "file name, or use storage.type: file. Falling back to file storage.");
         return new FileStorage(platform);
      }

      SqlStorage sql = new SqlStorage(platform, displayNameFor(type), url, config.sqlUsername(),
            config.sqlPassword(), config.sqlPoolSize(), config.sqlDriverPath());
      if (sql.available()) {
         return sql;
      }

      sql.close();
      platform.warn("The database is unreachable, falling back to file storage.");
      return new FileStorage(platform);
   }

   private static String displayNameFor(String type) {
      return switch (type) {
         case "mysql" -> "MySQL";
         case "mariadb" -> "MariaDB";
         case "postgresql", "postgres" -> "PostgreSQL";
         case "sqlite" -> "SQLite";
         case "h2" -> "H2";
         default -> type;
      };
   }

   /** Keeps everything in memory for the lifetime of the server. */
   public static final class NoStorage implements ShieldStorage {

      @Override
      public String name() {
         return "memory";
      }

      @Override
      public boolean available() {
         return true;
      }

      @Override
      public boolean shared() {
         return false;
      }

      @Override
      public java.util.Map<String, CachedVerdict> preload() {
         return java.util.Map.of();
      }

      @Override
      public java.util.Optional<CachedVerdict> find(String key) {
         return java.util.Optional.empty();
      }

      @Override
      public void put(String key, CachedVerdict verdict) {
      }

      @Override
      public void invalidate(String key) {
      }

      @Override
      public void clearVerdicts() {
      }

      @Override
      public java.util.Map<java.util.UUID, TrustRecord> loadTrust() {
         return java.util.Map.of();
      }

      @Override
      public void saveTrust(java.util.Map<java.util.UUID, TrustRecord> records) {
      }

      @Override
      public void close() {
      }
   }
}
