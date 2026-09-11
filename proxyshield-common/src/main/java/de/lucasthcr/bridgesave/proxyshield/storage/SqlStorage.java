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

import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.ServiceLoader;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Verdicts and trust in a SQL database, shared by every server pointed at it.
 * <p>
 * Speaks plain JDBC and ships no driver, because bundling one into five platform jars would relocate
 * a database driver into every server that installs the plugin, and collide with the copy another
 * plugin already loaded. The driver that is already on the server is used where there is one, and
 * {@code storage.sql.driver-path} loads a jar the operator dropped in the plugin folder otherwise.
 * <p>
 * The schema is deliberately in the portable subset of SQL: no dialect-specific upsert, no boolean
 * type, no unsigned integers. The same two statements create the tables on MySQL, MariaDB,
 * PostgreSQL, SQLite and H2, which is what lets one implementation cover all of them honestly
 * rather than covering MySQL and hoping.
 */
public final class SqlStorage implements ShieldStorage {

   private static final String VERDICTS = "proxyshield_verdicts";
   private static final String TRUST = "proxyshield_trust";

   /** Drivers to try before giving up, in the order a server is likely to have them. */
   private static final List<String> KNOWN_DRIVERS = List.of(
         "com.mysql.cj.jdbc.Driver",
         "com.mysql.jdbc.Driver",
         "org.mariadb.jdbc.Driver",
         "org.postgresql.Driver",
         "org.sqlite.JDBC",
         "org.h2.Driver");

   private final Platform platform;
   private final String url;
   private final String user;
   private final String password;
   private final String displayName;
   private final BlockingQueue<Connection> pool;
   private final int poolSize;
   private final AtomicBoolean healthy = new AtomicBoolean();
   private final AtomicBoolean reportedFailure = new AtomicBoolean();

   public SqlStorage(Platform platform, String displayName, String url, String user,
         String password, int poolSize, String driverPath) {
      this.platform = platform;
      this.displayName = displayName;
      this.url = url;
      this.user = user;
      this.password = password;
      this.poolSize = Math.max(1, poolSize);
      this.pool = new ArrayBlockingQueue<>(this.poolSize);

      loadDriver(driverPath);
      if (open()) {
         createTables();
      }
   }

   /**
    * Makes sure a driver for this URL exists.
    * <p>
    * {@code DriverManager} only sees drivers registered by the classloader that asks, which on a
    * server platform is not the one that loaded the plugin, so a driver sitting in a jar has to be
    * registered explicitly.
    */
   private void loadDriver(String driverPath) {
      for (String className : KNOWN_DRIVERS) {
         try {
            Class.forName(className);
         } catch (ClassNotFoundException | LinkageError notPresent) {
            // Expected: a server has at most one or two of these.
         }
      }

      if (driverPath == null || driverPath.isBlank()) {
         return;
      }

      Path jar = platform.dataFolder().resolve(driverPath.trim());
      if (!Files.isRegularFile(jar)) {
         platform.warn("storage.sql.driver-path points at " + jar + ", which does not exist.");
         return;
      }

      try {
         URL[] urls = {jar.toUri().toURL()};
         URLClassLoader loader = new URLClassLoader(urls, SqlStorage.class.getClassLoader());
         for (Driver driver : ServiceLoader.load(Driver.class, loader)) {
            // Wrapped, because DriverManager refuses drivers from a foreign classloader.
            DriverManager.registerDriver(new DriverShim(driver));
            platform.info("Loaded JDBC driver " + driver.getClass().getName() + " from "
                  + jar.getFileName() + ".");
         }
      } catch (MalformedURLException | SQLException | RuntimeException failure) {
         platform.warn("Could not load the JDBC driver from " + jar.getFileName() + ": "
               + failure.getMessage());
      }
   }

   private boolean open() {
      try {
         for (int i = 0; i < poolSize; i++) {
            pool.add(newConnection());
         }
         healthy.set(true);
         platform.info("Connected to " + displayName + " for shared verdict and trust storage.");
         return true;
      } catch (SQLException failure) {
         reportFailure("connect", failure);
         return false;
      }
   }

   private Connection newConnection() throws SQLException {
      Properties properties = new Properties();
      if (user != null && !user.isBlank()) {
         properties.setProperty("user", user);
      }
      if (password != null && !password.isBlank()) {
         properties.setProperty("password", password);
      }
      return DriverManager.getConnection(url, properties);
   }

   private void createTables() {
      String verdicts = "CREATE TABLE IF NOT EXISTS " + VERDICTS + " ("
            + "ip VARCHAR(64) NOT NULL, "
            + "expires BIGINT NOT NULL, "
            + "proxy SMALLINT NOT NULL, "
            + "hosting SMALLINT NOT NULL, "
            + "tor SMALLINT NOT NULL, "
            + "country VARCHAR(8), "
            + "country_name VARCHAR(80), "
            + "isp VARCHAR(160), "
            + "asn VARCHAR(16), "
            + "conn_type VARCHAR(40), "
            + "confidence INT NOT NULL, "
            + "sources VARCHAR(255), "
            + "PRIMARY KEY (ip))";
      String trust = "CREATE TABLE IF NOT EXISTS " + TRUST + " ("
            + "uuid VARCHAR(36) NOT NULL, "
            + "first_seen BIGINT NOT NULL, "
            + "last_seen BIGINT NOT NULL, "
            + "logins INT NOT NULL, "
            + "PRIMARY KEY (uuid))";

      withConnection(connection -> {
         try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(verdicts);
            statement.executeUpdate(trust);
         }
         return null;
      }, "create the tables");
   }

   @Override
   public String name() {
      return displayName;
   }

   @Override
   public boolean available() {
      return healthy.get();
   }

   @Override
   public boolean shared() {
      return true;
   }

   /** Nothing is preloaded: the whole point of a shared table is not to copy it into every proxy. */
   @Override
   public Map<String, CachedVerdict> preload() {
      return Map.of();
   }

   @Override
   public Optional<CachedVerdict> find(String key) {
      CachedVerdict verdict = withConnection(connection -> {
         String sql = "SELECT expires, proxy, hosting, tor, country, country_name, isp, asn, "
               + "conn_type, confidence, sources FROM " + VERDICTS + " WHERE ip = ?";
         try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, key);
            try (ResultSet rows = statement.executeQuery()) {
               return rows.next() ? read(rows) : null;
            }
         }
      }, "read a verdict");

      return verdict == null || verdict.isExpired() ? Optional.empty() : Optional.of(verdict);
   }

   private CachedVerdict read(ResultSet rows) throws SQLException {
      String sources = rows.getString("sources");
      LookupResult result = LookupResult.of(
            rows.getInt("proxy") != 0,
            rows.getInt("hosting") != 0,
            rows.getInt("tor") != 0,
            rows.getString("country"),
            rows.getString("country_name"),
            rows.getString("isp"),
            rows.getString("asn"),
            rows.getString("conn_type"),
            rows.getInt("confidence") / 100.0,
            sources == null || sources.isBlank() ? List.of() : List.of(sources.split(",")));
      return new CachedVerdict(result, rows.getLong("expires"));
   }

   @Override
   public void put(String key, CachedVerdict verdict) {
      withConnection(connection -> {
         // Delete-then-insert rather than a dialect-specific upsert: the same two statements work
         // on every database this can be pointed at.
         try (PreparedStatement delete =
               connection.prepareStatement("DELETE FROM " + VERDICTS + " WHERE ip = ?")) {
            delete.setString(1, key);
            delete.executeUpdate();
         }

         String sql = "INSERT INTO " + VERDICTS + " (ip, expires, proxy, hosting, tor, country, "
               + "country_name, isp, asn, conn_type, confidence, sources) "
               + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
         try (PreparedStatement insert = connection.prepareStatement(sql)) {
            LookupResult result = verdict.result();
            insert.setString(1, key);
            insert.setLong(2, verdict.expiresAt());
            insert.setInt(3, result.proxy() ? 1 : 0);
            insert.setInt(4, result.hosting() ? 1 : 0);
            insert.setInt(5, result.tor() ? 1 : 0);
            insert.setString(6, trim(result.countryCode(), 8));
            insert.setString(7, trim(result.countryName(), 80));
            insert.setString(8, trim(result.isp(), 160));
            insert.setString(9, trim(result.asn(), 16));
            insert.setString(10, trim(result.connectionType(), 40));
            insert.setInt(11, (int) Math.round(result.confidence() * 100.0));
            insert.setString(12, trim(String.join(",", result.sources()), 255));
            insert.executeUpdate();
         } catch (SQLException raced) {
            // Another server inserted the same address between the delete and the insert. Its row
            // says the same thing, so losing the race is not a problem.
            return null;
         }
         return null;
      }, "store a verdict");
   }

   private static String trim(String value, int max) {
      if (value == null) {
         return null;
      }
      return value.length() <= max ? value : value.substring(0, max);
   }

   @Override
   public void invalidate(String key) {
      withConnection(connection -> {
         try (PreparedStatement statement =
               connection.prepareStatement("DELETE FROM " + VERDICTS + " WHERE ip = ?")) {
            statement.setString(1, key);
            statement.executeUpdate();
         }
         return null;
      }, "invalidate a verdict");
   }

   @Override
   public void clearVerdicts() {
      withConnection(connection -> {
         try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("DELETE FROM " + VERDICTS);
         }
         return null;
      }, "clear the verdict table");
   }

   @Override
   public int purgeExpired() {
      Integer removed = withConnection(connection -> {
         try (PreparedStatement statement =
               connection.prepareStatement("DELETE FROM " + VERDICTS + " WHERE expires < ?")) {
            statement.setLong(1, System.currentTimeMillis());
            return statement.executeUpdate();
         }
      }, "purge expired verdicts");
      return removed == null ? 0 : removed;
   }

   @Override
   public Map<UUID, TrustRecord> loadTrust() {
      Map<UUID, TrustRecord> records = withConnection(connection -> {
         Map<UUID, TrustRecord> found = new LinkedHashMap<>();
         String sql = "SELECT uuid, first_seen, last_seen, logins FROM " + TRUST;
         try (Statement statement = connection.createStatement();
               ResultSet rows = statement.executeQuery(sql)) {
            while (rows.next()) {
               try {
                  found.put(UUID.fromString(rows.getString("uuid")),
                        new TrustRecord(rows.getLong("first_seen"), rows.getLong("last_seen"),
                              rows.getInt("logins")));
               } catch (IllegalArgumentException notAUuid) {
                  // Skip the row rather than refuse to load the table.
               }
            }
         }
         return found;
      }, "read the trust table");
      return records == null ? Map.of() : records;
   }

   @Override
   public void saveTrust(Map<UUID, TrustRecord> records) {
      if (records.isEmpty()) {
         return;
      }

      withConnection(connection -> {
         boolean autoCommit = connection.getAutoCommit();
         connection.setAutoCommit(false);
         try (PreparedStatement delete =
                     connection.prepareStatement("DELETE FROM " + TRUST + " WHERE uuid = ?");
               PreparedStatement insert = connection.prepareStatement("INSERT INTO " + TRUST
                     + " (uuid, first_seen, last_seen, logins) VALUES (?, ?, ?, ?)")) {
            for (Map.Entry<UUID, TrustRecord> entry : records.entrySet()) {
               delete.setString(1, entry.getKey().toString());
               delete.addBatch();

               insert.setString(1, entry.getKey().toString());
               insert.setLong(2, entry.getValue().firstSeen());
               insert.setLong(3, entry.getValue().lastSeen());
               insert.setInt(4, entry.getValue().cleanLogins());
               insert.addBatch();
            }
            delete.executeBatch();
            insert.executeBatch();
            connection.commit();
         } catch (SQLException failure) {
            connection.rollback();
            throw failure;
         } finally {
            connection.setAutoCommit(autoCommit);
         }
         return null;
      }, "write the trust table");
   }

   /** Borrows a connection, replacing it if it died while idle. */
   private <T> T withConnection(SqlTask<T> task, String what) {
      Connection connection = null;
      try {
         connection = pool.poll(2, TimeUnit.SECONDS);
         if (connection == null) {
            // Every connection is busy; skipping is better than holding up a login.
            return null;
         }
         if (!connection.isValid(2)) {
            closeQuietly(connection);
            connection = newConnection();
         }

         T value = task.run(connection);
         healthy.set(true);
         reportedFailure.set(false);
         return value;
      } catch (SQLException | RuntimeException failure) {
         reportFailure(what, failure);
         closeQuietly(connection);
         connection = null;
         return null;
      } catch (InterruptedException interrupted) {
         Thread.currentThread().interrupt();
         return null;
      } finally {
         if (connection != null) {
            pool.offer(connection);
         } else {
            // Keep the pool at size, so a recovered database is used again without a restart.
            try {
               pool.offer(newConnection());
            } catch (SQLException stillDown) {
               healthy.set(false);
            }
         }
      }
   }

   /** Reports the first failure of a run, then stays quiet until the store recovers. */
   private void reportFailure(String what, Exception failure) {
      healthy.set(false);
      if (reportedFailure.compareAndSet(false, true)) {
         platform.warn("Could not " + what + " on " + displayName + ": " + failure.getMessage()
               + ". ProxyShield keeps working from its in-memory cache; logins are not blocked "
               + "by this.");
      }
   }

   private void closeQuietly(Connection connection) {
      if (connection == null) {
         return;
      }
      try {
         connection.close();
      } catch (SQLException ignored) {
         // Closing a broken connection is allowed to fail.
      }
   }

   @Override
   public void close() {
      List<Connection> drained = new ArrayList<>();
      pool.drainTo(drained);
      for (Connection connection : drained) {
         closeQuietly(connection);
      }
      healthy.set(false);
   }

   @FunctionalInterface
   private interface SqlTask<T> {
      T run(Connection connection) throws SQLException;
   }

   /** Lets DriverManager accept a driver loaded by our own classloader. */
   private record DriverShim(Driver delegate) implements Driver {

      @Override
      public Connection connect(String url, Properties info) throws SQLException {
         return delegate.connect(url, info);
      }

      @Override
      public boolean acceptsURL(String url) throws SQLException {
         return delegate.acceptsURL(url);
      }

      @Override
      public java.sql.DriverPropertyInfo[] getPropertyInfo(String url, Properties info)
            throws SQLException {
         return delegate.getPropertyInfo(url, info);
      }

      @Override
      public int getMajorVersion() {
         return delegate.getMajorVersion();
      }

      @Override
      public int getMinorVersion() {
         return delegate.getMinorVersion();
      }

      @Override
      public boolean jdbcCompliant() {
         return delegate.jdbcCompliant();
      }

      @Override
      public java.util.logging.Logger getParentLogger() {
         try {
            return delegate.getParentLogger();
         } catch (Exception unsupported) {
            return java.util.logging.Logger.getLogger("ProxyShield-JDBC");
         }
      }
   }

   /** Builds a JDBC URL for the common engines from the host/port/database settings. */
   public static String urlFor(String type, String host, int port, String database, Path dataFolder,
         String extra) {
      String suffix = extra == null || extra.isBlank() ? "" : extra.trim();
      return switch (type.toLowerCase(java.util.Locale.ROOT)) {
         case "mysql" -> "jdbc:mysql://" + host + ":" + (port > 0 ? port : 3306) + "/" + database
               + (suffix.isEmpty() ? "?useSSL=false&allowPublicKeyRetrieval=true" : suffix);
         case "mariadb" -> "jdbc:mariadb://" + host + ":" + (port > 0 ? port : 3306) + "/"
               + database + suffix;
         case "postgresql", "postgres" -> "jdbc:postgresql://" + host + ":"
               + (port > 0 ? port : 5432) + "/" + database + suffix;
         case "sqlite" -> "jdbc:sqlite:"
               + dataFolder.resolve(database.isBlank() ? "proxyshield.db" : database)
                     .toAbsolutePath();
         case "h2" -> "jdbc:h2:"
               + dataFolder.resolve(database.isBlank() ? "proxyshield" : database).toAbsolutePath();
         default -> database;
      };
   }

   /** Whether a driver capable of this URL is registered. Used to fail fast with a clear message. */
   public static boolean hasDriverFor(String url) {
      try {
         DriverManager.getDriver(url);
         return true;
      } catch (SQLException none) {
         return false;
      }
   }
}
