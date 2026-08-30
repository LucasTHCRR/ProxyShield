package de.lucasthcr.bridgesave.proxyshield.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The persistence layer: the file store, a real SQL database and the Redis protocol. */
class StorageTest {

   @TempDir
   Path tempDir;

   private static ShieldStorage.CachedVerdict verdict(boolean proxy, long ttlMillis) {
      LookupResult result = LookupResult.of(proxy, false, false, "NL", "Netherlands",
            "Some VPN Ltd", "AS9009", "hosting", 2.5, List.of("ip-api", "blackbox"));
      return new ShieldStorage.CachedVerdict(result, System.currentTimeMillis() + ttlMillis);
   }

   private static void assertRoundTripped(ShieldStorage.CachedVerdict stored) {
      LookupResult result = stored.result();
      assertTrue(result.proxy());
      assertEquals("NL", result.countryCode());
      assertEquals("Some VPN Ltd", result.isp());
      assertEquals("AS9009", result.asn());
      assertEquals("hosting", result.connectionType());
      assertEquals(2.5, result.confidence(), 0.001);
      assertEquals(List.of("ip-api", "blackbox"), result.sources());
   }

   @Nested
   @DisplayName("File store")
   class Files {

      @Test
      void verdictsSurviveAReopen() {
         FileStorage first = new FileStorage(new RecordingPlatform(tempDir));
         first.put("203.0.113.7", verdict(true, 600_000L));
         first.flush();

         FileStorage second = new FileStorage(new RecordingPlatform(tempDir));
         Map<String, ShieldStorage.CachedVerdict> loaded = second.preload();

         assertEquals(1, loaded.size());
         assertRoundTripped(loaded.get("203.0.113.7"));
      }

      @Test
      void anExpiredEntryIsNotRestored() {
         FileStorage first = new FileStorage(new RecordingPlatform(tempDir));
         first.put("203.0.113.8", verdict(true, -1_000L));
         first.flush();

         assertTrue(new FileStorage(new RecordingPlatform(tempDir)).preload().isEmpty(),
               "a verdict that expired while the server was down must not come back");
      }

      @Test
      void trustSurvivesAReopen() {
         UUID uuid = UUID.randomUUID();
         FileStorage first = new FileStorage(new RecordingPlatform(tempDir));
         first.saveTrust(Map.of(uuid, new ShieldStorage.TrustRecord(1000L, 2000L, 7)));

         Map<UUID, ShieldStorage.TrustRecord> loaded =
               new FileStorage(new RecordingPlatform(tempDir)).loadTrust();

         assertEquals(7, loaded.get(uuid).cleanLogins());
         assertEquals(1000L, loaded.get(uuid).firstSeen());
      }

      @Test
      void theFileStoreIsNotShared() {
         assertFalse(new FileStorage(new RecordingPlatform(tempDir)).shared(),
               "a local file cannot be read by another proxy");
      }
   }

   @Nested
   @DisplayName("SQL store")
   class Sql {

      private SqlStorage storage;

      private SqlStorage open() {
         // An in-memory H2 stands in for MySQL: same portable schema, same statements.
         String url = "jdbc:h2:mem:proxyshield-" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1";
         storage = new SqlStorage(new RecordingPlatform(tempDir), "H2", url, "sa", "", 2, "");
         return storage;
      }

      @AfterEach
      void close() {
         if (storage != null) {
            storage.close();
         }
      }

      @Test
      void aVerdictRoundTrips() {
         SqlStorage sql = open();
         assertTrue(sql.available(), "the tables should have been created");

         sql.put("203.0.113.7", verdict(true, 600_000L));
         Optional<ShieldStorage.CachedVerdict> found = sql.find("203.0.113.7");

         assertTrue(found.isPresent());
         assertRoundTripped(found.get());
      }

      @Test
      void writingTheSameAddressTwiceReplacesIt() {
         SqlStorage sql = open();
         sql.put("203.0.113.7", verdict(true, 600_000L));
         sql.put("203.0.113.7", verdict(false, 600_000L));

         assertFalse(sql.find("203.0.113.7").orElseThrow().result().proxy(),
               "the newer verdict wins, and the primary key must not blow up");
      }

      @Test
      void anExpiredRowIsNotServedAndIsPurged() {
         SqlStorage sql = open();
         sql.put("203.0.113.9", verdict(true, -1_000L));

         assertTrue(sql.find("203.0.113.9").isEmpty(), "an expired row is not an answer");
         assertEquals(1, sql.purgeExpired());
      }

      @Test
      void invalidationRemovesTheRow() {
         SqlStorage sql = open();
         sql.put("203.0.113.7", verdict(true, 600_000L));
         sql.invalidate("203.0.113.7");

         assertTrue(sql.find("203.0.113.7").isEmpty());
      }

      @Test
      void trustRoundTrips() {
         SqlStorage sql = open();
         UUID first = UUID.randomUUID();
         UUID second = UUID.randomUUID();
         sql.saveTrust(Map.of(
               first, new ShieldStorage.TrustRecord(1000L, 2000L, 7),
               second, new ShieldStorage.TrustRecord(3000L, 4000L, 2)));

         Map<UUID, ShieldStorage.TrustRecord> loaded = sql.loadTrust();

         assertEquals(2, loaded.size());
         assertEquals(7, loaded.get(first).cleanLogins());
         assertEquals(4000L, loaded.get(second).lastSeen());
      }

      @Test
      void savingTrustTwiceDoesNotDuplicateRows() {
         SqlStorage sql = open();
         UUID uuid = UUID.randomUUID();
         sql.saveTrust(Map.of(uuid, new ShieldStorage.TrustRecord(1000L, 2000L, 7)));
         sql.saveTrust(Map.of(uuid, new ShieldStorage.TrustRecord(1000L, 5000L, 9)));

         Map<UUID, ShieldStorage.TrustRecord> loaded = sql.loadTrust();

         assertEquals(1, loaded.size());
         assertEquals(9, loaded.get(uuid).cleanLogins());
      }

      @Test
      void aSqlStoreIsSharedBetweenServers() {
         assertTrue(open().shared());
      }

      @Test
      void urlsAreBuiltForEveryEngine() {
         assertTrue(SqlStorage.urlFor("mysql", "db.example", 3306, "shield", tempDir, "")
               .startsWith("jdbc:mysql://db.example:3306/shield"));
         assertTrue(SqlStorage.urlFor("mariadb", "db.example", 0, "shield", tempDir, "")
               .startsWith("jdbc:mariadb://db.example:3306/shield"));
         assertTrue(SqlStorage.urlFor("postgres", "db.example", 0, "shield", tempDir, "")
               .startsWith("jdbc:postgresql://db.example:5432/shield"));
         assertTrue(SqlStorage.urlFor("sqlite", "", 0, "shield.db", tempDir, "")
               .startsWith("jdbc:sqlite:"));
      }
   }

   @Nested
   @DisplayName("Redis protocol")
   class Redis {

      private FakeRedis fake;

      @AfterEach
      void stop() {
         if (fake != null) {
            fake.close();
         }
      }

      @Test
      void valuesAreStoredAndReadBack() throws Exception {
         fake = new FakeRedis();
         RedisStorage redis = new RedisStorage(new RecordingPlatform(tempDir), "127.0.0.1",
               fake.port(), null, null, 0, 2000, "ps:", "server-a");

         assertTrue(redis.available(), "the client should have connected");
         redis.put("203.0.113.7", verdict(true, 600_000L));
         Optional<ShieldStorage.CachedVerdict> found = redis.find("203.0.113.7");

         assertTrue(found.isPresent());
         assertRoundTripped(found.get());
         redis.close();
      }

      @Test
      void anUnknownKeyIsEmptyRatherThanAnError() throws Exception {
         fake = new FakeRedis();
         RedisStorage redis = new RedisStorage(new RecordingPlatform(tempDir), "127.0.0.1",
               fake.port(), null, null, 0, 2000, "ps:", "server-a");

         assertTrue(redis.find("198.51.100.1").isEmpty());
         redis.close();
      }

      @Test
      void invalidationIsPublishedToTheOtherServers() throws Exception {
         fake = new FakeRedis();
         RedisStorage redis = new RedisStorage(new RecordingPlatform(tempDir), "127.0.0.1",
               fake.port(), null, null, 0, 2000, "ps:", "server-a");

         redis.put("203.0.113.7", verdict(true, 600_000L));
         redis.invalidate("203.0.113.7");

         assertTrue(fake.awaitPublish(5, TimeUnit.SECONDS), "an invalidation must be broadcast");
         assertEquals("ps:invalidate", fake.lastChannel());
         assertTrue(fake.lastMessage().startsWith("server-a "),
               "the message carries its origin so a server ignores its own");
         assertTrue(redis.find("203.0.113.7").isEmpty());
         redis.close();
      }

      @Test
      void anUnreachableServerDegradesInsteadOfThrowing() {
         RedisStorage redis = new RedisStorage(new RecordingPlatform(tempDir), "127.0.0.1",
               1, null, null, 0, 300, "ps:", "server-a");

         assertFalse(redis.available());
         assertTrue(redis.find("203.0.113.7").isEmpty(), "a dead Redis must not break a login");
         redis.put("203.0.113.7", verdict(true, 1000L));
         redis.close();
      }
   }

   /** A Redis stand-in that understands the handful of commands ProxyShield sends. */
   private static final class FakeRedis implements AutoCloseable {

      private final ServerSocket socket;
      private final Map<String, String> values = new ConcurrentHashMap<>();
      private final CountDownLatch published = new CountDownLatch(1);
      private volatile String lastChannel;
      private volatile String lastMessage;
      private volatile boolean closed;

      FakeRedis() throws IOException {
         socket = new ServerSocket();
         socket.bind(new InetSocketAddress("127.0.0.1", 0));

         Thread accepter = new Thread(() -> {
            while (!closed) {
               try {
                  Socket client = socket.accept();
                  Thread handler = new Thread(() -> serve(client), "fake-redis-client");
                  handler.setDaemon(true);
                  handler.start();
               } catch (IOException stopped) {
                  return;
               }
            }
         }, "fake-redis");
         accepter.setDaemon(true);
         accepter.start();
      }

      int port() {
         return socket.getLocalPort();
      }

      boolean awaitPublish(long timeout, TimeUnit unit) throws InterruptedException {
         return published.await(timeout, unit);
      }

      String lastChannel() {
         return lastChannel;
      }

      String lastMessage() {
         return lastMessage;
      }

      private void serve(Socket client) {
         try (client;
               BufferedReader in = new BufferedReader(
                     new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8))) {
            OutputStream out = client.getOutputStream();
            String line;
            while ((line = in.readLine()) != null) {
               if (!line.startsWith("*")) {
                  continue;
               }
               int argc = Integer.parseInt(line.substring(1));
               String[] args = new String[argc];
               for (int i = 0; i < argc; i++) {
                  in.readLine();
                  args[i] = in.readLine();
               }
               respond(out, args);
            }
         } catch (IOException | RuntimeException disconnected) {
            // A client going away is the normal end of this loop.
         }
      }

      private void respond(OutputStream out, String[] args) throws IOException {
         String command = args[0].toUpperCase(java.util.Locale.ROOT);
         switch (command) {
            case "SET" -> {
               values.put(args[1], args[2]);
               write(out, "+OK\r\n");
            }
            case "GET" -> {
               String value = values.get(args[1]);
               if (value == null) {
                  write(out, "$-1\r\n");
               } else {
                  write(out, "$" + value.getBytes(StandardCharsets.UTF_8).length + "\r\n" + value
                        + "\r\n");
               }
            }
            case "DEL" -> {
               values.remove(args[1]);
               write(out, ":1\r\n");
            }
            case "PUBLISH" -> {
               lastChannel = args[1];
               lastMessage = args[2];
               published.countDown();
               write(out, ":0\r\n");
            }
            default -> write(out, "+OK\r\n");
         }
      }

      private void write(OutputStream out, String reply) throws IOException {
         out.write(reply.getBytes(StandardCharsets.UTF_8));
         out.flush();
      }

      @Override
      public void close() {
         closed = true;
         try {
            socket.close();
         } catch (IOException ignored) {
            // Nothing useful to do while shutting a test fixture down.
         }
      }
   }
}
