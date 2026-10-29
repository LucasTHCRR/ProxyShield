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

package de.lucasthcr.bridgesave.proxyshield.lookup;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.storage.FileStorage;
import de.lucasthcr.bridgesave.proxyshield.storage.ShieldStorage;
import de.lucasthcr.bridgesave.proxyshield.testing.MapConfigNode;
import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Consensus mode, cache sharing and persistence, against real HTTP servers. */
class ConsensusLookupTest {

   private static final String IP = "203.0.113.7";

   @TempDir
   Path tempDir;

   private HttpServer server;
   private String baseUrl;
   private RecordingPlatform platform;

   @BeforeEach
   void startServer() throws IOException {
      server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
      server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
      server.start();
      baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
      platform = new RecordingPlatform(tempDir);
   }

   @AfterEach
   void stopServer() {
      server.stop(0);
   }

   private void serve(String path, com.sun.net.httpserver.HttpHandler handler) {
      server.createContext(path, handler);
   }

   private static void respond(HttpExchange exchange, int status, String body) throws IOException {
      byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
      if (bytes.length > 0) {
         try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
         }
      }
   }

   /** Builds a consensus service from ad-hoc providers, each with its own weight. */
   private FailoverLookupService service(double requiredScore, Map<String, Double> pathsToWeights) {
      return service(requiredScore, pathsToWeights, null);
   }

   private FailoverLookupService service(double requiredScore, Map<String, Double> pathsToWeights,
         ShieldStorage storage) {
      Map<String, Object> values = new LinkedHashMap<>();
      values.put("api.mode", "consensus");
      values.put("api.required-score", requiredScore);
      values.put("api.timeout-seconds", 5);
      values.put("api.total-timeout-seconds", 10);

      int index = 0;
      for (Map.Entry<String, Double> entry : pathsToWeights.entrySet()) {
         String id = "p" + index++;
         values.put("api.providers." + id + ".enabled", true);
         values.put("api.providers." + id + ".url", baseUrl + entry.getKey() + "/{ip}");
         values.put("api.providers." + id + ".weight", entry.getValue());
         values.put("api.providers." + id + ".proxy-fields", List.of("proxy"));
         values.put("api.providers." + id + ".hosting-fields", List.of("hosting"));
         values.put("api.providers." + id + ".country-fields", List.of("countryCode"));
      }
      return new FailoverLookupService(platform, ShieldConfig.from(new MapConfigNode(values)),
            null, storage);
   }

   @Test
   @DisplayName("One weak provider on its own does not reach the threshold")
   void oneFlagIsNotEnough() {
      serve("/flag", exchange -> respond(exchange, 200,
            "{\"proxy\":true,\"countryCode\":\"NL\"}"));
      serve("/clean", exchange -> respond(exchange, 200,
            "{\"proxy\":false,\"countryCode\":\"NL\"}"));

      try (FailoverLookupService service = service(2.0,
            new LinkedHashMap<>(Map.of("/flag", 1.0, "/clean", 1.0)))) {
         LookupResult result = service.lookup(IP);

         assertTrue(result.resolved());
         assertFalse(result.proxy(), "1.0 of weight must not clear a threshold of 2.0");
         assertEquals(1.0, result.confidence(), 0.001);
      }
   }

   @Test
   @DisplayName("Two independent providers agreeing reach it")
   void twoFlagsAddUp() {
      serve("/one", exchange -> respond(exchange, 200,
            "{\"proxy\":true,\"countryCode\":\"NL\"}"));
      serve("/two", exchange -> respond(exchange, 200,
            "{\"proxy\":true,\"countryCode\":\"NL\"}"));

      try (FailoverLookupService service = service(2.0,
            new LinkedHashMap<>(Map.of("/one", 1.0, "/two", 1.0)))) {
         LookupResult result = service.lookup(IP);

         assertTrue(result.proxy());
         assertEquals(2, result.sources().size(), "both services should be named in the alert");
      }
   }

   @Test
   @DisplayName("A single trusted provider can be weighted to decide on its own")
   void weightsDecide() {
      serve("/strong", exchange -> respond(exchange, 200, "{\"proxy\":true}"));
      serve("/quiet", exchange -> respond(exchange, 200, "{\"proxy\":false}"));

      try (FailoverLookupService service = service(2.0,
            new LinkedHashMap<>(Map.of("/strong", 2.5, "/quiet", 1.0)))) {
         assertTrue(service.lookup(IP).proxy());
      }
   }

   @Test
   @DisplayName("A provider that is down cannot clear an address the others flagged")
   void aDeadProviderDoesNotClearTheAddress() {
      serve("/dead", exchange -> respond(exchange, 503, ""));
      serve("/live", exchange -> respond(exchange, 200, "{\"proxy\":true}"));

      try (FailoverLookupService service = service(1.0,
            new LinkedHashMap<>(Map.of("/dead", 1.0, "/live", 1.0)))) {
         LookupResult result = service.lookup(IP);

         assertTrue(result.resolved());
         assertTrue(result.proxy());
      }
   }

   @Test
   @DisplayName("Simultaneous logins from one address share a single round of requests")
   void concurrentLookupsAreCoalesced() throws Exception {
      AtomicInteger hits = new AtomicInteger();
      CountDownLatch release = new CountDownLatch(1);
      serve("/slow", exchange -> {
         hits.incrementAndGet();
         try {
            release.await(5, TimeUnit.SECONDS);
         } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
         }
         respond(exchange, 200, "{\"proxy\":true}");
      });

      try (FailoverLookupService service = service(1.0,
            new LinkedHashMap<>(Map.of("/slow", 1.0)))) {
         CountDownLatch started = new CountDownLatch(4);
         CountDownLatch finished = new CountDownLatch(4);
         for (int i = 0; i < 4; i++) {
            Thread thread = new Thread(() -> {
               started.countDown();
               service.lookup(IP);
               finished.countDown();
            });
            thread.setDaemon(true);
            thread.start();
         }

         assertTrue(started.await(5, TimeUnit.SECONDS));
         Thread.sleep(200);
         release.countDown();
         assertTrue(finished.await(10, TimeUnit.SECONDS));

         assertEquals(1, hits.get(), "four simultaneous logins must cost one request");
         assertTrue(service.coalescedCount() >= 1);
      }
   }

   @Test
   @DisplayName("An IPv6 address is cached for its whole /64")
   void ipv6IsCachedPerPrefix() {
      AtomicInteger hits = new AtomicInteger();
      serve("/v6", exchange -> {
         hits.incrementAndGet();
         respond(exchange, 200, "{\"proxy\":false}");
      });

      try (FailoverLookupService service = service(1.0,
            new LinkedHashMap<>(Map.of("/v6", 1.0)))) {
         service.lookup("2001:db8:1:2:3:4:5:6");
         service.lookup("2001:db8:1:2:aaaa:bbbb:cccc:dddd");

         assertEquals(1, hits.get(),
               "a rotating host part inside one /64 is the same client, not a new lookup");
      }
   }

   @Test
   @DisplayName("The cache survives a restart")
   void cachePersistsToDisk() {
      AtomicInteger hits = new AtomicInteger();
      serve("/persist", exchange -> {
         hits.incrementAndGet();
         respond(exchange, 200, "{\"proxy\":true,\"countryCode\":\"NL\"}");
      });

      Map<String, Double> providers = new LinkedHashMap<>(Map.of("/persist", 1.0));
      FileStorage storage = new FileStorage(platform);
      try (FailoverLookupService first = service(1.0, providers, storage)) {
         assertTrue(first.lookup(IP).proxy());
         storage.flush();
      }

      assertTrue(Files.isRegularFile(tempDir.resolve("lookup-cache.json")));

      FileStorage reopened = new FileStorage(platform);
      try (FailoverLookupService second = service(1.0, providers, reopened)) {
         second.preloadFrom(reopened);
         LookupResult restored = second.lookup(IP);

         assertTrue(restored.proxy(), "the stored verdict should come back");
         assertEquals(1, hits.get(), "a restart must not re-query what was already known");
      }
   }

   /** Captures what the service asked to be persisted, so the TTL is observable. */
   private static final class CapturingStorage implements ShieldStorage {

      private final Map<String, CachedVerdict> written = new LinkedHashMap<>();

      @Override
      public String name() {
         return "capturing";
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
      public Map<String, CachedVerdict> preload() {
         return Map.of();
      }

      @Override
      public java.util.Optional<CachedVerdict> find(String key) {
         return java.util.Optional.ofNullable(written.get(key));
      }

      @Override
      public void put(String key, CachedVerdict verdict) {
         written.put(key, verdict);
      }

      @Override
      public void invalidate(String key) {
         written.remove(key);
      }

      @Override
      public void clearVerdicts() {
         written.clear();
      }

      @Override
      public Map<java.util.UUID, TrustRecord> loadTrust() {
         return Map.of();
      }

      @Override
      public void saveTrust(Map<java.util.UUID, TrustRecord> records) {
      }

      @Override
      public void close() {
      }

      long ttlMillisFor(String key) {
         CachedVerdict verdict = written.get(key);
         return verdict == null ? -1 : verdict.expiresAt() - System.currentTimeMillis();
      }
   }

   @Nested
   @DisplayName("How long a clean answer may be reused")
   class CleanVerdictLifetime {

      private Map<String, Object> config(double requiredScore, String... paths) {
         Map<String, Object> values = new LinkedHashMap<>();
         values.put("api.mode", "consensus");
         values.put("api.required-score", requiredScore);
         values.put("api.cache-minutes", 360);
         values.put("api.flagged-cache-minutes", 1440);
         values.put("api.total-timeout-seconds", 10);
         int index = 0;
         for (String path : paths) {
            String id = "p" + index++;
            values.put("api.providers." + id + ".enabled", true);
            values.put("api.providers." + id + ".url", baseUrl + path + "/{ip}");
            values.put("api.providers." + id + ".weight", 1.0);
            values.put("api.providers." + id + ".proxy-fields", List.of("proxy"));
            values.put("api.providers." + id + ".hosting-fields", List.of("hosting"));
         }
         return values;
      }

      @Test
      @DisplayName("Every provider answered clean, so the full cache time applies")
      void completeCleanRoundIsKeptForTheFullTime() {
         serve("/allclean1", exchange -> respond(exchange, 200, "{\"proxy\":false}"));
         serve("/allclean2", exchange -> respond(exchange, 200, "{\"proxy\":false}"));

         CapturingStorage storage = new CapturingStorage();
         try (FailoverLookupService service = new FailoverLookupService(platform,
               ShieldConfig.from(new MapConfigNode(config(2.0, "/allclean1", "/allclean2"))),
               null, storage)) {
            assertFalse(service.lookup(IP).proxy());
         }

         assertTrue(storage.ttlMillisFor(IP) > 300_000L,
               "a complete clean round is worth the configured six hours");
      }

      /**
       * The failure mode this guards: one provider answering "not a proxy" is enough to resolve
       * the round, so a rate limit or a timeout on the provider that would have flagged the
       * address used to produce a clean answer that sat in the cache for six hours and survived
       * restarts through lookup-cache.json. The address kept passing long after the providers
       * recovered.
       */
      @Test
      @DisplayName("A provider that never answered cuts the clean answer short")
      void incompleteCleanRoundExpiresQuickly() {
         serve("/halfclean", exchange -> respond(exchange, 200, "{\"proxy\":false}"));
         serve("/halfdown", exchange -> respond(exchange, 500, ""));

         CapturingStorage storage = new CapturingStorage();
         try (FailoverLookupService service = new FailoverLookupService(platform,
               ShieldConfig.from(new MapConfigNode(config(2.0, "/halfclean", "/halfdown"))),
               null, storage)) {
            assertFalse(service.lookup(IP).proxy());
         }

         long ttl = storage.ttlMillisFor(IP);
         assertTrue(ttl > 0 && ttl <= 300_000L,
               "an incomplete clean round may only absorb a burst, not the rest of the day, "
                     + "but was kept for " + ttl + "ms");
      }

      @Test
      @DisplayName("A flagged answer keeps its own cache time even off a short round")
      void flaggedRoundIsUnaffected() {
         serve("/flagfast", exchange -> respond(exchange, 200, "{\"proxy\":true}"));
         serve("/flagdown", exchange -> respond(exchange, 500, ""));

         CapturingStorage storage = new CapturingStorage();
         try (FailoverLookupService service = new FailoverLookupService(platform,
               ShieldConfig.from(new MapConfigNode(config(1.0, "/flagfast", "/flagdown"))),
               null, storage)) {
            assertTrue(service.lookup(IP).proxy());
         }

         assertTrue(storage.ttlMillisFor(IP) > 300_000L,
               "stopping early on a settled verdict is not an incomplete round");
      }
   }

   @Test
   @DisplayName("A reload keeps the cache it already paid for")
   void reloadInheritsTheCache() {
      AtomicInteger hits = new AtomicInteger();
      serve("/reload", exchange -> {
         hits.incrementAndGet();
         respond(exchange, 200, "{\"proxy\":true}");
      });

      Map<String, Object> values = new LinkedHashMap<>();
      values.put("api.mode", "consensus");
      values.put("api.required-score", 1.0);
      values.put("api.providers.p0.enabled", true);
      values.put("api.providers.p0.url", baseUrl + "/reload/{ip}");
      values.put("api.providers.p0.proxy-fields", List.of("proxy"));
      ShieldConfig config = ShieldConfig.from(new MapConfigNode(values));

      try (FailoverLookupService before = new FailoverLookupService(platform, config)) {
         before.lookup(IP);

         try (FailoverLookupService after =
               new FailoverLookupService(platform, config, before)) {
            after.lookup(IP);
            assertEquals(1, hits.get(), "a reload must not cost a fresh round of provider quota");
            assertEquals(1, after.cacheSize());
         }
      }
   }

   @Nested
   @DisplayName("Staged lookups")
   class Staged {

      private final java.util.concurrent.atomic.AtomicInteger first = new java.util.concurrent.atomic.AtomicInteger();
      private final java.util.concurrent.atomic.AtomicInteger second = new java.util.concurrent.atomic.AtomicInteger();
      private final java.util.concurrent.atomic.AtomicInteger third = new java.util.concurrent.atomic.AtomicInteger();

      private FailoverLookupService staged(int firstWave, String... bodies) {
         java.util.concurrent.atomic.AtomicInteger[] counters = {first, second, third};
         Map<String, Object> values = new LinkedHashMap<>();
         values.put("api.mode", "consensus");
         values.put("api.required-score", 1.5);
         values.put("api.first-wave", firstWave);
         values.put("api.total-timeout-seconds", 10);
         for (int index = 0; index < bodies.length; index++) {
            String path = "/stage" + index + "-" + System.nanoTime();
            String body = bodies[index];
            java.util.concurrent.atomic.AtomicInteger counter = counters[index];
            serve(path, exchange -> {
               counter.incrementAndGet();
               respond(exchange, 200, body);
            });
            String id = "s" + index;
            values.put("api.providers." + id + ".enabled", true);
            values.put("api.providers." + id + ".url", baseUrl + path + "/{ip}");
            values.put("api.providers." + id + ".weight", 1.0);
            values.put("api.providers." + id + ".proxy-fields", List.of("proxy"));
            values.put("api.providers." + id + ".hosting-fields", List.of("hosting"));
         }
         return new FailoverLookupService(platform, ShieldConfig.from(new MapConfigNode(values)), null, null);
      }

      @Test
      @DisplayName("A clean first wave settles the lookup without asking the rest")
      void cleanFirstWaveSkipsTheRest() {
         try (FailoverLookupService service = staged(2, "{\"proxy\":false}", "{\"proxy\":false}",
               "{\"proxy\":true}")) {
            LookupResult result = service.lookup(IP);

            assertFalse(result.proxy());
            assertEquals(1, first.get());
            assertEquals(1, second.get());
            assertEquals(0, third.get(), "the third provider must not be asked");
         }
      }

      @Test
      @DisplayName("A flag in the first wave brings in the others")
      void aFlagAsksTheRest() {
         try (FailoverLookupService service = staged(2, "{\"proxy\":true}", "{\"proxy\":false}",
               "{\"proxy\":true}")) {
            LookupResult result = service.lookup(IP);

            assertTrue(result.proxy());
            assertEquals(1, third.get());
         }
      }

      @Test
      @DisplayName("A first wave of 0 asks everyone at once, as before")
      void zeroAsksEveryone() {
         try (FailoverLookupService service = staged(0, "{\"proxy\":false}", "{\"proxy\":false}",
               "{\"proxy\":false}")) {
            service.lookup(IP);

            assertEquals(1, third.get());
         }
      }
   }
}
