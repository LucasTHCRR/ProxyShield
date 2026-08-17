package de.lucasthcr.bridgesave.proxyshield.list;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Exercises the download path against a real HTTP server.
 * <p>
 * These cover the failure seen on the first live run, where raw.githubusercontent.com answered 429
 * to all four feeds at once and the plugin came up with no list protection at all.
 */
class ListManagerTest {

   private static final String FEED = "1.2.3.0/24\n5.5.5.0/24\n";

   private static final ListManager.RetryPolicy FAST_RETRIES =
         new ListManager.RetryPolicy(3, 10L, 50L, 0L);

   @TempDir
   Path tempDir;

   private HttpServer server;
   private String baseUrl;
   private RecordingPlatform platform;
   private ListManager lists;

   @BeforeEach
   void startServer() throws IOException {
      server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
      server.start();
      baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
      platform = new RecordingPlatform(tempDir);
      // Real backoff would make this suite take twenty seconds; the delays themselves are
      // covered by asserting the attempt count, not by waiting them out.
      lists = new ListManager(platform, FAST_RETRIES);
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
      exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
      if (bytes.length > 0) {
         try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
         }
      }
   }

   @Test
   @DisplayName("A plain download compiles into ranges")
   void downloadsAndCompiles() {
      serve("/feed", exchange -> respond(exchange, 200, FEED));

      assertTrue(lists.refresh(List.of(baseUrl + "/feed"), 5, true));

      assertTrue(lists.matches("1.2.3.99"));
      assertTrue(lists.matches("5.5.5.1"));
      assertFalse(lists.matches("9.9.9.9"));
      assertEquals(0, lists.failedSourceCount());
   }

   @Test
   @DisplayName("A 429 is retried and the feed still loads")
   void retriesAfterRateLimit() {
      AtomicInteger attempts = new AtomicInteger();
      serve("/feed", exchange -> {
         if (attempts.incrementAndGet() < 3) {
            exchange.getResponseHeaders().add("Retry-After", "0");
            respond(exchange, 429, "");
            return;
         }
         respond(exchange, 200, FEED);
      });

      assertTrue(lists.refresh(List.of(baseUrl + "/feed"), 5, true));

      assertEquals(3, attempts.get(), "should have retried twice before succeeding");
      assertTrue(lists.matches("1.2.3.99"));
   }

   @Test
   @DisplayName("Persistent rate limiting gives up without wiping existing ranges")
   void keepsPreviousRangesWhenRateLimited() {
      serve("/good", exchange -> respond(exchange, 200, FEED));
      assertTrue(lists.refresh(List.of(baseUrl + "/good"), 5, true));
      int before = lists.ranges().rangeCount();

      serve("/limited", exchange -> {
         exchange.getResponseHeaders().add("Retry-After", "0");
         respond(exchange, 429, "");
      });
      assertFalse(lists.refresh(List.of(baseUrl + "/limited"), 5, true));

      assertEquals(before, lists.ranges().rangeCount(), "protection must not be dropped");
      assertTrue(lists.matches("1.2.3.99"));
      assertTrue(lists.lastError().contains("rate limited"));
   }

   @Test
   @DisplayName("Losing every source with nothing cached is reported as inactive detection")
   void warnsLoudlyWhenNothingIsAvailable() {
      serve("/limited", exchange -> respond(exchange, 429, ""));

      assertFalse(lists.refresh(List.of(baseUrl + "/limited"), 5, true));

      assertTrue(platform.warnings().stream().anyMatch(w -> w.contains("INACTIVE")),
            "operator must be told list detection is off: " + platform.warnings());
      assertTrue(platform.warnings().stream().anyMatch(w -> w.contains("429")),
            "the rate limit should be explained: " + platform.warnings());
   }

   @Test
   @DisplayName("An unchanged feed is served from the cache via ETag")
   void reusesCacheOnNotModified() {
      AtomicInteger fullBodies = new AtomicInteger();
      serve("/feed", exchange -> {
         String sent = exchange.getRequestHeaders().getFirst("If-None-Match");
         if ("\"v1\"".equals(sent)) {
            respond(exchange, 304, "");
            return;
         }
         fullBodies.incrementAndGet();
         exchange.getResponseHeaders().add("ETag", "\"v1\"");
         respond(exchange, 200, FEED);
      });

      String source = baseUrl + "/feed";
      assertTrue(lists.refresh(List.of(source), 5, true));
      assertTrue(lists.refresh(List.of(source), 5, true));

      assertEquals(1, fullBodies.get(), "second refresh should have been a conditional 304");
      assertTrue(lists.matches("1.2.3.99"), "ranges must survive the 304 path");
   }

   @Test
   @DisplayName("The disk cache protects a restart during an outage")
   void restoresFromDiskCache() {
      serve("/feed", exchange -> respond(exchange, 200, FEED));
      assertTrue(lists.refresh(List.of(baseUrl + "/feed"), 5, true));

      ListManager afterRestart = new ListManager(platform, FAST_RETRIES);
      assertFalse(afterRestart.matches("1.2.3.99"), "starts empty");

      afterRestart.loadFromDisk(List.of(baseUrl + "/feed"));

      assertTrue(afterRestart.matches("1.2.3.99"), "cached copy should provide protection");
   }

   @Test
   @DisplayName("One dead source does not stop the others")
   void survivesAPartialFailure() {
      serve("/good", exchange -> respond(exchange, 200, FEED));
      serve("/gone", exchange -> respond(exchange, 404, "not found"));

      assertTrue(lists.refresh(List.of(baseUrl + "/gone", baseUrl + "/good"), 5, true));

      assertTrue(lists.matches("1.2.3.99"));
      assertEquals(1, lists.failedSourceCount());
      assertEquals(2, lists.sourceCount());
   }

   @Test
   void emptySourceListClearsEverything() {
      serve("/feed", exchange -> respond(exchange, 200, FEED));
      assertTrue(lists.refresh(List.of(baseUrl + "/feed"), 5, true));

      assertTrue(lists.refresh(List.of(), 5, true));

      assertTrue(lists.ranges().isEmpty());
   }
}
