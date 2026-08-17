package de.lucasthcr.bridgesave.proxyshield.lookup;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.testing.MapConfigNode;
import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises the provider chain against real HTTP servers. */
class FailoverLookupServiceTest {

   private static final String IP = "203.0.113.7";

   @TempDir
   Path tempDir;

   private HttpServer server;
   private String baseUrl;
   private RecordingPlatform platform;

   @BeforeEach
   void startServer() throws IOException {
      server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
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

   private FailoverLookupService service(List<String> providers) {
      Map<String, Object> values = new LinkedHashMap<>();
      values.put("api.providers", providers);
      values.put("api.timeout-seconds", 5);
      return new FailoverLookupService(platform, ShieldConfig.from(new MapConfigNode(values)));
   }

   @Test
   @DisplayName("A dead first provider is skipped and the second answers")
   void failsOverToTheSecondProvider() {
      AtomicInteger firstHits = new AtomicInteger();
      AtomicInteger secondHits = new AtomicInteger();

      serve("/dead", exchange -> {
         firstHits.incrementAndGet();
         respond(exchange, 503, "");
      });
      serve("/alive", exchange -> {
         secondHits.incrementAndGet();
         respond(exchange, 200,
               "{\"status\":\"success\",\"proxy\":true,\"hosting\":false,\"countryCode\":\"NL\"}");
      });

      FailoverLookupService service =
            service(List.of(baseUrl + "/dead/{ip}", baseUrl + "/alive/{ip}"));
      LookupResult result = service.lookup(IP);

      assertTrue(result.resolved(), "second provider should have answered");
      assertTrue(result.proxy());
      assertEquals("NL", result.countryCode());
      assertEquals(1, firstHits.get());
      assertEquals(1, secondHits.get());
      assertEquals(1, service.failoverCount());
   }

   @Test
   @DisplayName("The second provider is not touched while the first works")
   void doesNotFailOverUnnecessarily() {
      AtomicInteger secondHits = new AtomicInteger();

      serve("/good", exchange -> respond(exchange, 200,
            "{\"status\":\"success\",\"proxy\":false,\"countryCode\":\"DE\"}"));
      serve("/spare", exchange -> {
         secondHits.incrementAndGet();
         respond(exchange, 200, "{\"status\":\"success\",\"proxy\":true}");
      });

      FailoverLookupService service =
            service(List.of(baseUrl + "/good/{ip}", baseUrl + "/spare/{ip}"));
      LookupResult result = service.lookup(IP);

      assertTrue(result.resolved());
      assertFalse(result.proxy());
      assertEquals(0, secondHits.get(), "spare provider must stay untouched");
      assertEquals(0, service.failoverCount());
   }

   @Test
   @DisplayName("Every provider failing leaves the result unresolved rather than clean")
   void reportsFailureWhenTheWholeChainIsDown() {
      serve("/a", exchange -> respond(exchange, 500, ""));
      serve("/b", exchange -> respond(exchange, 500, ""));

      FailoverLookupService service = service(List.of(baseUrl + "/a/{ip}", baseUrl + "/b/{ip}"));
      LookupResult result = service.lookup(IP);

      assertFalse(result.resolved(), "an unreachable chain must not look like a clean address");
      assertEquals(1, service.failureCount());
   }

   @Test
   @DisplayName("A repeat lookup is served from the cache, not the provider")
   void cachesAcrossTheChain() {
      AtomicInteger hits = new AtomicInteger();
      serve("/good", exchange -> {
         hits.incrementAndGet();
         respond(exchange, 200, "{\"status\":\"success\",\"proxy\":false,\"countryCode\":\"DE\"}");
      });

      FailoverLookupService service = service(List.of(baseUrl + "/good/{ip}"));
      service.lookup(IP);
      service.lookup(IP);

      assertEquals(1, hits.get(), "second call should have been a cache hit");
      assertEquals(1, service.cacheHits());
   }

   /** proxycheck.io nests its data under the queried address and spells flags "yes"/"no". */
   @Test
   @DisplayName("A nested, yes/no style response is understood")
   void readsNestedProviderShape() {
      serve("/pc", exchange -> respond(exchange, 200,
            "{\"status\":\"ok\",\"" + IP + "\":{\"proxy\":\"yes\",\"type\":\"VPN\","
                  + "\"isocode\":\"NL\",\"provider\":\"Some VPN Ltd\"}}"));

      FailoverLookupService service = service(List.of(baseUrl + "/pc/{ip}"));
      LookupResult result = service.lookup(IP);

      assertTrue(result.resolved());
      assertTrue(result.proxy(), "\"yes\" must count as true");
      assertEquals("NL", result.countryCode());
      assertEquals("Some VPN Ltd", result.ispOrUnknown());
   }

   @Test
   @DisplayName("An in-band failure status is a failure, not a clean result")
   void treatsInBandFailureAsUnresolved() {
      serve("/fail", exchange -> respond(exchange, 200,
            "{\"status\":\"fail\",\"message\":\"reserved range\"}"));

      FailoverLookupService service = service(List.of(baseUrl + "/fail/{ip}"));
      LookupResult result = service.lookup(IP);

      assertFalse(result.resolved());
      assertTrue(result.failureReason().contains("reserved range"));
   }

   @Test
   void anEmptyChainIsReportedRatherThanCrashing() {
      FailoverLookupService service = service(List.of());

      assertEquals(0, service.providerCount());
      assertFalse(service.lookup(IP).resolved());
   }
}
