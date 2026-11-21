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

package de.lucasthcr.bridgesave.proxyshield.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import de.lucasthcr.bridgesave.proxyshield.check.CheckVerdict;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import de.lucasthcr.bridgesave.proxyshield.testing.MapConfigNode;
import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SightingReporterTest {

   private static final CheckVerdict PROXY =
         CheckVerdict.deny(CheckVerdict.Reason.PROXY, "2 providers", LookupResult.UNKNOWN);

   @TempDir
   Path tempDir;

   private HttpServer server;
   private final List<String> requests = new CopyOnWriteArrayList<>();
   private volatile int answer = 200;

   @BeforeEach
   void start() throws IOException {
      server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
      server.createContext("/", exchange -> {
         String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
         requests.add(exchange.getRequestURI().getPath() + " " + body);
         byte[] reply = "{\"deleted\":3,\"accepted\":1}".getBytes(StandardCharsets.UTF_8);
         exchange.sendResponseHeaders(answer, reply.length);
         exchange.getResponseBody().write(reply);
         exchange.close();
      });
      server.start();
   }

   @AfterEach
   void stop() {
      server.stop(0);
   }

   private ShieldConfig config(boolean enabled) {
      Map<String, Object> values = new LinkedHashMap<>();
      values.put("reporting.enabled", enabled);
      values.put("reporting.url", "http://127.0.0.1:" + server.getAddress().getPort() + "/");
      return ShieldConfig.from(new MapConfigNode(values));
   }

   private SightingReporter reporter(boolean enabled) {
      ShieldConfig config = config(enabled);
      return new SightingReporter(new RecordingPlatform(tempDir), () -> config);
   }

   @Test
   @DisplayName("Reporting is off unless the owner switches it on")
   void offByDefault() {
      assertFalse(ShieldConfig.from(new MapConfigNode(new LinkedHashMap<>())).reportingEnabled());
      SightingReporter off = reporter(false);
      off.offer("203.0.113.9", PROXY);
      off.flush(config(false));

      assertTrue(requests.isEmpty());
      assertFalse(Files.exists(tempDir.resolve("install-id")));
   }

   @Test
   @DisplayName("Only addresses refused as proxies are queued, and only well formed ones")
   void queuesOnlyProxyVerdicts() {
      SightingReporter reporter = reporter(true);
      reporter.offer("203.0.113.9", CheckVerdict.deny(CheckVerdict.Reason.IP_LIST, "list", LookupResult.UNKNOWN));
      reporter.offer("203.0.113.9", CheckVerdict.allow(CheckVerdict.Reason.ALLOWED));
      reporter.offer("not an address", PROXY);
      reporter.offer(null, PROXY);
      assertEquals(0, reporter.status().queued());

      reporter.offer("203.0.113.9", PROXY);
      reporter.offer("203.0.113.9", PROXY);
      reporter.offer("2001:db8::1", PROXY);
      assertEquals(2, reporter.status().queued());
   }

   @Test
   @DisplayName("A batch carries the addresses and a random id, nothing else")
   void sendsBatch() throws IOException {
      SightingReporter reporter = reporter(true);
      reporter.offer("203.0.113.9", PROXY);
      reporter.flush(config(true));

      assertEquals(1, requests.size());
      String request = requests.get(0);
      assertTrue(request.startsWith("/v1/report {\"install\":\""), request);
      assertTrue(request.contains("\"ips\":[\"203.0.113.9\"]"), request);
      String id = Files.readString(tempDir.resolve("install-id")).trim();
      assertTrue(id.matches("[0-9a-f]{32}"), id);
      assertTrue(request.contains(id));
      assertEquals(0, reporter.status().queued());
      assertEquals(1, reporter.status().sent());

      reporter.offer("198.51.100.7", PROXY);
      reporter.flush(config(true));
      assertTrue(requests.get(1).contains(id), "the id stays the same");
   }

   @Test
   @DisplayName("A failed send keeps the batch for the next try")
   void keepsBatchOnFailure() {
      answer = 503;
      SightingReporter reporter = reporter(true);
      reporter.offer("203.0.113.9", PROXY);
      reporter.flush(config(true));

      assertEquals(1, reporter.status().queued());
      assertEquals("HTTP 503", reporter.status().lastError());

      answer = 200;
      reporter.flush(config(true));
      assertEquals(0, reporter.status().queued());
      assertEquals("", reporter.status().lastError());
   }

   @Test
   @DisplayName("Forget deletes at the service and drops the install id")
   void forgets() {
      SightingReporter reporter = reporter(true);
      assertEquals(-2, reporter.forget());

      reporter.offer("203.0.113.9", PROXY);
      reporter.flush(config(true));
      assertTrue(reporter.status().hasId());

      assertEquals(3, reporter.forget());
      assertTrue(requests.get(requests.size() - 1).startsWith("/v1/forget"));
      assertFalse(reporter.status().hasId());
   }

   @Test
   @DisplayName("An unreachable service leaves the id and the queue alone when forgetting")
   void forgetNeedsTheService() {
      SightingReporter reporter = reporter(true);
      reporter.offer("203.0.113.9", PROXY);
      reporter.flush(config(true));
      server.stop(0);

      assertEquals(-1, reporter.forget());
      assertTrue(reporter.status().hasId());
   }
}
