package de.lucasthcr.bridgesave.proxyshield.notify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class WeeklyReportTest {

   @Test
   @DisplayName("Counts survive a restart and are posted once the week is over")
   void countsSurviveRestartAndArePosted(@TempDir Path dir) throws IOException {
      Path file = dir.resolve("weekly.properties");
      WeeklyReport first = new WeeklyReport(file);
      first.add(10, 2);
      first.add(15, 3);

      // Neustart: Zaehler des Servers beginnen wieder bei 0
      WeeklyReport second = new WeeklyReport(file);
      second.add(5, 1);
      assertFalse(second.due());

      Files.writeString(file, Files.readString(file).replaceAll("start=\\d+", "start=0"));
      WeeklyReport third = new WeeklyReport(file);
      assertTrue(third.due());

      AtomicReference<String> received = new AtomicReference<>();
      HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
      server.createContext("/hook", exchange -> {
         received.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
         exchange.sendResponseHeaders(204, -1);
         exchange.close();
      });
      server.start();
      try {
         String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/hook";
         assertTrue(third.send(url, "test", List.of("zowi (3)")));
      } finally {
         server.stop(0);
      }
      assertTrue(received.get().contains("Joins checked: **20**"), received.get());
      assertTrue(received.get().contains("Refused: **4**"), received.get());
      assertTrue(received.get().contains("zowi (3)"), received.get());
      assertFalse(new WeeklyReport(file).due(), "a new week starts after sending");
      assertEquals(-1, received.get().indexOf('\n'), "line breaks are escaped in the JSON");
   }
}
