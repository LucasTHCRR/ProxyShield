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

import de.lucasthcr.bridgesave.proxyshield.check.CheckVerdict;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Sends the addresses that were refused as proxies to the intel service, when the owner switched
 * that on. Off by default. Nothing but the address and a random install id leaves the server: no
 * player name, no UUID, no server address.
 */
public final class SightingReporter {

   private static final int QUEUE_LIMIT = 1000;
   private static final int BATCH = 200;
   private static final Pattern ADDRESS = Pattern.compile("[0-9a-fA-F:.]{2,45}");

   public record Status(boolean enabled, String url, int queued, int sent, String lastError, boolean hasId) {
   }

   private final Platform platform;
   private final Supplier<ShieldConfig> config;
   private final Path idFile;
   private final Set<String> queue = ConcurrentHashMap.newKeySet();
   private volatile long lastFlush = System.currentTimeMillis();
   private volatile int sent;
   private volatile String lastError = "";

   public SightingReporter(Platform platform, Supplier<ShieldConfig> config) {
      this.platform = platform;
      this.config = config;
      this.idFile = platform.dataFolder().resolve("install-id");
   }

   /** Queues an address when it was refused as a proxy by the providers. */
   public void offer(String ip, CheckVerdict verdict) {
      if (verdict.reason() != CheckVerdict.Reason.PROXY || !config.get().reportingEnabled()) {
         return;
      }
      if (ip != null && ADDRESS.matcher(ip).matches() && queue.size() < QUEUE_LIMIT) {
         queue.add(ip);
      }
   }

   /** Called every minute, sends when the configured interval has passed. */
   public void tick() {
      ShieldConfig current = config.get();
      if (!current.reportingEnabled() || queue.isEmpty()) {
         return;
      }
      long now = System.currentTimeMillis();
      if (now - lastFlush < current.reportingIntervalMinutes() * 60_000L) {
         return;
      }
      lastFlush = now;
      flush(current);
   }

   void flush(ShieldConfig current) {
      List<String> batch = new ArrayList<>();
      for (String ip : queue) {
         batch.add(ip);
         if (batch.size() >= BATCH) {
            break;
         }
      }
      if (batch.isEmpty()) {
         return;
      }
      StringBuilder body = new StringBuilder("{\"install\":\"").append(installId()).append("\",\"ips\":[");
      for (int i = 0; i < batch.size(); i++) {
         body.append(i == 0 ? "\"" : ",\"").append(batch.get(i)).append('"');
      }
      body.append("]}");
      int status = post(current.reportingUrl() + "/v1/report", body.toString());
      if (status == 200) {
         queue.removeAll(batch);
         sent += batch.size();
         lastError = "";
      } else {
         lastError = status < 0 ? "not reachable" : "HTTP " + status;
         if (status == 400) {
            queue.removeAll(batch);
         }
      }
   }

   /**
    * Asks the service to delete everything it holds for this install and forgets the id.
    *
    * @return the number of deleted entries, -1 when the service could not be reached, -2 when this
    *         server never reported anything
    */
   public int forget() {
      if (!Files.isRegularFile(idFile)) {
         queue.clear();
         return -2;
      }
      String id = installId();
      String answer = postForBody(config.get().reportingUrl() + "/v1/forget", "{\"install\":\"" + id + "\"}");
      if (answer == null) {
         return -1;
      }
      queue.clear();
      try {
         Files.deleteIfExists(idFile);
      } catch (IOException ignored) {
         platform.warn("Could not delete " + idFile.getFileName());
      }
      java.util.regex.Matcher count = Pattern.compile("\"deleted\"\\s*:\\s*(\\d+)").matcher(answer);
      return count.find() ? Integer.parseInt(count.group(1)) : 0;
   }

   // Meldung eines Admins: Adresse ist ein VPN (vpn) oder wurde zu Unrecht gesperrt (clean)
   public int feedback(String ip, String kind) {
      if (!de.lucasthcr.bridgesave.proxyshield.net.IpAddresses.isValid(ip)
            || !(kind.equals("vpn") || kind.equals("clean"))) {
         return 400;
      }
      String body = "{\"install\":\"" + installId() + "\",\"ip\":\"" + ip + "\",\"kind\":\"" + kind + "\"}";
      return post(config.get().reportingUrl() + "/v1/feedback", body);
   }

   public Status status() {
      ShieldConfig current = config.get();
      return new Status(current.reportingEnabled(), current.reportingUrl(), queue.size(), sent, lastError,
            Files.isRegularFile(idFile));
   }

   private String installId() {
      try {
         if (Files.isRegularFile(idFile)) {
            String stored = Files.readString(idFile).trim();
            if (stored.matches("[0-9a-f]{32}")) {
               return stored;
            }
         }
         byte[] random = new byte[16];
         new SecureRandom().nextBytes(random);
         String created = HexFormat.of().formatHex(random);
         Files.createDirectories(idFile.getParent());
         Files.writeString(idFile, created + "\n");
         return created;
      } catch (IOException failure) {
         platform.warn("Could not store the install id: " + failure.getMessage());
         byte[] random = new byte[16];
         new SecureRandom().nextBytes(random);
         return HexFormat.of().formatHex(random);
      }
   }

   private int post(String url, String body) {
      HttpURLConnection connection = open(url, body);
      if (connection == null) {
         return -1;
      }
      try {
         return connection.getResponseCode();
      } catch (IOException failure) {
         return -1;
      } finally {
         connection.disconnect();
      }
   }

   private String postForBody(String url, String body) {
      HttpURLConnection connection = open(url, body);
      if (connection == null) {
         return null;
      }
      try {
         if (connection.getResponseCode() != 200) {
            return null;
         }
         return new String(connection.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      } catch (IOException failure) {
         return null;
      } finally {
         connection.disconnect();
      }
   }

   private HttpURLConnection open(String url, String body) {
      try {
         HttpURLConnection connection = (HttpURLConnection) URI.create(url).toURL().openConnection();
         connection.setRequestMethod("POST");
         connection.setConnectTimeout(10_000);
         connection.setReadTimeout(10_000);
         connection.setDoOutput(true);
         connection.setRequestProperty("Content-Type", "application/json");
         connection.setRequestProperty("User-Agent", "ProxyShield");
         try (OutputStream out = connection.getOutputStream()) {
            out.write(body.getBytes(StandardCharsets.UTF_8));
         }
         return connection;
      } catch (IOException | IllegalArgumentException failure) {
         return null;
      }
   }
}
