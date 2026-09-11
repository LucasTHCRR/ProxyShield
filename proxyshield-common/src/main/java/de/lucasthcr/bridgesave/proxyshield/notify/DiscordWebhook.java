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

package de.lucasthcr.bridgesave.proxyshield.notify;

import de.lucasthcr.bridgesave.proxyshield.check.CheckVerdict;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import de.lucasthcr.bridgesave.proxyshield.util.Json;
import de.lucasthcr.bridgesave.proxyshield.util.Text;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Posts block alerts to a Discord webhook.
 * <p>
 * Alerts are queued and drained by a single worker so a login flood cannot spawn one HTTP request
 * per connection, and Discord's {@code 429 Retry-After} is honoured instead of hammering through
 * it. Payloads are built with {@link Json.Writer}, so names and config strings are escaped rather
 * than concatenated into the body.
 */
public final class DiscordWebhook {

   private static final int MAX_QUEUE = 100;
   private static final int MAX_ATTEMPTS = 3;

   private final Platform platform;
   private final Queue<Payload> queue = new ConcurrentLinkedQueue<>();
   private final AtomicBoolean draining = new AtomicBoolean();

   private volatile ShieldConfig config;
   private final AtomicLong sent = new AtomicLong();
   private final AtomicLong dropped = new AtomicLong();

   public DiscordWebhook(Platform platform, ShieldConfig config) {
      this.platform = platform;
      this.config = config;
   }

   public void applyConfig(ShieldConfig config) {
      this.config = config;
   }

   /** Queues an alert. Returns immediately; delivery happens on an async worker. */
   public void enqueue(String player, String ip, CheckVerdict verdict, boolean enforced) {
      ShieldConfig current = config;
      if (!current.discordUsable()) {
         return;
      }

      if (queue.size() >= MAX_QUEUE) {
         dropped.incrementAndGet();
         return;
      }

      queue.add(new Payload(player, ip, verdict.describe(),
            verdict.lookup().countryOrUnknown(), verdict.lookup().ispOrUnknown(), enforced));
      drain();
   }

   private void drain() {
      if (!draining.compareAndSet(false, true)) {
         return;
      }

      platform.runAsync(() -> {
         try {
            Payload payload;
            while ((payload = queue.poll()) != null) {
               deliver(payload);
            }
         } finally {
            draining.set(false);
            // Something may have been queued between the last poll and clearing the flag.
            if (!queue.isEmpty()) {
               drain();
            }
         }
      });
   }

   private void deliver(Payload payload) {
      ShieldConfig current = config;
      String body = buildBody(current, payload);

      for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
         HttpURLConnection connection = null;
         try {
            URL url = URI.create(current.webhookUrl()).toURL();
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("User-Agent", "ProxyShield/2.1");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            connection.setDoOutput(true);

            try (OutputStream out = connection.getOutputStream()) {
               out.write(body.getBytes(StandardCharsets.UTF_8));
            }

            int status = connection.getResponseCode();
            if (status == 429) {
               long waitMillis = retryAfterMillis(connection);
               drainErrorStream(connection);
               if (attempt == MAX_ATTEMPTS) {
                  dropped.incrementAndGet();
                  platform.warn("Discord kept rate limiting the webhook, dropping one alert.");
                  return;
               }
               Thread.sleep(waitMillis);
               continue;
            }

            if (status >= 200 && status < 300) {
               sent.incrementAndGet();
               return;
            }

            drainErrorStream(connection);
            dropped.incrementAndGet();
            platform.warn("Discord webhook rejected the alert with HTTP " + status + ".");
            return;
         } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            dropped.incrementAndGet();
            return;
         } catch (IOException | RuntimeException failure) {
            if (attempt == MAX_ATTEMPTS) {
               dropped.incrementAndGet();
               platform.warn("Discord webhook failed: " + failure.getMessage());
            }
         } finally {
            if (connection != null) {
               connection.disconnect();
            }
         }
      }
   }

   private long retryAfterMillis(HttpURLConnection connection) {
      String header = connection.getHeaderField("Retry-After");
      if (header != null) {
         try {
            // Discord sends seconds, occasionally fractional.
            return Math.min(30_000L, (long) (Double.parseDouble(header.trim()) * 1000.0) + 250L);
         } catch (NumberFormatException notANumber) {
            // fall through to the default
         }
      }
      return 2000L;
   }

   private void drainErrorStream(HttpURLConnection connection) {
      // Reading the error body lets the JVM reuse the connection instead of leaking it.
      try (InputStream errors = connection.getErrorStream()) {
         if (errors != null) {
            errors.readAllBytes();
         }
      } catch (IOException ignored) {
         // best effort only
      }
   }

   private String buildBody(ShieldConfig current, Payload payload) {
      String displayIp = current.discordShowIp() ? payload.ip : "hidden";
      String title = Text.stripColors(current.discordTitle());

      Json.Writer json = new Json.Writer();
      json.beginObject()
            .field("username", Text.stripColors(current.discordUsername()))
            .name("embeds").beginArray()
            .beginObject()
            .field("title", payload.enforced ? title : title + " (dry run)")
            .field("color", current.discordColor())
            .field("timestamp", Instant.now().toString())
            .name("fields").beginArray()
            .beginObject()
            .field("name", "Player").field("value", payload.player).field("inline", true)
            .endObject()
            .beginObject()
            .field("name", "IP").field("value", displayIp).field("inline", true)
            .endObject()
            .beginObject()
            .field("name", "Country").field("value", payload.country).field("inline", true)
            .endObject()
            .beginObject()
            .field("name", "Reason").field("value", payload.reason).field("inline", true)
            .endObject()
            .beginObject()
            .field("name", "ISP").field("value", Text.clip(payload.isp, 200)).field("inline", true)
            .endObject()
            .beginObject()
            .field("name", "Action")
            .field("value", payload.enforced ? "Connection denied" : "Logged only (dry run)")
            .field("inline", true)
            .endObject()
            .endArray()
            .name("footer").beginObject()
            .field("text", "ProxyShield " + platform.version() + " on " + platform.name())
            .endObject()
            .endObject()
            .endArray()
            .endObject();
      return json.toString();
   }

   public long sentCount() {
      return sent.get();
   }

   public long droppedCount() {
      return dropped.get();
   }

   public int queueSize() {
      return queue.size();
   }

   private record Payload(String player, String ip, String reason, String country, String isp,
         boolean enforced) {
   }
}
