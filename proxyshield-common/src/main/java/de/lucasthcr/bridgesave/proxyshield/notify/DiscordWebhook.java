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
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Queue;
import java.util.UUID;
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
   public void enqueue(String player, UUID uuid, String ip, CheckVerdict verdict,
         boolean enforced) {
      ShieldConfig current = config;
      if (!current.discordUsable()) {
         return;
      }

      if (queue.size() >= MAX_QUEUE) {
         dropped.incrementAndGet();
         return;
      }

      queue.add(new Payload(player, uuid, ip, verdict.describe(),
            verdict.lookup().countryOrUnknown(), verdict.lookup().ispOrUnknown(),
            verdict.lookup().asnOrUnknown(), verdict.lookup().confidence(),
            verdict.lookup().sourceSummary(), enforced));
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
            connection.setRequestProperty("User-Agent", "ProxyShield/" + platform.version());
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

   String buildBody(ShieldConfig current, Payload payload) {
      EmbedTemplate template = current.discordEmbed();
      Map<String, String> values = placeholders(current, payload);

      Json.Writer json = new Json.Writer();
      json.beginObject();

      // Discord rejects the whole request with HTTP 400 when a string it does expect to be filled
      // arrives empty, so an option left blank has to be left out rather than sent as "". Omitting
      // the name falls back to whatever the webhook itself is called, which is what a blank value
      // was meant to express in the first place.
      String username = Text.stripColors(current.discordUsername());
      if (!username.isBlank()) {
         json.field("username", Text.clip(username, 80));
      }

      json.name("embeds").beginArray().beginObject();

      String title = titleFor(template, values, payload);
      if (!title.isBlank()) {
         json.field("title", Text.clip(title, 256));
      }

      String description = fill(template.description(), values);
      if (!description.isBlank()) {
         json.field("description", Text.clip(description, 4096));
      }

      json.field("color", current.discordColor())
            .field("timestamp", Instant.now().toString());

      // Only https, the same rule the webhook URL itself is held to: a http image would be
      // requested by Discord over plain text from every viewer's client.
      String thumbnail = fill(template.thumbnail(), values).trim();
      if (thumbnail.startsWith("https://")) {
         json.name("thumbnail").beginObject().field("url", thumbnail).endObject();
      }

      if (!template.fields().isEmpty()) {
         json.name("fields").beginArray();
         for (EmbedTemplate.Field field : template.fields()) {
            String value = fill(field.value(), values);
            if (value.isBlank()) {
               // An empty field value is refused the same way an empty title is, and dropping the
               // box is friendlier than losing the whole alert to a 400.
               continue;
            }
            json.beginObject()
                  .field("name", Text.clip(field.name(), 256))
                  .field("value", Text.clip(value, 1024))
                  .field("inline", field.inline())
                  .endObject();
         }
         json.endArray();
      }

      String footer = fill(template.footer(), values);
      if (!footer.isBlank()) {
         json.name("footer").beginObject().field("text", Text.clip(footer, 2048)).endObject();
      }

      json.endObject().endArray().endObject();
      return json.toString();
   }

   /**
    * The heading, with the dry-run marker appended unless the layout already says something about
    * it. A blank title stays blank, which leaves the embed without a heading rather than sending
    * the empty string Discord refuses.
    */
   private static String titleFor(EmbedTemplate template, Map<String, String> values,
         Payload payload) {
      String title = Text.stripColors(fill(template.title(), values)).trim();
      if (payload.enforced) {
         return title;
      }
      if (title.toLowerCase(Locale.ROOT).contains("dry run")) {
         return title;
      }
      return title.isEmpty() ? "Dry run" : title + " (dry run)";
   }

   private Map<String, String> placeholders(ShieldConfig current, Payload payload) {
      Map<String, String> values = new LinkedHashMap<>();
      values.put("player", present(payload.player));
      values.put("uuid", payload.uuid == null ? "unknown" : payload.uuid.toString());
      values.put("ip", current.discordShowIp() ? present(payload.ip) : "hidden");
      values.put("reason", present(payload.reason));
      values.put("country", present(payload.country));
      values.put("isp", Text.clip(present(payload.isp), 200));
      values.put("asn", present(payload.asn));
      values.put("score", String.format(Locale.ROOT, "%.2f", payload.score));
      values.put("sources", present(payload.sources));
      values.put("action", payload.enforced ? "Connection denied" : "Logged only (dry run)");
      values.put("action_id", payload.enforced ? "kicked" : "allowed");
      values.put("platform", platform.name());
      values.put("version", platform.version());
      return values;
   }

   /**
    * Substitutes {@code {key}} placeholders into one template string.
    * <p>
    * Values go in exactly as written, because whether a name belongs in a code span is a layout
    * decision and the operator owns the layout. Backticks coming from a provider are dropped so a
    * hostile ISP string cannot close a code span the template opened.
    */
   private static String fill(String template, Map<String, String> values) {
      if (template == null || template.isEmpty()) {
         return "";
      }
      String result = template;
      for (Map.Entry<String, String> entry : values.entrySet()) {
         String token = "{" + entry.getKey() + "}";
         if (result.contains(token)) {
            result = result.replace(token, entry.getValue().replace("`", ""));
         }
      }
      return result;
   }

   /** A value Discord will accept, since an empty one is refused the same way an empty title is. */
   private static String present(String value) {
      return value == null || value.isBlank() ? "unknown" : value;
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

   record Payload(String player, UUID uuid, String ip, String reason, String country, String isp,
         String asn, double score, String sources, boolean enforced) {
   }
}
