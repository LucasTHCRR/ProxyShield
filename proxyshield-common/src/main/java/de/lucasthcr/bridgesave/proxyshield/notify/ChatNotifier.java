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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Sends block alerts as plain chat messages to Telegram and VK.
 * <p>
 * Same delivery model as {@link DiscordWebhook}: one bounded queue, one async worker, so a login
 * flood turns into a short backlog rather than a burst of parallel requests. Both services answer
 * HTTP 200 for some failures and put the error in the body, so the body is read and checked.
 */
public final class ChatNotifier {

   private static final int MAX_QUEUE = 100;
   private static final int TIMEOUT_MILLIS = 5000;

   /** Where a message goes. */
   enum Target {
      TELEGRAM, VK
   }

   private record Message(Target target, String text) {
   }

   private final Platform platform;
   private final Queue<Message> queue = new ConcurrentLinkedQueue<>();
   private final AtomicBoolean draining = new AtomicBoolean();
   private final AtomicLong sent = new AtomicLong();
   private final AtomicLong dropped = new AtomicLong();

   private volatile ShieldConfig config;

   public ChatNotifier(Platform platform, ShieldConfig config) {
      this.platform = platform;
      this.config = config;
   }

   public void applyConfig(ShieldConfig config) {
      this.config = config;
   }

   /** Queues the alert for every chat service that is switched on. */
   public void enqueue(String player, String ip, CheckVerdict verdict, boolean enforced) {
      ShieldConfig current = config;
      if (current.telegramUsable()) {
         offer(new Message(Target.TELEGRAM, render(current.telegramMessage(), player, ip,
               verdict, enforced, current.telegramShowIp())));
      }
      if (current.vkUsable()) {
         offer(new Message(Target.VK, render(current.vkMessage(), player, ip, verdict, enforced,
               current.vkShowIp())));
      }
   }

   private void offer(Message message) {
      if (queue.size() >= MAX_QUEUE) {
         dropped.incrementAndGet();
         return;
      }
      queue.add(message);
      drain();
   }

   static String render(String template, String player, String ip, CheckVerdict verdict,
         boolean enforced, boolean showIp) {
      Map<String, String> values = new LinkedHashMap<>();
      values.put("player", player == null ? "unknown" : player);
      values.put("ip", !showIp ? "hidden" : ip == null ? "unknown" : ip);
      values.put("reason", verdict.describe());
      values.put("country", verdict.lookup().countryOrUnknown());
      values.put("isp", verdict.lookup().ispOrUnknown());
      values.put("asn", verdict.lookup().asnOrUnknown());
      values.put("score", String.format(Locale.ROOT, "%.1f", verdict.lookup().confidence()));
      values.put("sources", verdict.lookup().sourceSummary());
      values.put("action", enforced ? "blocked" : "dry-run");
      String out = template;
      for (Map.Entry<String, String> value : values.entrySet()) {
         out = out.replace("{" + value.getKey() + "}", value.getValue());
      }
      return out.replace("\\n", "\n");
   }

   private void drain() {
      if (!draining.compareAndSet(false, true)) {
         return;
      }
      platform.runAsync(() -> {
         try {
            Message message;
            while ((message = queue.poll()) != null) {
               deliver(message);
            }
         } finally {
            draining.set(false);
            if (!queue.isEmpty()) {
               drain();
            }
         }
      });
   }

   private void deliver(Message message) {
      ShieldConfig current = config;
      try {
         String error = switch (message.target()) {
            case TELEGRAM -> sendTelegram(current, message.text());
            case VK -> sendVk(current, message.text());
         };
         if (error == null) {
            sent.incrementAndGet();
         } else {
            dropped.incrementAndGet();
            platform.warn(message.target().name().charAt(0)
                  + message.target().name().substring(1).toLowerCase(Locale.ROOT)
                  + " alert failed: " + error);
         }
      } catch (IOException | RuntimeException failure) {
         dropped.incrementAndGet();
         platform.warn("Could not deliver a " + message.target().name().toLowerCase(Locale.ROOT)
               + " alert: " + failure.getMessage());
      }
   }

   /** @return {@code null} on success, otherwise what went wrong */
   private String sendTelegram(ShieldConfig current, String text) throws IOException {
      Json.Writer body = new Json.Writer().beginObject()
            .field("chat_id", current.telegramChatId())
            .field("text", text)
            .field("disable_web_page_preview", true);
      if (current.telegramThreadId() > 0L) {
         body.field("message_thread_id", current.telegramThreadId());
      }
      body.endObject();
      String url = "https://api.telegram.org/bot" + current.telegramToken() + "/sendMessage";
      Response response = post(url, "application/json", body.toString());
      Object parsed = parseQuietly(response.body());
      if (response.status() >= 200 && response.status() < 300 && Json.boolAt(parsed, "ok")) {
         return null;
      }
      String description = Json.stringAt(parsed, "description");
      return "HTTP " + response.status() + (description == null ? "" : ", " + description);
   }

   /** @return {@code null} on success, otherwise what went wrong */
   private String sendVk(ShieldConfig current, String text) throws IOException {
      String form = "peer_id=" + current.vkPeerId()
            + "&random_id=" + ThreadLocalRandom.current().nextInt(Integer.MAX_VALUE)
            + "&message=" + encode(text)
            + "&access_token=" + encode(current.vkToken())
            + "&v=" + encode(current.vkApiVersion());
      Response response = post("https://api.vk.com/method/messages.send",
            "application/x-www-form-urlencoded", form);
      Object parsed = parseQuietly(response.body());
      String error = Json.stringAt(parsed, "error.error_msg");
      if (response.status() >= 200 && response.status() < 300 && error == null) {
         return null;
      }
      return "HTTP " + response.status() + (error == null ? "" : ", " + error);
   }

   private static String encode(String value) {
      return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
   }

   private static Object parseQuietly(String body) {
      try {
         return Json.parse(body);
      } catch (RuntimeException notJson) {
         return Map.of();
      }
   }

   private record Response(int status, String body) {
   }

   private Response post(String endpoint, String contentType, String body) throws IOException {
      HttpURLConnection connection =
            (HttpURLConnection) URI.create(endpoint).toURL().openConnection();
      try {
         connection.setRequestMethod("POST");
         connection.setRequestProperty("Content-Type", contentType + "; charset=utf-8");
         connection.setRequestProperty("User-Agent", "ProxyShield/" + platform.version());
         connection.setConnectTimeout(TIMEOUT_MILLIS);
         connection.setReadTimeout(TIMEOUT_MILLIS);
         connection.setDoOutput(true);
         try (OutputStream out = connection.getOutputStream()) {
            out.write(body.getBytes(StandardCharsets.UTF_8));
         }
         int status = connection.getResponseCode();
         InputStream stream = status >= 400 ? connection.getErrorStream()
               : connection.getInputStream();
         String text = "";
         if (stream != null) {
            try (InputStream in = stream) {
               text = new String(in.readNBytes(64 * 1024), StandardCharsets.UTF_8);
            }
         }
         return new Response(status, text);
      } finally {
         connection.disconnect();
      }
   }

   public long sentCount() {
      return sent.get();
   }

   public long droppedCount() {
      return dropped.get();
   }
}
