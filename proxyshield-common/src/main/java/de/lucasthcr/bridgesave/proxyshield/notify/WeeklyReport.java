package de.lucasthcr.bridgesave.proxyshield.notify;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;

// Zaehlt Pruefungen ueber Neustarts hinweg und schickt einmal pro Woche eine Zusammenfassung
public final class WeeklyReport {

   private static final long WEEK_MILLIS = 7L * 24 * 3_600_000L;

   private final Path file;
   private long start;
   private long checked;
   private long blocked;
   private long lastChecked;
   private long lastBlocked;

   public WeeklyReport(Path file) {
      this.file = file;
      Properties saved = new Properties();
      try (var in = Files.newInputStream(file)) {
         saved.load(in);
      } catch (IOException missing) {
         // Erster Start: Woche beginnt jetzt
      }
      start = Long.parseLong(saved.getProperty("start", String.valueOf(System.currentTimeMillis())));
      checked = Long.parseLong(saved.getProperty("checked", "0"));
      blocked = Long.parseLong(saved.getProperty("blocked", "0"));
   }

   public void add(long checkedTotal, long blockedTotal) {
      checked += Math.max(0, checkedTotal - lastChecked);
      blocked += Math.max(0, blockedTotal - lastBlocked);
      lastChecked = checkedTotal;
      lastBlocked = blockedTotal;
      save();
   }

   public boolean due() {
      return System.currentTimeMillis() - start >= WEEK_MILLIS;
   }

   public boolean send(String webhookUrl, String version, List<String> failingProviders) {
      String failing = failingProviders.isEmpty() ? "none" : String.join(", ", failingProviders);
      String text = "**ProxyShield weekly report**\\n"
            + "Joins checked: **" + checked + "**\\n"
            + "Refused: **" + blocked + "**\\n"
            + "Providers with failures: " + escape(failing);
      String body = "{\"username\":\"ProxyShield\",\"content\":\"" + text + "\"}";
      try {
         HttpURLConnection connection = (HttpURLConnection) URI.create(webhookUrl).toURL().openConnection();
         connection.setRequestMethod("POST");
         connection.setRequestProperty("Content-Type", "application/json");
         connection.setRequestProperty("User-Agent", "ProxyShield/" + version);
         connection.setConnectTimeout(5000);
         connection.setReadTimeout(5000);
         connection.setDoOutput(true);
         try (OutputStream out = connection.getOutputStream()) {
            out.write(body.getBytes(StandardCharsets.UTF_8));
         }
         int status = connection.getResponseCode();
         connection.disconnect();
         if (status / 100 != 2) {
            return false;
         }
      } catch (IOException | IllegalArgumentException failed) {
         return false;
      }
      start = System.currentTimeMillis();
      checked = 0;
      blocked = 0;
      save();
      return true;
   }

   private static String escape(String text) {
      return text.replace("\\", "\\\\").replace("\"", "\\\"");
   }

   private void save() {
      Properties out = new Properties();
      out.setProperty("start", String.valueOf(start));
      out.setProperty("checked", String.valueOf(checked));
      out.setProperty("blocked", String.valueOf(blocked));
      try (var stream = Files.newOutputStream(file)) {
         out.store(stream, "ProxyShield weekly report");
      } catch (IOException ignored) {
         // Nur Statistik, beim naechsten Mal wieder versuchen
      }
   }
}
