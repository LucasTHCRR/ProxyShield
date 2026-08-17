package de.lucasthcr.bridgesave.proxyshield.notify;

import de.lucasthcr.bridgesave.proxyshield.check.CheckVerdict;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.message.Messages;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import de.lucasthcr.bridgesave.proxyshield.platform.ShieldPlayer;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Fans a block out to every enabled notification channel.
 * <p>
 * Silent mode suppresses the two channels players and admins see live, the staff broadcast and the
 * console line, while the log file and the Discord webhook keep recording. That way a server can
 * watch for false positives without advertising to everyone online that the filter fired.
 */
public final class AlertDispatcher {

   private static final DateTimeFormatter TIMESTAMP =
         DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

   private final Platform platform;
   private final DiscordWebhook webhook;
   private final Path logFile;
   private final ReentrantLock logLock = new ReentrantLock();

   private volatile ShieldConfig config;
   private volatile Messages messages;
   private volatile boolean logFileBroken;

   public AlertDispatcher(Platform platform, ShieldConfig config, Messages messages,
         DiscordWebhook webhook) {
      this.platform = platform;
      this.config = config;
      this.messages = messages;
      this.webhook = webhook;
      this.logFile = platform.dataFolder().resolve("blocks.log");
   }

   public void applyConfig(ShieldConfig config, Messages messages) {
      this.config = config;
      this.messages = messages;
      this.logFileBroken = false;
   }

   /**
    * Reports one detection.
    *
    * @param enforced {@code false} when dry-run mode kept the player connected
    */
   public void alert(String player, String ip, CheckVerdict verdict, boolean enforced) {
      ShieldConfig current = config;
      String message = messages.get(enforced ? "alert" : "alert-dry-run",
            placeholders(player, ip, verdict, enforced));

      if (!current.silent()) {
         broadcastToStaff(current, message);
         if (current.consoleAlerts()) {
            platform.sendConsole(message);
         }
      }

      if (current.logToFile()) {
         appendToLog(player, ip, verdict, enforced);
      }

      webhook.enqueue(player, ip, verdict, enforced);
   }

   private Map<String, String> placeholders(String player, String ip, CheckVerdict verdict,
         boolean enforced) {
      Map<String, String> values = new LinkedHashMap<>();
      values.put("player", player == null ? "unknown" : player);
      values.put("ip", ip == null ? "unknown" : ip);
      values.put("reason", verdict.describe());
      values.put("country", verdict.lookup().countryOrUnknown());
      values.put("isp", verdict.lookup().ispOrUnknown());
      values.put("action", enforced ? "blocked" : "dry-run");
      values.put("platform", platform.name());
      return values;
   }

   private void broadcastToStaff(ShieldConfig current, String message) {
      String permission = current.notifyPermission();
      for (ShieldPlayer online : platform.onlinePlayers()) {
         if (online.hasPermission(permission)) {
            online.sendMessage(message);
         }
      }
   }

   private void appendToLog(String player, String ip, CheckVerdict verdict, boolean enforced) {
      if (logFileBroken) {
         return;
      }

      String line = LocalDateTime.now().format(TIMESTAMP)
            + " | " + (enforced ? "BLOCKED" : "DRY-RUN")
            + " | " + (player == null ? "unknown" : player)
            + " | " + (ip == null ? "unknown" : ip)
            + " | " + verdict.lookup().countryOrUnknown()
            + " | " + verdict.describe()
            + " | " + verdict.lookup().ispOrUnknown()
            + System.lineSeparator();

      logLock.lock();
      try {
         Path parent = logFile.getParent();
         if (parent != null) {
            Files.createDirectories(parent);
         }
         Files.writeString(logFile, line, StandardCharsets.UTF_8,
               StandardOpenOption.CREATE, StandardOpenOption.APPEND);
      } catch (IOException failure) {
         // Report once, then stop trying so a full disk does not spam the console per login.
         logFileBroken = true;
         platform.warn("Could not write blocks.log, disabling file logging until the next reload: "
               + failure.getMessage());
      } finally {
         logLock.unlock();
      }
   }

   public Path logFile() {
      return logFile;
   }
}
