package de.lucasthcr.bridgesave.proxyShield;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.OfflinePlayer;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.plugin.java.JavaPlugin;

public final class PaperMain extends JavaPlugin implements Listener {

   private static final long TICKS_PER_HOUR = 72000L;

   private final Set<String> vpnList = ConcurrentHashMap.newKeySet();
   private final Map<String, Boolean> apiCache = new ConcurrentHashMap<>();

   @Override
   public void onEnable() {
      saveDefaultConfig();
      Bukkit.getScheduler().runTaskAsynchronously(this, this::loadLists);
      getServer().getPluginManager().registerEvents(this, this);

      long hours = getConfig().getLong("settings.update-interval-hours", 24L);
      Bukkit.getScheduler().runTaskTimerAsynchronously(
            this, this::loadLists, hours * TICKS_PER_HOUR, hours * TICKS_PER_HOUR);
   }

   private void loadLists() {
      vpnList.clear();

      for (String urlStr : getConfig().getStringList("sources")) {
         try (BufferedReader r = new BufferedReader(new InputStreamReader(new URL(urlStr).openStream()))) {
            r.lines()
                  .filter(l -> !l.startsWith("#") && !l.isEmpty())
                  .forEach(l -> vpnList.add(l.split(" ")[0].split("/")[0]));
         } catch (Exception ignored) {
         }
      }
   }

   @EventHandler
   public void onPreLogin(AsyncPlayerPreLoginEvent e) {
      String ip = e.getAddress().getHostAddress();
      String name = e.getName();
      UUID uuid = e.getUniqueId();

      if (getConfig().getStringList("whitelist").contains(ip)) {
         return;
      }

      OfflinePlayer offline = Bukkit.getOfflinePlayer(uuid);
      if (offline.isOp()) {
         return;
      }

      Player online = offline.getPlayer();
      if (online != null && online.hasPermission("proxyshield.bypass")) {
         return;
      }

      if (vpnList.contains(ip) || apiCache.getOrDefault(ip, false)) {
         reject(e, name, ip);
         return;
      }

      if (apiCache.containsKey(ip)) {
         return;
      }

      if (checkApi(ip)) {
         apiCache.put(ip, true);
         reject(e, name, ip);
      } else {
         apiCache.put(ip, false);
      }
   }

   private void reject(AsyncPlayerPreLoginEvent e, String name, String ip) {
      e.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, color(getConfig().getString("settings.kick-message")));
      sendNotify(name, ip);
   }

   private boolean checkApi(String ip) {
      try {
         URL url = new URL("http://ip-api.com/json/" + ip + "?fields=proxy,hosting");
         try (BufferedReader r = new BufferedReader(new InputStreamReader(url.openStream()))) {
            String line = r.readLine();
            return line != null && line.contains("true");
         }
      } catch (Exception ignored) {
         return false;
      }
   }

   private void sendNotify(String name, String ip) {
      String msg = color("&8[&cProxyShield&8] &e" + name + " &7blocked. &8(&f" + ip + "&8)");
      Bukkit.getConsoleSender().sendMessage(msg);

      for (Player p : Bukkit.getOnlinePlayers()) {
         if (p.hasPermission("proxyshield.notify")) {
            p.sendMessage(msg);
         }
      }

      if (getConfig().getBoolean("discord.enabled")) {
         sendWebhook(name, ip);
      }
   }

   private void sendWebhook(String name, String ip) {
      Bukkit.getScheduler().runTaskAsynchronously(this, () -> {
         try {
            URL url = new URL(getConfig().getString("discord.webhook-url"));
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/json");
            con.setDoOutput(true);

            String displayIp = getConfig().getBoolean("discord.show-ip") ? ip : "HIDDEN";
            String json = "{\"embeds\":[{\"title\":\""
                  + getConfig().getString("discord.message-title")
                  + "\",\"color\":16711680,\"fields\":[{\"name\":\"Player\",\"value\":\""
                  + name
                  + "\",\"inline\":true},{\"name\":\"IP\",\"value\":\""
                  + displayIp
                  + "\",\"inline\":true}],\"footer\":{\"text\":\"v1.1 by LucasTHCR\"}}]}";

            try (OutputStream os = con.getOutputStream()) {
               os.write(json.getBytes(StandardCharsets.UTF_8));
            }

            con.getResponseCode();
         } catch (Exception ignored) {
         }
      });
   }

   private String color(String s) {
      return ChatColor.translateAlternateColorCodes('&', s);
   }
}
