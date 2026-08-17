package de.lucasthcr.bridgesave.proxyShield;

import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;

@Plugin(
      id = "proxyshield",
      name = "ProxyShield",
      version = "1.1",
      authors = {"LucasTHCR"},
      url = "https://dc.gg/лукас"
)
public class VelocityMain {

   private final ProxyServer server;
   private final Path dataDirectory;
   private final Set<String> vpnList = ConcurrentHashMap.newKeySet();
   private final Map<String, Boolean> apiCache = new ConcurrentHashMap<>();
   private final Properties props = new Properties();

   @Inject
   public VelocityMain(ProxyServer server, @DataDirectory Path dataDirectory) {
      this.server = server;
      this.dataDirectory = dataDirectory;
   }

   @Subscribe
   public void onInit(ProxyInitializeEvent event) {
      setupConfig();
      loadLists();
      server.getScheduler().buildTask(this, this::loadLists).repeat(24L, TimeUnit.HOURS).schedule();
   }

   private void setupConfig() {
      try {
         if (!Files.exists(dataDirectory)) {
            Files.createDirectories(dataDirectory);
         }

         File file = new File(dataDirectory.toFile(), "config.properties");
         if (!file.exists()) {
            try (PrintWriter w = new PrintWriter(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8))) {
               w.println("kick-message=&c&lProxyShield &8» &7VPNs are not allowed!");
               w.println("vpn-source=https://raw.githubusercontent.com/X4BNet/lists_vpn/main/ipv4.txt");
               w.println("discord-enabled=false");
               w.println("discord-webhook=");
               w.println("discord-show-ip=true");
               w.println("discord-title=🛡️ ProxyShield Alert");
            }
         }

         try (InputStream is = new FileInputStream(file)) {
            props.load(new InputStreamReader(is, StandardCharsets.UTF_8));
         }
      } catch (IOException e) {
         e.printStackTrace();
      }
   }

   private void loadLists() {
      vpnList.clear();

      try (BufferedReader r = new BufferedReader(new InputStreamReader(new URL(props.getProperty("vpn-source")).openStream()))) {
         r.lines()
               .filter(l -> !l.startsWith("#") && !l.isEmpty())
               .forEach(l -> vpnList.add(l.split(" ")[0].split("/")[0]));
      } catch (Exception ignored) {
      }
   }

   @Subscribe
   public void onPostLogin(PostLoginEvent event) {
      Player player = event.getPlayer();
      if (player.hasPermission("proxyshield.bypass")) {
         return;
      }

      String ip = player.getRemoteAddress().getAddress().getHostAddress();
      if (vpnList.contains(ip) || apiCache.getOrDefault(ip, false)) {
         kick(player, ip);
         return;
      }

      if (apiCache.containsKey(ip)) {
         return;
      }

      server.getScheduler().buildTask(this, () -> {
         if (checkApi(ip)) {
            apiCache.put(ip, true);
            kick(player, ip);
         } else {
            apiCache.put(ip, false);
         }
      }).schedule();
   }

   private void kick(Player player, String ip) {
      player.disconnect(format(props.getProperty("kick-message")));
      sendNotify(player.getUsername(), ip);
   }

   private boolean checkApi(String ip) {
      try {
         URL url = new URL("http://ip-api.com/json/" + ip + "?fields=proxy,hosting");
         try (BufferedReader r = new BufferedReader(new InputStreamReader(url.openStream()))) {
            return r.readLine().contains("true");
         }
      } catch (Exception ignored) {
         return false;
      }
   }

   private void sendNotify(String name, String ip) {
      Component msg = format("&8[&cShield&8] &e" + name + " &7blocked. &8(&f" + ip + "&8)");
      server.getAllPlayers().stream()
            .filter(p -> p.hasPermission("proxyshield.notify"))
            .forEach(p -> p.sendMessage(msg));

      if (props.getProperty("discord-enabled").equals("true")) {
         executeWebhook(name, ip);
      }
   }

   private void executeWebhook(String name, String ip) {
      server.getScheduler().buildTask(this, () -> {
         try {
            URL url = new URL(props.getProperty("discord-webhook"));
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/json");
            con.setDoOutput(true);

            String displayIp = props.getProperty("discord-show-ip").equals("true") ? ip : "HIDDEN";
            String json = "{\"embeds\":[{\"title\":\""
                  + props.getProperty("discord-title")
                  + "\",\"color\":16711680,\"fields\":[{\"name\":\"Player\",\"value\":\""
                  + name
                  + "\",\"inline\":true},{\"name\":\"IP\",\"value\":\""
                  + displayIp
                  + "\",\"inline\":true}]}]}";

            try (OutputStream os = con.getOutputStream()) {
               os.write(json.getBytes(StandardCharsets.UTF_8));
            }

            con.getResponseCode();
         } catch (Exception ignored) {
         }
      }).schedule();
   }

   private Component format(String s) {
      return LegacyComponentSerializer.legacyAmpersand().deserialize(s);
   }
}
