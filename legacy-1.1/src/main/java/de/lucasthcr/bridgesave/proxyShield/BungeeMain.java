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

package de.lucasthcr.bridgesave.proxyShield;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import net.md_5.bungee.api.chat.BaseComponent;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.event.LoginEvent;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.config.Configuration;
import net.md_5.bungee.config.ConfigurationProvider;
import net.md_5.bungee.config.YamlConfiguration;
import net.md_5.bungee.event.EventHandler;

public class BungeeMain extends Plugin implements Listener {

   private final Set<String> vpnList = ConcurrentHashMap.newKeySet();
   private final Map<String, Boolean> apiCache = new ConcurrentHashMap<>();
   private Configuration config;

   @Override
   public void onEnable() {
      loadConfig();
      getProxy().getScheduler().runAsync(this, this::loadLists);
      getProxy().getPluginManager().registerListener(this, this);

      int h = config.getInt("settings.update-interval-hours", 24);
      getProxy().getScheduler().schedule(this, this::loadLists, h, h, TimeUnit.HOURS);
   }

   private void loadConfig() {
      try {
         if (!getDataFolder().exists()) {
            getDataFolder().mkdir();
         }

         File f = new File(getDataFolder(), "config.yml");
         if (!f.exists()) {
            try (InputStream in = getResourceAsStream("config.yml")) {
               Files.copy(in, f.toPath());
            }
         }

         config = ConfigurationProvider.getProvider(YamlConfiguration.class).load(f);
      } catch (IOException e) {
         e.printStackTrace();
      }
   }

   private void loadLists() {
      vpnList.clear();

      for (String s : config.getStringList("sources")) {
         try (BufferedReader r = new BufferedReader(new InputStreamReader(new URL(s).openStream()))) {
            r.lines()
                  .filter(l -> !l.startsWith("#") && !l.isEmpty())
                  .forEach(l -> vpnList.add(l.split(" ")[0].split("/")[0]));
         } catch (Exception ignored) {
         }
      }
   }

   @EventHandler
   public void onLogin(LoginEvent e) {
      String name = e.getConnection().getName();
      String ip = e.getConnection().getAddress().getAddress().getHostAddress();

      ProxiedPlayer p = getProxy().getPlayer(e.getConnection().getUniqueId());
      if (p != null && p.hasPermission("proxyshield.bypass")) {
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

   private void reject(LoginEvent e, String name, String ip) {
      e.setCancelReason(new BaseComponent[]{new TextComponent(color(config.getString("settings.kick-message")))});
      e.setCancelled(true);
      sendNotify(name, ip);
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
      String m = color("&8[&cShield&8] &e" + name + " &7blocked. &8(&f" + ip + "&8)");
      getProxy().getPlayers().stream()
            .filter(pl -> pl.hasPermission("proxyshield.notify"))
            .forEach(pl -> pl.sendMessage(new TextComponent(m)));

      if (config.getBoolean("discord.enabled")) {
         sendWebhook(name, ip);
      }
   }

   private void sendWebhook(String name, String ip) {
      getProxy().getScheduler().runAsync(this, () -> {
         try {
            URL u = new URL(config.getString("discord.webhook-url"));
            HttpURLConnection c = (HttpURLConnection) u.openConnection();
            c.setRequestMethod("POST");
            c.setRequestProperty("Content-Type", "application/json");
            c.setDoOutput(true);

            String dip = config.getBoolean("discord.show-ip") ? ip : "HIDDEN";
            String json = "{\"embeds\":[{\"title\":\""
                  + config.getString("discord.message-title")
                  + "\",\"color\":16711680,\"fields\":[{\"name\":\"Player\",\"value\":\""
                  + name
                  + "\",\"inline\":true},{\"name\":\"IP\",\"value\":\""
                  + dip
                  + "\",\"inline\":true}]}]}";

            try (OutputStream os = c.getOutputStream()) {
               os.write(json.getBytes(StandardCharsets.UTF_8));
            }

            c.getResponseCode();
         } catch (Exception ignored) {
         }
      });
   }

   private String color(String s) {
      return s.replace("&", "§");
   }
}
