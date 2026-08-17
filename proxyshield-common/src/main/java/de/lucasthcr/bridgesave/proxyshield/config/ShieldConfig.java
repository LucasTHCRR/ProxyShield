package de.lucasthcr.bridgesave.proxyshield.config;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Typed, immutable snapshot of config.yml. Reloading builds a new instance and swaps it in. */
public final class ShieldConfig {

   public enum CountryMode {
      /** Listed countries are blocked, everything else is allowed. */
      BLACKLIST,
      /** Only listed countries are allowed, everything else is blocked. */
      WHITELIST;

      static CountryMode parse(String raw) {
         return "whitelist".equalsIgnoreCase(raw) ? WHITELIST : BLACKLIST;
      }
   }

   // settings
   private final String language;
   private final boolean failClosed;
   private final String bypassPermission;

   // detection
   private final boolean dryRun;
   private final boolean blockProxy;
   private final boolean blockHosting;
   private final boolean useLists;
   private final boolean useApi;
   private final boolean recheckOnline;

   // country
   private final boolean countryEnabled;
   private final CountryMode countryMode;
   private final Set<String> countryCodes;
   private final boolean blockUnknownCountry;

   // whitelist / blacklist
   private final List<String> whitelistIps;
   private final Set<String> whitelistPlayers;
   private final List<String> blacklistIps;

   // lists
   private final long listUpdateIntervalHours;
   private final int listTimeoutSeconds;
   private final boolean listDiskCache;
   private final List<String> listSources;

   // api
   private final String apiUrl;
   private final int apiTimeoutSeconds;
   private final long apiCacheMinutes;
   private final int apiMaxCacheEntries;
   private final int apiRateLimitPerMinute;

   // notifications
   private final boolean silent;
   private final boolean consoleAlerts;
   private final String notifyPermission;
   private final boolean logToFile;

   // discord
   private final boolean discordEnabled;
   private final String webhookUrl;
   private final boolean discordShowIp;
   private final String discordUsername;
   private final String discordTitle;
   private final int discordColor;

   private ShieldConfig(ConfigNode node) {
      this.language = node.getString("settings.language", "en");
      this.failClosed = node.getBoolean("settings.fail-closed", false);
      this.bypassPermission = node.getString("settings.bypass-permission", "proxyshield.bypass");

      this.dryRun = node.getBoolean("detection.dry-run", false);
      this.blockProxy = node.getBoolean("detection.block-proxy", true);
      this.blockHosting = node.getBoolean("detection.block-hosting", true);
      this.useLists = node.getBoolean("detection.use-lists", true);
      this.useApi = node.getBoolean("detection.use-api", true);
      this.recheckOnline = node.getBoolean("detection.recheck-online-on-reload", false);

      this.countryEnabled = node.getBoolean("country.enabled", false);
      this.countryMode = CountryMode.parse(node.getString("country.mode", "blacklist"));
      this.countryCodes = upperCaseSet(node.getStringList("country.codes"));
      this.blockUnknownCountry = node.getBoolean("country.block-unknown", false);

      this.whitelistIps = List.copyOf(node.getStringList("whitelist.ips"));
      this.whitelistPlayers = lowerCaseSet(node.getStringList("whitelist.players"));
      this.blacklistIps = List.copyOf(node.getStringList("blacklist.ips"));

      this.listUpdateIntervalHours = Math.max(1L, node.getLong("lists.update-interval-hours", 24L));
      this.listTimeoutSeconds = clamp(node.getInt("lists.timeout-seconds", 20), 1, 300);
      this.listDiskCache = node.getBoolean("lists.disk-cache", true);
      this.listSources = List.copyOf(node.getStringList("lists.sources"));

      this.apiUrl = node.getString("api.url",
            "http://ip-api.com/json/{ip}?fields=status,message,proxy,hosting,countryCode,country,isp");
      this.apiTimeoutSeconds = clamp(node.getInt("api.timeout-seconds", 5), 1, 60);
      this.apiCacheMinutes = Math.max(1L, node.getLong("api.cache-minutes", 360L));
      this.apiMaxCacheEntries = clamp(node.getInt("api.max-cache-entries", 10000), 100, 1000000);
      this.apiRateLimitPerMinute = clamp(node.getInt("api.rate-limit-per-minute", 45), 1, 10000);

      this.silent = node.getBoolean("notifications.silent", false);
      this.consoleAlerts = node.getBoolean("notifications.console", true);
      this.notifyPermission = node.getString("notifications.permission", "proxyshield.notify");
      this.logToFile = node.getBoolean("notifications.log-file", true);

      this.discordEnabled = node.getBoolean("discord.enabled", false);
      this.webhookUrl = node.getString("discord.webhook-url", "");
      this.discordShowIp = node.getBoolean("discord.show-ip", true);
      this.discordUsername = node.getString("discord.username", "ProxyShield");
      this.discordTitle = node.getString("discord.title", "ProxyShield Alert");
      this.discordColor = node.getInt("discord.color", 0xFF0000);
   }

   public static ShieldConfig from(ConfigNode node) {
      return new ShieldConfig(node);
   }

   private static int clamp(int value, int min, int max) {
      return Math.max(min, Math.min(max, value));
   }

   private static Set<String> upperCaseSet(List<String> values) {
      Set<String> out = new LinkedHashSet<>();
      for (String value : values) {
         if (value != null && !value.isBlank()) {
            out.add(value.trim().toUpperCase(Locale.ROOT));
         }
      }
      return Set.copyOf(out);
   }

   private static Set<String> lowerCaseSet(List<String> values) {
      Set<String> out = new LinkedHashSet<>();
      for (String value : values) {
         if (value != null && !value.isBlank()) {
            out.add(value.trim().toLowerCase(Locale.ROOT));
         }
      }
      return Set.copyOf(out);
   }

   /** Sources with blank entries removed. */
   public List<String> activeListSources() {
      List<String> out = new ArrayList<>(listSources.size());
      for (String source : listSources) {
         if (source != null && !source.isBlank()) {
            out.add(source.trim());
         }
      }
      return out;
   }

   public boolean discordUsable() {
      return discordEnabled && webhookUrl != null && webhookUrl.startsWith("https://");
   }

   /** Message file to load, e.g. "en" for messages_en.yml. */
   public String language() {
      return language;
   }

   public boolean failClosed() {
      return failClosed;
   }

   public String bypassPermission() {
      return bypassPermission;
   }

   public boolean dryRun() {
      return dryRun;
   }

   public boolean blockProxy() {
      return blockProxy;
   }

   public boolean blockHosting() {
      return blockHosting;
   }

   public boolean useLists() {
      return useLists;
   }

   public boolean useApi() {
      return useApi;
   }

   public boolean recheckOnline() {
      return recheckOnline;
   }

   public boolean countryEnabled() {
      return countryEnabled;
   }

   public CountryMode countryMode() {
      return countryMode;
   }

   public Set<String> countryCodes() {
      return countryCodes;
   }

   public boolean blockUnknownCountry() {
      return blockUnknownCountry;
   }

   public List<String> whitelistIps() {
      return whitelistIps;
   }

   public Set<String> whitelistPlayers() {
      return whitelistPlayers;
   }

   public List<String> blacklistIps() {
      return blacklistIps;
   }

   public long listUpdateIntervalHours() {
      return listUpdateIntervalHours;
   }

   public int listTimeoutSeconds() {
      return listTimeoutSeconds;
   }

   public boolean listDiskCache() {
      return listDiskCache;
   }

   public String apiUrl() {
      return apiUrl;
   }

   public int apiTimeoutSeconds() {
      return apiTimeoutSeconds;
   }

   public long apiCacheMinutes() {
      return apiCacheMinutes;
   }

   public int apiMaxCacheEntries() {
      return apiMaxCacheEntries;
   }

   public int apiRateLimitPerMinute() {
      return apiRateLimitPerMinute;
   }

   public boolean silent() {
      return silent;
   }

   public boolean consoleAlerts() {
      return consoleAlerts;
   }

   public String notifyPermission() {
      return notifyPermission;
   }

   public boolean logToFile() {
      return logToFile;
   }

   public boolean discordEnabled() {
      return discordEnabled;
   }

   public String webhookUrl() {
      return webhookUrl;
   }

   public boolean discordShowIp() {
      return discordShowIp;
   }

   public String discordUsername() {
      return discordUsername;
   }

   public String discordTitle() {
      return discordTitle;
   }

   public int discordColor() {
      return discordColor;
   }
}
