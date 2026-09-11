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

package de.lucasthcr.bridgesave.proxyshield.config;

import de.lucasthcr.bridgesave.proxyshield.lookup.ProviderCatalog;
import de.lucasthcr.bridgesave.proxyshield.lookup.ProviderDefinition;
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

   /** How the answers of several providers are combined. */
   public enum LookupMode {
      /**
       * Ask providers in order, first answer wins. Cheapest, but a service that has never heard of
       * a given VPN clears the address before anything else gets asked.
       */
      FAILOVER,
      /**
       * Ask several providers at once and block once the weight of those flagging the address
       * reaches {@code api.required-score}. Catches the newer commercial VPNs that any single free
       * dataset misses, and stops early as soon as the threshold is met.
       */
      CONSENSUS;

      static LookupMode parse(String raw) {
         return "failover".equalsIgnoreCase(raw) ? FAILOVER : CONSENSUS;
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
   private final boolean exemptBedrock;

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
   private final List<String> apiProviders;
   private final List<ProviderDefinition> providers;
   private final LookupMode lookupMode;
   private final double requiredScore;
   private final int apiTimeoutSeconds;
   private final int apiTotalTimeoutSeconds;
   private final int apiMaxParallel;
   private final long apiCacheMinutes;
   private final long apiFlaggedCacheMinutes;
   private final int apiMaxCacheEntries;
   private final int apiRateLimitPerMinute;
   private final boolean apiPersistCache;

   // detection extras
   private final boolean blockTor;
   private final boolean allowResidentialHosting;
   private final boolean asnEnabled;
   private final Set<String> blockedAsns;
   private final Set<String> allowedAsns;
   private final boolean rdnsEnabled;
   private final List<String> rdnsPatterns;
   private final double rdnsWeight;
   private final int rdnsTimeoutMillis;

   // trust
   private final boolean trustEnabled;
   private final int trustMinLogins;
   private final int trustMinDays;

   // heuristics
   private final boolean heuristicsEnabled;
   private final int maxJoinsPerSubnetPerMinute;
   private final int maxAccountsPerIp;
   private final int geoJumpMinutes;
   private final double heuristicWeight;

   // storage
   private final String storageType;
   private final String serverId;
   private final String sqlHost;
   private final int sqlPort;
   private final String sqlDatabase;
   private final String sqlUsername;
   private final String sqlPassword;
   private final String sqlUrl;
   private final String sqlParameters;
   private final int sqlPoolSize;
   private final String sqlDriverPath;
   private final String redisHost;
   private final int redisPort;
   private final String redisUsername;
   private final String redisPassword;
   private final int redisDatabase;
   private final int redisTimeoutMillis;
   private final String redisPrefix;

   // metrics
   private final boolean metricsEnabled;
   private final int metricsPluginId;

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
      this.exemptBedrock = node.getBoolean("whitelist.bedrock-players", true);

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

      // Superseded by api.providers. Empty by default so an empty provider list stays empty
      // rather than silently falling back to a hardcoded endpoint.
      this.apiUrl = node.getString("api.url", "");
      this.apiProviders = List.copyOf(node.getStringList("api.providers"));
      this.lookupMode = LookupMode.parse(node.getString("api.mode", "consensus"));
      this.requiredScore = Math.max(0.1, node.getDouble("api.required-score", 1.0));
      this.apiTimeoutSeconds = clamp(node.getInt("api.timeout-seconds", 4), 1, 60);
      this.apiTotalTimeoutSeconds = clamp(node.getInt("api.total-timeout-seconds", 6), 1, 120);
      this.apiMaxParallel = clamp(node.getInt("api.max-parallel", 6), 1, 32);
      this.apiCacheMinutes = Math.max(1L, node.getLong("api.cache-minutes", 360L));
      this.apiFlaggedCacheMinutes =
            Math.max(1L, node.getLong("api.flagged-cache-minutes", 1440L));
      this.apiMaxCacheEntries = clamp(node.getInt("api.max-cache-entries", 10000), 100, 1000000);
      this.apiRateLimitPerMinute = clamp(node.getInt("api.rate-limit-per-minute", 45), 1, 10000);
      this.apiPersistCache = node.getBoolean("api.persist-cache", true);
      this.providers = readProviders(node);

      this.blockTor = node.getBoolean("detection.block-tor", true);
      this.allowResidentialHosting =
            node.getBoolean("detection.allow-residential-hosting", true);
      this.asnEnabled = node.getBoolean("detection.asn.enabled", true);
      this.blockedAsns = normalizedAsns(node.getStringList("detection.asn.blocked"));
      this.allowedAsns = normalizedAsns(node.getStringList("detection.asn.allowed"));
      this.rdnsEnabled = node.getBoolean("detection.rdns.enabled", true);
      this.rdnsPatterns = lowerCaseList(node.getStringList("detection.rdns.patterns"));
      this.rdnsWeight = Math.max(0.0, node.getDouble("detection.rdns.weight", 1.0));
      this.rdnsTimeoutMillis = clamp(node.getInt("detection.rdns.timeout-millis", 700), 50, 5000);

      this.trustEnabled = node.getBoolean("trust.enabled", true);
      this.trustMinLogins = clamp(node.getInt("trust.min-logins", 5), 1, 10000);
      this.trustMinDays = clamp(node.getInt("trust.min-days", 3), 0, 3650);

      this.heuristicsEnabled = node.getBoolean("heuristics.enabled", true);
      this.maxJoinsPerSubnetPerMinute =
            clamp(node.getInt("heuristics.max-joins-per-subnet-per-minute", 12), 1, 10000);
      this.maxAccountsPerIp = clamp(node.getInt("heuristics.max-accounts-per-ip", 4), 1, 1000);
      this.geoJumpMinutes = clamp(node.getInt("heuristics.geo-jump-minutes", 10), 0, 1440);
      this.heuristicWeight = Math.max(0.0, node.getDouble("heuristics.weight", 1.0));

      this.storageType = node.getString("storage.type", "file");
      this.serverId = node.getString("storage.server-id", "");
      this.sqlHost = node.getString("storage.sql.host", "127.0.0.1");
      this.sqlPort = clamp(node.getInt("storage.sql.port", 3306), 1, 65535);
      this.sqlDatabase = node.getString("storage.sql.database", "proxyshield");
      this.sqlUsername = node.getString("storage.sql.username", "");
      this.sqlPassword = node.getString("storage.sql.password", "");
      this.sqlUrl = node.getString("storage.sql.url", "");
      this.sqlParameters = node.getString("storage.sql.parameters", "");
      this.sqlPoolSize = clamp(node.getInt("storage.sql.pool-size", 4), 1, 32);
      this.sqlDriverPath = node.getString("storage.sql.driver-path", "");
      this.redisHost = node.getString("storage.redis.host", "127.0.0.1");
      this.redisPort = clamp(node.getInt("storage.redis.port", 6379), 1, 65535);
      this.redisUsername = node.getString("storage.redis.username", "");
      this.redisPassword = node.getString("storage.redis.password", "");
      this.redisDatabase = clamp(node.getInt("storage.redis.database", 0), 0, 15);
      this.redisTimeoutMillis = clamp(node.getInt("storage.redis.timeout-millis", 2000), 100,
            30000);
      this.redisPrefix = node.getString("storage.redis.prefix", "proxyshield:");

      this.metricsEnabled = node.getBoolean("metrics.enabled", true);
      this.metricsPluginId = Math.max(0, node.getInt("metrics.plugin-id", 0));

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

   /**
    * Turns the {@code api.providers} section into definitions.
    * <p>
    * Two shapes are accepted. A plain list of URLs is what earlier builds took, and still works.
    * A section keyed by service id is the new form: every id in {@link ProviderCatalog} brings its
    * own response layout, so enabling one is a single line, while an unknown id with a {@code url}
    * describes a service the catalog has never heard of without touching code.
    */
   private static List<ProviderDefinition> readProviders(ConfigNode node) {
      List<ProviderDefinition> out = new ArrayList<>();

      for (String id : node.getKeys("api.providers")) {
         String base = "api.providers." + id;
         if (!node.getBoolean(base + ".enabled", node.getBoolean(base, false))) {
            continue;
         }

         ProviderDefinition catalogued = ProviderCatalog.byId(id);
         String url = node.getString(base + ".url", null);
         ProviderDefinition definition;
         if (catalogued != null && (url == null || url.isBlank())) {
            definition = catalogued;
         } else if (url != null && !url.isBlank()) {
            definition = custom(node, id, base, url);
         } else {
            // Unknown id and no URL: nothing to query. Reported at start-up by the lookup service.
            continue;
         }

         definition = definition
               .withCredentials(node.getString(base + ".key", null),
                     node.getString(base + ".contact", null))
               .withWeight(node.getDouble(base + ".weight", definition.weight()))
               .withRateLimit(node.getInt(base + ".rate-limit-per-minute",
                     definition.rateLimitPerMinute()));
         out.add(definition);
      }

      // A URL list from an older config, or api.url on its own.
      for (String url : node.getStringList("api.providers")) {
         if (url != null && !url.isBlank()) {
            out.add(ProviderDefinition.generic(url.trim())
                  .withRateLimit(clamp(node.getInt("api.rate-limit-per-minute", 45), 1, 10000)));
         }
      }
      if (out.isEmpty()) {
         String legacy = node.getString("api.url", "");
         if (legacy != null && !legacy.isBlank()) {
            out.add(ProviderDefinition.generic(legacy.trim()));
         }
      }

      return List.copyOf(out);
   }

   /** Builds a definition for a service described entirely in config.yml. */
   private static ProviderDefinition custom(ConfigNode node, String id, String base, String url) {
      ProviderDefinition.Builder builder = ProviderDefinition.builder(id, url);

      if ("plain".equalsIgnoreCase(node.getString(base + ".format", "json"))) {
         List<String> trueValues = node.getStringList(base + ".true-values");
         builder.plain(trueValues.isEmpty()
               ? new String[] {"true", "yes", "y", "1"}
               : trueValues.toArray(new String[0]));
      }

      String header = node.getString(base + ".key-header", null);
      if (header != null && !header.isBlank()) {
         builder.headerKey(header.trim());
      }

      applyPaths(node, base + ".proxy-fields", builder::proxy);
      applyPaths(node, base + ".hosting-fields", builder::hosting);
      applyPaths(node, base + ".tor-fields", builder::tor);
      applyPaths(node, base + ".country-fields", builder::country);
      applyPaths(node, base + ".isp-fields", builder::isp);
      applyPaths(node, base + ".asn-fields", builder::asn);

      String scoreField = node.getString(base + ".score-field", null);
      if (scoreField != null && !scoreField.isBlank()) {
         builder.score(scoreField.trim(), node.getDouble(base + ".score-threshold", 1.0),
               node.getDouble(base + ".score-max", Double.MAX_VALUE));
      }
      if (node.getBoolean(base + ".nested-by-ip", false)) {
         builder.nestedByIp();
      }

      ProviderDefinition built = builder.build();
      // With no field mapping at all, fall back to the catch-all reader rather than a provider
      // that can only ever answer "none of the expected fields".
      boolean described = !built.proxyPaths().isEmpty() || !built.hostingPaths().isEmpty()
            || built.scorePath() != null
            || built.format() == ProviderDefinition.Format.PLAIN;
      return described ? built : ProviderDefinition.generic(url);
   }

   private static void applyPaths(ConfigNode node, String path,
         java.util.function.Consumer<String[]> setter) {
      List<String> values = node.getStringList(path);
      if (!values.isEmpty()) {
         setter.accept(values.toArray(new String[0]));
      }
   }

   private static Set<String> normalizedAsns(List<String> values) {
      Set<String> out = new LinkedHashSet<>();
      for (String value : values) {
         if (value == null || value.isBlank()) {
            continue;
         }
         String digits = value.trim().toUpperCase(Locale.ROOT).replace("AS", "");
         if (!digits.isEmpty() && digits.chars().allMatch(Character::isDigit)) {
            out.add("AS" + digits);
         }
      }
      return Set.copyOf(out);
   }

   private static List<String> lowerCaseList(List<String> values) {
      List<String> out = new ArrayList<>(values.size());
      for (String value : values) {
         if (value != null && !value.isBlank()) {
            out.add(value.trim().toLowerCase(Locale.ROOT));
         }
      }
      return List.copyOf(out);
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

   /** Whether Geyser/Floodgate players skip every check. */
   public boolean exemptBedrock() {
      return exemptBedrock;
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

   /**
    * Lookup endpoints in the order they should be tried, each with an {@code {ip}} placeholder.
    * <p>
    * Falls back to the single {@code api.url} when {@code api.providers} is empty, so a config
    * written for an earlier build keeps working.
    */
   public List<String> activeApiProviders() {
      List<String> out = new ArrayList<>();
      for (String provider : apiProviders) {
         if (provider != null && !provider.isBlank()) {
            out.add(provider.trim());
         }
      }
      if (out.isEmpty() && apiUrl != null && !apiUrl.isBlank()) {
         out.add(apiUrl.trim());
      }
      return out;
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

   /** Provider definitions in configured order, credentials and weights already applied. */
   public List<ProviderDefinition> providers() {
      return providers;
   }

   public LookupMode lookupMode() {
      return lookupMode;
   }

   /** Combined weight needed before an address counts as a proxy in consensus mode. */
   public double requiredScore() {
      return requiredScore;
   }

   /** Ceiling on how long the whole lookup stage may take for one login. */
   public int apiTotalTimeoutSeconds() {
      return apiTotalTimeoutSeconds;
   }

   public int apiMaxParallel() {
      return apiMaxParallel;
   }

   public long apiFlaggedCacheMinutes() {
      return apiFlaggedCacheMinutes;
   }

   public boolean apiPersistCache() {
      return apiPersistCache;
   }

   public boolean blockTor() {
      return blockTor;
   }

   /** Whether a residential or mobile connection type overrides a hosting flag. */
   public boolean allowResidentialHosting() {
      return allowResidentialHosting;
   }

   public boolean asnEnabled() {
      return asnEnabled;
   }

   public Set<String> blockedAsns() {
      return blockedAsns;
   }

   public Set<String> allowedAsns() {
      return allowedAsns;
   }

   public boolean rdnsEnabled() {
      return rdnsEnabled;
   }

   public List<String> rdnsPatterns() {
      return rdnsPatterns;
   }

   public double rdnsWeight() {
      return rdnsWeight;
   }

   public int rdnsTimeoutMillis() {
      return rdnsTimeoutMillis;
   }

   public boolean trustEnabled() {
      return trustEnabled;
   }

   public int trustMinLogins() {
      return trustMinLogins;
   }

   public int trustMinDays() {
      return trustMinDays;
   }

   public boolean heuristicsEnabled() {
      return heuristicsEnabled;
   }

   public int maxJoinsPerSubnetPerMinute() {
      return maxJoinsPerSubnetPerMinute;
   }

   public int maxAccountsPerIp() {
      return maxAccountsPerIp;
   }

   public int geoJumpMinutes() {
      return geoJumpMinutes;
   }

   public double heuristicWeight() {
      return heuristicWeight;
   }

   /** {@code file}, {@code mysql}, {@code mariadb}, {@code postgresql}, {@code sqlite},
    * {@code h2}, {@code redis} or {@code memory}. */
   public String storageType() {
      return storageType;
   }

   /** Identity used to ignore this server's own Redis invalidations. Generated when blank. */
   public String serverId() {
      return serverId;
   }

   public String sqlHost() {
      return sqlHost;
   }

   public int sqlPort() {
      return sqlPort;
   }

   public String sqlDatabase() {
      return sqlDatabase;
   }

   public String sqlUsername() {
      return sqlUsername;
   }

   public String sqlPassword() {
      return sqlPassword;
   }

   /** A complete JDBC URL, which takes precedence over the host/port/database settings. */
   public String sqlUrl() {
      return sqlUrl;
   }

   public String sqlParameters() {
      return sqlParameters;
   }

   public int sqlPoolSize() {
      return sqlPoolSize;
   }

   public String sqlDriverPath() {
      return sqlDriverPath;
   }

   public String redisHost() {
      return redisHost;
   }

   public int redisPort() {
      return redisPort;
   }

   public String redisUsername() {
      return redisUsername;
   }

   public String redisPassword() {
      return redisPassword;
   }

   public int redisDatabase() {
      return redisDatabase;
   }

   public int redisTimeoutMillis() {
      return redisTimeoutMillis;
   }

   public String redisPrefix() {
      return redisPrefix;
   }

   public boolean metricsEnabled() {
      return metricsEnabled;
   }

   /** bStats id, or 0 to use the built-in one for this platform. */
   public int metricsPluginId() {
      return metricsPluginId;
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
