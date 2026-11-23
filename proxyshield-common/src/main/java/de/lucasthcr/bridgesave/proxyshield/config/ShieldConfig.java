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
import de.lucasthcr.bridgesave.proxyshield.notify.EmbedTemplate;
import de.lucasthcr.bridgesave.proxyshield.lookup.ProviderDefinition;
import de.lucasthcr.bridgesave.proxyshield.lookup.ResponseRule;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

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

   /** Which detections the {@code actions.on-flag} commands run for. */
   public enum ActionTrigger {
      /** Every detection, whether or not the player was disconnected. */
      ALWAYS,
      /** Only detections that actually disconnected the player. */
      KICKED,
      /** Only detections the player survived, i.e. dry-run. */
      ALLOWED;

      static ActionTrigger parse(String raw) {
         if ("kicked".equalsIgnoreCase(raw)) {
            return KICKED;
         }
         return "allowed".equalsIgnoreCase(raw) ? ALLOWED : ALWAYS;
      }

      /** @param enforced whether the detection disconnected the player */
      public boolean matches(boolean enforced) {
         return this == ALWAYS || (enforced ? this == KICKED : this == ALLOWED);
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

   /** Plain text alert for Telegram and VK. A literal backslash-n becomes a line break. */
   static final String DEFAULT_CHAT_MESSAGE =
         "ProxyShield {action}: {player} ({ip})\\n{reason} | {country} | {isp}";

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
   private final int apiFirstWave;
   private final int apiCleanSettleMillis;
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
   private final double hostingMinScore;
   private final String networkDataSource;
   private final boolean updatesNotify;
   private final boolean updatesAutoInstall;
   private final boolean reportingEnabled;
   private final String reportingUrl;
   private final int reportingIntervalMinutes;
   private final boolean networkFallbackHosting;
   private final String networkFastAdmitMode;
   private final int networkFastAdmitBurst;
   private final boolean asnEnabled;
   private final Set<String> blockedAsns;
   private final Set<String> allowedAsns;
   private final List<String> asnSources;
   private final boolean rdnsEnabled;
   private final List<String> rdnsPatterns;
   private final double rdnsWeight;
   private final int rdnsTimeoutMillis;
   private final boolean blockBogon;
   private final boolean passive;
   private final List<Pattern> blockedIsps;
   private final List<Pattern> allowedIsps;
   private final boolean debug;

   // limiter
   private final boolean limiterEnabled;
   private final int limiterMax;
   private final int limiterWindowMinutes;

   // restricted servers
   private final boolean restrictedEnabled;
   private final boolean restrictedWhitelist;
   private final List<Pattern> restrictedServers;

   // alts
   private final boolean altsEnabled;
   private final int altsRetentionDays;

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

   // actions
   private final List<String> flagCommands;
   private final long flagCommandDelaySeconds;
   private final ActionTrigger flagCommandTrigger;

   // discord
   private final boolean discordEnabled;
   private final String webhookUrl;
   private final boolean discordShowIp;
   private final String discordUsername;
   private final String discordTitle;
   private final int discordColor;
   private final EmbedTemplate discordEmbed;

   // telegram / vk
   private final boolean telegramEnabled;
   private final String telegramToken;
   private final String telegramChatId;
   private final long telegramThreadId;
   private final boolean telegramShowIp;
   private final String telegramMessage;
   private final boolean vkEnabled;
   private final String vkToken;
   private final long vkPeerId;
   private final String vkApiVersion;
   private final boolean vkShowIp;
   private final String vkMessage;

   /** Problems found while reading, reported once by the caller. */
   private final List<String> warnings;

   private ShieldConfig(ConfigNode node) {
      List<String> configWarnings = new ArrayList<>();
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
      List<String> sources = new java.util.ArrayList<>(node.getStringList("lists.sources"));
      String relays = "https://intel.paperstream.dev/feed/operators.txt";
      if (node.getBoolean("lists.operator-relays", true) && !sources.contains(relays)) {
         sources.add(relays);
      }
      this.listSources = List.copyOf(sources);

      // Superseded by api.providers. Empty by default so an empty provider list stays empty
      // rather than silently falling back to a hardcoded endpoint.
      this.apiUrl = node.getString("api.url", "");
      this.apiProviders = List.copyOf(node.getStringList("api.providers"));
      this.lookupMode = LookupMode.parse(node.getString("api.mode", "consensus"));
      this.apiFirstWave = clamp(node.getInt("api.first-wave", 2), 0, 32);
      this.apiCleanSettleMillis = clamp(node.getInt("api.clean-settle-ms", 0), 0, 5000);
      this.requiredScore = Math.max(0.1, node.getDouble("api.required-score", 1.0));
      this.apiTimeoutSeconds = clamp(node.getInt("api.timeout-seconds", 4), 1, 60);
      this.apiTotalTimeoutSeconds = clamp(node.getInt("api.total-timeout-seconds", 6), 1, 120);
      this.apiMaxParallel = clamp(node.getInt("api.max-parallel", 64), 1, 256);
      this.apiCacheMinutes = Math.max(1L, node.getLong("api.cache-minutes", 360L));
      this.apiFlaggedCacheMinutes =
            Math.max(1L, node.getLong("api.flagged-cache-minutes", 1440L));
      this.apiMaxCacheEntries = clamp(node.getInt("api.max-cache-entries", 10000), 100, 1000000);
      this.apiRateLimitPerMinute = clamp(node.getInt("api.rate-limit-per-minute", 45), 1, 10000);
      this.apiPersistCache = node.getBoolean("api.persist-cache", true);
      this.providers = readProviders(node, configWarnings);

      this.blockTor = node.getBoolean("detection.block-tor", true);
      this.allowResidentialHosting =
            node.getBoolean("detection.allow-residential-hosting", true);
      this.hostingMinScore = Math.max(0.0, node.getDouble("detection.hosting-min-score", 0.5));
      this.networkDataSource = node.getString("detection.network-data.source", "").trim();
      this.updatesNotify = node.getBoolean("updates.notify", true);
      this.updatesAutoInstall = node.getBoolean("updates.auto-update", false);
      this.reportingEnabled = node.getBoolean("reporting.enabled", false);
      String reportingTarget = node.getString("reporting.url", "https://intel.paperstream.dev").trim();
      this.reportingUrl = reportingTarget.endsWith("/")
            ? reportingTarget.substring(0, reportingTarget.length() - 1) : reportingTarget;
      this.reportingIntervalMinutes = Math.max(1, Math.min(1440, node.getInt("reporting.interval-minutes", 10)));
      this.networkFallbackHosting = node.getBoolean("detection.network-data.fallback-block-hosting", true);
      String fastAdmit = node.getString("detection.network-data.fast-admit", "auto").trim().toLowerCase(java.util.Locale.ROOT);
      if (node.getBoolean("detection.network-data.fast-admit-end-user", false)) {
         fastAdmit = "always";
      }
      this.networkFastAdmitMode = switch (fastAdmit) {
         case "always", "true", "on" -> "always";
         case "never", "false", "off" -> "never";
         default -> "auto";
      };
      this.networkFastAdmitBurst = Math.max(1, node.getInt("detection.network-data.fast-admit-burst", 20));
      this.asnEnabled = node.getBoolean("detection.asn.enabled", true);
      this.blockedAsns = normalizedAsns(node.getStringList("detection.asn.blocked"));
      this.allowedAsns = normalizedAsns(node.getStringList("detection.asn.allowed"));
      this.asnSources = List.copyOf(node.getStringList("detection.asn.sources"));
      this.rdnsEnabled = node.getBoolean("detection.rdns.enabled", true);
      this.rdnsPatterns = lowerCaseList(node.getStringList("detection.rdns.patterns"));
      this.rdnsWeight = Math.max(0.0, node.getDouble("detection.rdns.weight", 1.0));
      this.rdnsTimeoutMillis = clamp(node.getInt("detection.rdns.timeout-millis", 700), 50, 5000);
      this.blockBogon = node.getBoolean("detection.block-bogon", true);
      this.passive = node.getBoolean("detection.passive", false);
      this.blockedIsps = ispPatterns(node.getStringList("detection.isp.blocked"));
      this.allowedIsps = ispPatterns(node.getStringList("detection.isp.allowed"));
      this.debug = node.getBoolean("settings.debug", false);

      this.limiterEnabled = node.getBoolean("limiter.enabled", false);
      this.limiterMax = clamp(node.getInt("limiter.max-per-ip", 3), 1, 1000);
      this.limiterWindowMinutes = parseWindowMinutes(node.getString("limiter.window", "disable"));

      this.restrictedEnabled = node.getBoolean("restricted.enabled", false);
      this.restrictedWhitelist =
            !"blacklist".equalsIgnoreCase(node.getString("restricted.mode", "whitelist"));
      this.restrictedServers = serverPatterns(node.getStringList("restricted.servers"));

      this.altsEnabled = node.getBoolean("alts.enabled", true);
      this.altsRetentionDays = clamp(node.getInt("alts.retention-days", 30), 0, 3650);

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

      this.flagCommands = cleanCommands(node.getStringList("actions.on-flag"));
      // Capped: the delay holds a task per detection, and a value in the hours would let a burst
      // of joins pile up an unbounded queue of them.
      this.flagCommandDelaySeconds =
            Math.max(0L, Math.min(300L, node.getInt("actions.delay-seconds", 0)));
      this.flagCommandTrigger = ActionTrigger.parse(node.getString("actions.run-when", "always"));

      this.discordEnabled = node.getBoolean("discord.enabled", false);
      this.webhookUrl = node.getString("discord.webhook-url", "");
      this.discordShowIp = node.getBoolean("discord.show-ip", true);
      this.discordUsername = node.getString("discord.username", "ProxyShield");
      this.discordTitle = node.getString("discord.title", "ProxyShield Alert");
      this.discordColor = node.getInt("discord.color", 0xFF0000);
      this.discordEmbed = EmbedTemplate.from(node, this.discordTitle);

      this.telegramEnabled = node.getBoolean("telegram.enabled", false);
      this.telegramToken = node.getString("telegram.bot-token", "").trim();
      this.telegramChatId = node.getString("telegram.chat-id", "").trim();
      this.telegramThreadId = Math.max(0L, node.getLong("telegram.thread-id", 0L));
      this.telegramShowIp = node.getBoolean("telegram.show-ip", true);
      this.telegramMessage = node.getString("telegram.message", DEFAULT_CHAT_MESSAGE);
      this.vkEnabled = node.getBoolean("vk.enabled", false);
      this.vkToken = node.getString("vk.access-token", "").trim();
      this.vkPeerId = node.getLong("vk.peer-id", 0L);
      this.vkApiVersion = node.getString("vk.api-version", "5.199").trim();
      this.vkShowIp = node.getBoolean("vk.show-ip", true);
      this.vkMessage = node.getString("vk.message", DEFAULT_CHAT_MESSAGE);
      this.warnings = List.copyOf(configWarnings);
   }

   public List<String> warnings() {
      return warnings;
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
   private static List<ProviderDefinition> readProviders(ConfigNode node,
         List<String> warnings) {
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
         definition = definition.withExtras(readHeaders(node, base + ".headers"),
               readRules(node, base + ".conditions.bypass", warnings),
               readRules(node, base + ".conditions.flag", warnings));
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

   private static Map<String, String> readHeaders(ConfigNode node, String path) {
      Map<String, String> headers = new LinkedHashMap<>();
      for (String name : node.getKeys(path)) {
         String value = node.getString(path + "." + name, null);
         if (value != null && !name.isBlank()) {
            headers.put(name.trim(), value);
         }
      }
      return headers;
   }

   /**
    * Reads a block of named rule groups. Each key holds a list of conditions that must all hold;
    * any one group matching is enough. A group that cannot be parsed is skipped and reported
    * through {@link #warnings()}: refusing the whole config would leave the server unprotected
    * over one typo.
    */
   private static List<ResponseRule> readRules(ConfigNode node, String path,
         List<String> warnings) {
      List<ResponseRule> rules = new ArrayList<>();
      for (String name : node.getKeys(path)) {
         List<String> lines = node.getStringList(path + "." + name);
         if (lines.isEmpty()) {
            String single = node.getString(path + "." + name, null);
            if (single != null && !single.isBlank()) {
               lines = List.of(single);
            }
         }
         try {
            rules.add(ResponseRule.parse(name, lines));
         } catch (IllegalArgumentException invalid) {
            warnings.add("Ignoring " + path + "." + name + ": " + invalid.getMessage());
         }
      }
      return rules;
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

   /**
    * Compiles the ISP filter entries case-insensitively. An entry that is not a valid regular
    * expression is matched literally instead of being dropped, so "AT&T (Mobility)" still works.
    */
   /**
    * Reads a window such as {@code 30m}, {@code 2h} or a bare number of minutes. Anything else,
    * {@code disable} included, means no window.
    */
   static int parseWindowMinutes(String raw) {
      if (raw == null) {
         return 0;
      }
      String value = raw.trim().toLowerCase(Locale.ROOT);
      int factor = 1;
      if (value.endsWith("h")) {
         factor = 60;
         value = value.substring(0, value.length() - 1);
      } else if (value.endsWith("m")) {
         value = value.substring(0, value.length() - 1);
      }
      try {
         return clamp(Integer.parseInt(value.trim()) * factor, 0, 7 * 24 * 60);
      } catch (NumberFormatException notANumber) {
         return 0;
      }
   }

   /** Backend names match as a whole, case-insensitively, so "lobby" does not also hit "lobby-dev". */
   private static List<Pattern> serverPatterns(List<String> values) {
      List<Pattern> out = new ArrayList<>(values.size());
      for (String value : values) {
         if (value == null || value.isBlank()) {
            continue;
         }
         String trimmed = value.trim();
         try {
            out.add(Pattern.compile(trimmed, Pattern.CASE_INSENSITIVE));
         } catch (PatternSyntaxException notARegex) {
            out.add(Pattern.compile(Pattern.quote(trimmed), Pattern.CASE_INSENSITIVE));
         }
      }
      return List.copyOf(out);
   }

   private static List<Pattern> ispPatterns(List<String> values) {
      List<Pattern> out = new ArrayList<>(values.size());
      for (String value : values) {
         if (value == null || value.isBlank()) {
            continue;
         }
         String trimmed = value.trim();
         try {
            out.add(Pattern.compile(trimmed, Pattern.CASE_INSENSITIVE));
         } catch (PatternSyntaxException notARegex) {
            out.add(Pattern.compile(Pattern.quote(trimmed), Pattern.CASE_INSENSITIVE));
         }
      }
      return List.copyOf(out);
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

   /**
    * Tidies the configured commands into something a dispatcher will accept.
    * <p>
    * A leading slash is dropped because every platform wants the bare command, and writing it with
    * one is the natural mistake to make.
    */
   private static List<String> cleanCommands(List<String> values) {
      List<String> out = new ArrayList<>(values.size());
      for (String value : values) {
         if (value == null || value.isBlank()) {
            continue;
         }
         String command = value.trim();
         while (command.startsWith("/")) {
            command = command.substring(1).trim();
         }
         if (!command.isEmpty()) {
            out.add(command);
         }
      }
      return List.copyOf(out);
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

   public boolean telegramUsable() {
      return telegramEnabled && !telegramToken.isEmpty() && !telegramChatId.isEmpty();
   }

   public String telegramToken() {
      return telegramToken;
   }

   public String telegramChatId() {
      return telegramChatId;
   }

   /** Topic inside a forum supergroup, 0 for the main chat. */
   public long telegramThreadId() {
      return telegramThreadId;
   }

   public boolean telegramShowIp() {
      return telegramShowIp;
   }

   public String telegramMessage() {
      return telegramMessage;
   }

   public boolean vkUsable() {
      return vkEnabled && !vkToken.isEmpty() && vkPeerId != 0L;
   }

   public String vkToken() {
      return vkToken;
   }

   public long vkPeerId() {
      return vkPeerId;
   }

   public String vkApiVersion() {
      return vkApiVersion;
   }

   public boolean vkShowIp() {
      return vkShowIp;
   }

   public String vkMessage() {
      return vkMessage;
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

   /** Providers asked first in consensus mode, 0 for all at once. */
   public int apiFirstWave() {
      return apiFirstWave;
   }

   /** After this many milliseconds an address in a home network is let through on one clean answer. 0 = off (default). */
   public int apiCleanSettleMillis() {
      return apiCleanSettleMillis;
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

   /** Whether the console is told about newer versions. */
   public boolean updatesNotify() {
      return updatesNotify;
   }

   /** Whether new versions are staged into the update folder on their own. Off unless switched on. */
   public boolean updatesAutoInstall() {
      return updatesAutoInstall;
   }

   /** Whether refused proxy addresses are sent to the intel service. Off unless switched on. */
   public boolean reportingEnabled() {
      return reportingEnabled;
   }

   public String reportingUrl() {
      return reportingUrl;
   }

   public int reportingIntervalMinutes() {
      return reportingIntervalMinutes;
   }

   /** URL of the network feed, empty when the feature is off. */
   public String networkDataSource() {
      return networkDataSource;
   }

   /** Refuse hosting-like networks when no provider could answer. */
   public boolean networkFallbackHosting() {
      return networkFallbackHosting;
   }

   /** Skip provider lookups for addresses in end-user networks. */
   public String networkFastAdmitMode() {
      return networkFastAdmitMode;
   }

   public int networkFastAdmitBurst() {
      return networkFastAdmitBurst;
   }

   /** Score a hosting flag needs from other signals before it blocks. */
   public double hostingMinScore() {
      return hostingMinScore;
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

   /**
    * Whether a detected player on a proxy is kept on the allowed backends instead of being
    * disconnected. Off, or with no servers listed, the player is disconnected as usual.
    */
   public boolean restrictedEnabled() {
      return restrictedEnabled && !restrictedServers.isEmpty();
   }

   /** Whether a restricted player may be sent to the named backend. */
   public boolean restrictedAllows(String server) {
      boolean listed = false;
      for (Pattern pattern : restrictedServers) {
         if (pattern.matcher(server).matches()) {
            listed = true;
            break;
         }
      }
      return restrictedWhitelist == listed;
   }

   /** Whether accounts are remembered per address for {@code /proxyshield alts}. */
   public boolean altsEnabled() {
      return altsEnabled;
   }

   public int altsRetentionDays() {
      return altsRetentionDays;
   }

   public boolean limiterEnabled() {
      return limiterEnabled;
   }

   public int limiterMax() {
      return limiterMax;
   }

   /** 0 means "count players online right now" rather than admissions inside a window. */
   public int limiterWindowMinutes() {
      return limiterWindowMinutes;
   }

   /** URLs of downloadable ASN block lists, refreshed with the address lists. */
   public List<String> asnSources() {
      return asnSources;
   }

   public boolean blockBogon() {
      return blockBogon;
   }

   /** Joins are not checked; only {@code /proxyshield check} and the API look at addresses. */
   public boolean passive() {
      return passive;
   }

   public List<Pattern> blockedIsps() {
      return blockedIsps;
   }

   public List<Pattern> allowedIsps() {
      return allowedIsps;
   }

   /** Logs every provider response, for working out why an address was or was not flagged. */
   public boolean debug() {
      return debug;
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

   /** Console commands to run on a detection, already stripped of any leading slash. */
   public List<String> flagCommands() {
      return flagCommands;
   }

   /** How long to wait before running them, so a join can finish first. Clamped to 300. */
   public long flagCommandDelaySeconds() {
      return flagCommandDelaySeconds;
   }

   public ActionTrigger flagCommandTrigger() {
      return flagCommandTrigger;
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

   /** The message layout, either as configured under {@code discord.embed} or the classic one. */
   public EmbedTemplate discordEmbed() {
      return discordEmbed;
   }

   public int discordColor() {
      return discordColor;
   }
}
