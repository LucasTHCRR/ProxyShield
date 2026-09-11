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

package de.lucasthcr.bridgesave.proxyshield.message;

import de.lucasthcr.bridgesave.proxyshield.config.ConfigNode;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import de.lucasthcr.bridgesave.proxyshield.util.Text;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * All user facing text, loaded from a message file so servers can translate or reword anything
 * without touching the jar.
 * <p>
 * A missing key falls back to the built-in English default rather than printing an error, so a
 * message file written for an older version keeps working after an update.
 */
public final class Messages {

   /** Message files bundled with the plugin. The first one is the fallback. */
   public static final List<String> BUNDLED_LOCALES = List.of("en", "de");

   private static final Map<String, String> DEFAULTS = defaults();

   private final Map<String, String> values;
   private final String prefix;
   private final String locale;

   private Messages(String locale, Map<String, String> values) {
      this.locale = locale;
      this.values = values;
      this.prefix = values.getOrDefault("prefix", DEFAULTS.get("prefix"));
   }

   /** English defaults, used as the fallback for any key a message file does not define. */
   public static Messages builtIn() {
      return new Messages("built-in", Map.of());
   }

   /**
    * Loads {@code messages_<locale>.yml}, writing the bundled copy first when one exists for that
    * locale. Falls back to the built-in text if the file cannot be read.
    */
   public static Messages load(Platform platform, String locale) {
      String normalized = locale == null || locale.isBlank() ? "en" : locale.trim().toLowerCase();
      String fileName = "messages_" + normalized + ".yml";

      if (BUNDLED_LOCALES.contains(normalized)) {
         platform.saveResource(fileName);
      }

      ConfigNode node;
      try {
         node = platform.loadYaml(fileName);
      } catch (RuntimeException missing) {
         platform.warn("Could not read " + fileName + " (" + missing.getMessage()
               + "), falling back to the built-in English text.");
         return builtIn();
      }

      Map<String, String> values = new LinkedHashMap<>();
      for (String key : DEFAULTS.keySet()) {
         String value = node.getString(key, null);
         if (value != null) {
            values.put(key, value);
         }
      }
      return new Messages(normalized, values);
   }

   public String locale() {
      return locale;
   }

   /** Raw text for a key, with {@code {prefix}} already substituted. */
   public String get(String key) {
      return get(key, Map.of());
   }

   public String get(String key, Map<String, String> placeholders) {
      String template = values.get(key);
      if (template == null) {
         template = DEFAULTS.get(key);
      }
      if (template == null) {
         // Better to show the key than to swallow the message entirely.
         return "&c[missing message: " + key + "]";
      }

      Map<String, String> merged = new LinkedHashMap<>(placeholders);
      merged.putIfAbsent("prefix", prefix);
      return Text.fill(template, merged);
   }

   /** Number of keys the message file overrode. Reported by {@code /proxyshield info}. */
   public int overriddenKeys() {
      return values.size();
   }

   public static int knownKeyCount() {
      return DEFAULTS.size();
   }

   /** Every key the plugin knows about, in the order the bundled files list them. */
   public static Set<String> knownKeys() {
      return DEFAULTS.keySet();
   }

   /** Built-in English text for a key, or {@code null} if the key is unknown. */
   public static String defaultValue(String key) {
      return DEFAULTS.get(key);
   }

   private static Map<String, String> defaults() {
      Map<String, String> m = new LinkedHashMap<>();
      m.put("prefix", "&8[&cProxyShield&8]&r ");

      m.put("alert", "{prefix}&e{player} &7blocked &8(&f{reason}&8) &7from &f{ip} &8[&f{country}&8]");
      m.put("alert-dry-run",
            "{prefix}&6[DRY-RUN] &e{player} &7would be blocked &8(&f{reason}&8) &7from &f{ip}");

      // Shown on the disconnect screen of a blocked player. \n produces a line break.
      m.put("kick-message",
            "&c&lProxyShield&r\\n\\n&7VPNs and proxies are not allowed on this server.\\n"
                  + "&7Reason: &f{reason}");

      m.put("no-permission", "{prefix}&cYou do not have permission to use this command.");
      m.put("unknown-subcommand", "{prefix}&cUnknown subcommand &f{input}&c.");
      m.put("player-not-found", "{prefix}&cNo online player named &f{input} &cand not a valid IP.");
      m.put("invalid-entry", "{prefix}&cNot a valid address, CIDR block or range: &f{input}");

      m.put("help-header", "&8&m--------&r &c&lProxyShield &7v{version} &8&m--------");
      m.put("help-info", "&e/proxyshield info &8- &7Version and current mode");
      m.put("help-stats", "&e/proxyshield stats &8- &7Detection counters");
      m.put("help-check", "&e/proxyshield check <player|ip> &8- &7Run the full pipeline");
      m.put("help-lookup", "&e/proxyshield lookup <ip> &8- &7Fresh provider lookup");
      m.put("help-whitelist", "&e/proxyshield whitelist <add|remove|list> [ip] &8- &7Never block");
      m.put("help-blacklist", "&e/proxyshield blacklist <add|remove|list> [ip] &8- &7Always block");
      m.put("help-refresh", "&e/proxyshield refresh &8- &7Re-download the VPN lists");
      m.put("help-recheck", "&e/proxyshield recheck &8- &7Re-check everyone online");
      m.put("help-clearcache", "&e/proxyshield clearcache &8- &7Drop cached lookup results");
      m.put("help-reload", "&e/proxyshield reload &8- &7Re-read config.yml");
      m.put("help-footer", "&7Entries accept a single IP, a CIDR block or a range.");

      m.put("info-header", "&8&m--------&r &c&lProxyShield &8&m--------");
      m.put("info-version", "&7Version: &f{version} &8| &7Platform: &f{platform} &8| &7Language: &f{locale}");
      m.put("info-mode-enforcing", "&7Mode: &aenforcing");
      m.put("info-mode-dry-run", "&7Mode: &6dry-run (nobody is kicked)");
      m.put("info-alerts", "&7Alerts: {silent} &8| &7Webhook: {webhook} &8| &7Log file: {logfile}");
      m.put("info-detection", "&7Detection: &flists={lists} &fapi={api} &fproxy={proxy} &fhosting={hosting}");
      m.put("info-country-off", "&7Country filter: &7off");
      m.put("info-country-on", "&7Country filter: &f{mode} &8[&f{codes}&8] &7unknown={unknown}");
      m.put("info-lists", "&7VPN ranges: &f{ranges} &7from &f{ok}&7/&f{total} &7source(s)");
      m.put("info-managed", "&7Whitelist: &f{whitelist} &8| &7Blacklist: &f{blacklist} &7range(s)");
      m.put("info-provider", "&7Provider: &f{provider} &8| &7Fail policy: {failmode}");
      m.put("info-lookup-mode", "&7Mode: &f{mode} &8| &7required score: &f{score} &8| &7active providers: &f{count}");
      m.put("info-storage", "&7Storage: &f{storage} &8| &7shared with other servers: {shared}");
      m.put("info-signals", "&7Signals: &7ASN {asn} &8| &7rDNS {rdns} &8| &7behaviour {heuristics} &8| &7trust {trust}");

      m.put("providers-header", "&8&m--------&r &c&lProxyShield Providers &8&m--------");
      m.put("providers-line", "&8» &f{id} &8(&7{host}&8) &7weight &f{weight} &8| {status} &8| &7{queries} queries, &f{failures} &7failed, &f{latency}ms");
      m.put("providers-none", "&cNo lookup provider is enabled. Turn some on under api.providers.");
      m.put("provider-status-ok", "&aok");
      m.put("provider-status-tripped", "&cin cooldown");

      m.put("stats-header", "&8&m--------&r &c&lProxyShield Stats &8&m--------");
      m.put("stats-uptime", "&7Uptime: &f{uptime}");
      m.put("stats-checked", "&7Connections checked: &f{checked}");
      m.put("stats-blocked", "&7Blocked: &c{blocked}{dryrun}");
      m.put("stats-reasons-1", "&7 &8• &7List: &f{list} &8• &7Proxy: &f{proxy} &8• &7Hosting: &f{hosting}");
      m.put("stats-reasons-2", "&7 &8• &7Country: &f{country} &8• &7Blacklist: &f{blacklist} &8• &7Failed: &f{failed}");
      m.put("stats-allowed", "&7Allowed by bypass: &f{bypass} &8• &7by whitelist: &f{whitelist}");
      m.put("stats-efficiency", "&7Saved: &f{coalesced} &7shared lookups &8| &7timed out: &f{budget} &8| &7trusted players: &f{trusted}");
      m.put("stats-lookups", "&7Lookups: &f{lookups} &8| &7cache: &f{cachesize}&7, &f{cachehits} &7hits &8| &7limited: &f{limited} &8| &7failed: &f{failed}");
      m.put("stats-webhook", "&7Webhook: &f{sent} &7sent, &f{dropped} &7dropped, &f{queued} &7queued");

      m.put("reload-success", "{prefix}&aConfiguration reloaded. Lists are refreshing.");
      m.put("reload-dry-run", "{prefix}&6Dry-run is enabled, detections will not kick anybody.");
      m.put("reload-failed", "{prefix}&cReload failed: &f{error}");
      m.put("reload-kept", "&7The previous configuration is still active.");

      m.put("refresh-running", "{prefix}&eA list refresh is already running.");
      m.put("refresh-start", "{prefix}&7Downloading VPN lists...");
      m.put("refresh-done", "{prefix}&aLists updated: &f{ranges} &aranges, &f{addresses} &aaddresses.");
      m.put("refresh-failed", "{prefix}&cRefresh failed: &f{error}");

      m.put("recheck-start", "{prefix}&7Re-checking every online player...");
      m.put("recheck-done", "{prefix}&aRecheck finished, &f{count} &aplayer(s) disconnected.");
      m.put("recheck-dry-run", "{prefix}&aRecheck finished. &6Dry-run is on, nobody was disconnected.");

      m.put("cache-cleared", "{prefix}&aDropped &f{count} &acached lookup result(s).");

      m.put("check-start", "{prefix}&7Checking &f{ip}&7...");
      m.put("check-header", "&8&m--------&r &c&lProxyShield Check &8&m--------");
      m.put("check-target", "&7Target: &f{target} &8(&f{ip}&8)");
      m.put("check-verdict-allowed", "&7Verdict: &aALLOWED &8- &f{reason}");
      m.put("check-verdict-blocked", "&7Verdict: &cBLOCKED &8- &f{reason}");
      m.put("check-country", "&7Country: &f{code} &8(&f{name}&8)");
      m.put("check-isp", "&7ISP: &f{isp}");
      m.put("check-flags", "&7Proxy: {proxy} &8| &7Hosting: {hosting}");
      m.put("check-score", "&7Score: &f{score}&7/&f{required} &8| &7signals: &f{signals}");
      m.put("check-provider-header", "&7Per provider:");
      m.put("check-provider-line", "&8  » &f{id} &8(&7w{weight}&8): {verdict} &8| &7{detail}");
      m.put("check-unresolved", "&7Provider data: &7unavailable &8(&f{error}&8)");
      m.put("check-lists", "&7On list: {list} &8| &7Whitelisted: {whitelist} &8| &7Blacklisted: {blacklist}");
      m.put("check-dry-run-note", "&6Dry-run is on, so this player would still be let through.");

      m.put("lookup-start", "{prefix}&7Querying the provider for &f{ip}&7...");
      m.put("lookup-failed", "{prefix}&cLookup failed: &f{error}");
      m.put("lookup-details", "&7ASN &f{asn} &8| &7type &f{type} &8| &7score &f{score} &8| &7flagged by &f{sources}");
      m.put("lookup-result", "&7{ip} &8→ &7country &f{country} &8| &7proxy {proxy} &8| &7hosting {hosting} &8| &7isp &f{isp}");

      m.put("list-header", "&8&m--------&r &c&l{list} &8&m--------");
      m.put("list-config", "&7From config.yml &8(&f{count}&8): &f{entries}");
      m.put("list-runtime", "&7Added in game &8(&f{count}&8): &f{entries}");
      m.put("list-ranges", "&7Covering &f{count} &7merged range(s).");
      m.put("list-empty", "none");
      m.put("list-added", "{prefix}&aAdded &f{entry} &ato the {list}.");
      m.put("list-already", "{prefix}&e{entry} &7is already on the {list}.");
      m.put("list-removed", "{prefix}&aRemoved &f{entry} &afrom the {list}.");
      m.put("list-not-runtime", "{prefix}&c{entry} &7is not an in-game entry. Remove config entries in config.yml.");
      m.put("list-save-failed", "{prefix}&cCould not save the {list}: &f{error}");
      m.put("list-usage", "{prefix}&cUsage: &f/proxyshield {list} <add|remove|list> [ip]");

      m.put("usage-check", "{prefix}&cUsage: &f/proxyshield check <player|ip>");
      m.put("usage-lookup", "{prefix}&cUsage: &f/proxyshield lookup <player|ip>");

      m.put("toggle-state", "&7{key} is currently {state}&7.");
      m.put("toggle-hint", "&7Change it in config.yml and run &f/proxyshield reload&7.");

      m.put("update-available",
            "{prefix}&eProxyShield &f{latest} &eis available, you are running &f{current}&e.");

      // Deliberately not named yes/no/on/off: YAML 1.1 parses those as booleans, so an
      // unquoted key of that name would come back as true/false instead of a string.
      m.put("word-yes", "&cyes");
      m.put("word-no", "&ano");
      m.put("word-on", "&aon");
      m.put("word-off", "&coff");
      m.put("enabled", "&aenabled");
      m.put("disabled", "&cdisabled");
      m.put("silent-mode", "&6silent");
      m.put("broadcast-mode", "&abroadcast");
      m.put("fail-open", "&afail-open (allow on error)");
      m.put("fail-closed", "&6fail-closed (deny on error)");

      // Insertion order is kept so the generated message files stay grouped and readable.
      return Collections.unmodifiableMap(m);
   }
}
