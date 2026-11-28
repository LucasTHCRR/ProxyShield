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
   public boolean has(String key) {
      return values.containsKey(key) || DEFAULTS.containsKey(key);
   }

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
      m.put("help-whitelist", "&e/proxyshield whitelist <add|remove|info|list|purge> [ip] [time] [reason] &8- &7Never block");
      m.put("help-blacklist", "&e/proxyshield blacklist <add|remove|info|list|purge> [ip] [time] [reason] &8- &7Always block");
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
      m.put("stats-reasons-3", "&7 &8• &7Network/ISP: &f{network} &8• &7Account limit: &f{limit} &8• &7Bogon: &f{bogon}");
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
      m.put("refresh-done", "{prefix}&aLists updated: &f{ranges} &aranges, &f{addresses} &aIPv4 addresses.");
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
      m.put("list-usage", "{prefix}&cUsage: &f/proxyshield {list} <add|remove|info|list|purge> [ip|player] [30m|12h|7d] [reason]");

      m.put("reporting-on", "{prefix}&aReporting is on &8(&f{url}&8)&a. Queued: &f{queued}&a, sent: &f{sent}&a, last error: &f{error}&a. Delete what was sent with &f/proxyshield reporting forget&a.");
      m.put("reporting-off", "{prefix}&7Reporting is off. Switch it on with &freporting.enabled&7 in the config.");
      m.put("reporting-forgotten", "{prefix}&aThe service deleted &f{count} &areported address(es) and this server forgot its install id.");
      m.put("reporting-nothing", "{prefix}&7This server never reported anything, so there is nothing to delete.");
      m.put("reporting-failed", "{prefix}&cThe service could not be reached. Nothing was deleted, try again later.");
      m.put("help-reporting", "&e/proxyshield reporting [forget] &8- &7Reporting status, or delete what was sent");
      m.put("update-checking", "{prefix}&7Checking for updates...");
      m.put("update-found", "{prefix}&aProxyShield &f{version} &ais out on {source}, this server runs &f{current}&a. On Paper, Folia and Spigot &f/proxyshield update install&a stages it.");
      m.put("update-latest", "{prefix}&aProxyShield &f{current} &ais the newest version.");
      m.put("update-staged", "{prefix}&aProxyShield &f{version} &ais in the update folder and takes effect on the next restart.");
      m.put("update-no-folder", "{prefix}&7This platform has no update folder. Download the new jar from Modrinth, Hangar or Codeberg.");
      m.put("update-failed", "{prefix}&cThe update check failed: &f{error}");
      m.put("usage-fpreport", "{prefix}&cUsage: &f/proxyshield fpreport <player|ip>");
      m.put("fp-report-start", "{prefix}&7Building a report. It contains neither the address nor the player name.");
      m.put("fp-report-line", "&7{line}");
      m.put("kick-appeal-line", "\\n\\n&7Wrongly blocked? Give this code to a staff member: &e{code}");
      m.put("usage-allow", "{prefix}&cUsage: /proxyshield allow <code> [minutes]");
      m.put("allow-unknown", "{prefix}&cThat code is not known or has expired. Ask the player for a fresh one.");
      m.put("allow-done", "{prefix}&aLet {ip} through for {minutes} minutes (player {player}, code {code}).");
      m.put("allow-failed", "{prefix}&cCould not save the entry: {error}");
      m.put("help-doctor", "&e/proxyshield doctor &8- &7Check the setup and show what needs attention");
      m.put("help-explain", "&e/proxyshield explain <player|ip> &8- &7Show step by step why an address is refused or let in");
      m.put("help-report", "&e/proxyshield report <player|ip> <vpn|clean> &8- &7Tell PaperStream Intel about a missed VPN or a wrong block");
      m.put("usage-explain", "{prefix}&cUsage: &f/proxyshield explain <player|ip>");
      m.put("usage-report", "{prefix}&cUsage: &f/proxyshield report <player|ip> <vpn|clean>");
      m.put("help-ping", "&e/proxyshield ping &8- &7Ask every lookup provider once and show its response time");
      m.put("ping-header", "&8&m----&r &bProvider ping &8&m----");
      m.put("ping-ok", "&7» &f{provider} &8({host})&7: &a{ms} ms");
      m.put("ping-failed", "&7» &f{provider} &8({host})&7: &cfailed &8({reason})");
      m.put("reason-hosting", "datacenter network ({isp})");
      m.put("reason-proxy", "VPN or proxy ({isp})");
      m.put("reason-ip_list", "known VPN, proxy, Tor or datacenter address");
      m.put("reason-tor", "Tor network");
      m.put("reason-asn", "blocked network ({isp})");
      m.put("reason-suspicious", "suspicious connection");
      m.put("reason-country", "your country ({country}) is not allowed here");
      m.put("reason-lookup_failed", "the check could not be completed, try again in a minute");
      m.put("doctor-header", "&8&m----&r &bProxyShield doctor &8&m----");
      m.put("doctor-intel-off", "&e! &7PaperStream Intel database is switched off (detection.intel.enabled).");
      m.put("doctor-intel-missing", "&c✖ &7PaperStream Intel database is not loaded yet. Run &f/proxyshield refresh&7.");
      m.put("doctor-intel-stale", "&c✖ &7PaperStream Intel data is &f{hours} h &7old, VPN hits no longer refuse on their own.");
      m.put("doctor-intel-ok", "&a✔ &7PaperStream Intel database loaded, data &f{hours} h &7old ({nodes} nodes).");
      m.put("doctor-lists-empty", "&c✖ &7No IP list is loaded. Check the sources under lists.");
      m.put("doctor-lists-ok", "&a✔ &7IP lists: {sources} sources, {failed} failed, last update {hours} h ago.");
      m.put("doctor-network-missing", "&c✖ &7The network feed (detection.network-data.source) is not loaded.");
      m.put("doctor-providers-none", "&c✖ &7No provider is enabled, only local data decides.");
      m.put("doctor-providers-tripped", "&c✖ &7Providers paused after errors: &f{ids}");
      m.put("doctor-providers-ok", "&a✔ &7{count} providers ready.");
      m.put("doctor-dry-run", "&e! &7Dry run is on: nobody is kicked.");
      m.put("doctor-fail-closed", "&e! &7fail-closed is on: players are refused when no provider answers.");
      m.put("doctor-fast-admit", "&e! &7fast-admit is &f{mode}&7: during waves home networks are let in without a lookup.");
      m.put("doctor-result-ok", "&aEverything looks fine.");
      m.put("doctor-result-problems", "&c{count} problem(s) found.");
      m.put("explain-header", "&8&m----&r &bExplain &f{target} &7({ip}) &8&m----");
      m.put("explain-own-lists", "&71. Own lists: whitelist &f{whitelist}&7, blacklist &f{blacklist}");
      m.put("explain-address", "&72. Address: local &f{local}&7, bogon &f{bogon}");
      m.put("explain-lists", "&73. Downloaded IP lists: match &f{match}");
      m.put("explain-intel", "&74. PaperStream Intel: score &f{score}&7/{required} &8(&7{reasons}&8) &7network &f{network}&7, {country}, {asn}");
      m.put("explain-intel-none", "&74. PaperStream Intel: nothing known about this address");
      m.put("explain-intel-missing", "&74. PaperStream Intel: database not loaded");
      m.put("explain-cache", "&75. Cached provider answer: &f{cached}");
      m.put("report-local", "{prefix}&cLocal and reserved addresses cannot be reported.");
      m.put("report-sent-vpn", "{prefix}&aReported to PaperStream Intel as VPN or proxy. Thanks!");
      m.put("report-sent-clean", "{prefix}&aReported to PaperStream Intel as wrongly blocked. Thanks!");
      m.put("report-whitelist-hint", "{prefix}&7To let the player in right now: &f/proxyshield whitelist add {ip}");
      m.put("report-failed", "{prefix}&cThe report could not be sent (answer {status}).");
      m.put("info-decisions", "&7Refused by the local PaperStream Intel copy: &f{intel}&7, let in unchecked: &f{unchecked}");
      m.put("doctor-unchecked", "&c✖ &f{count} &7players were let in unchecked because no provider answered. Check the providers above or turn on detection.intel.");
      m.put("help-allow", "&e/proxyshield allow <code> [minutes] &8- &7Let a refused player through with the code from the kick screen");
      m.put("fp-report-footer", "{prefix}&7Copy the lines above into a new issue: &f{url}");
      m.put("help-fpreport", "&e/proxyshield fpreport <player|ip> &8- &7Anonymous report for a wrongly blocked player");
      m.put("help-update", "&e/proxyshield update [install] &8- &7Check for a newer version, or stage it");
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

      m.put("help-alts", "&e/proxyshield alts <ip|player> &8- &7Accounts seen on the same address");
      m.put("list-added-timed", "{prefix}&aAdded &f{entry} &ato the {list}, expires {duration}.");
      m.put("list-info", "&7{list} &f{entry}&7: reason &f{reason}&7, added by &f{by} &7{added}, expires &f{expires}");
      m.put("list-info-config", "{prefix}&f{entry} &7comes from config.yml and has no details.");
      m.put("list-info-missing", "{prefix}&f{entry} &7is not on the {list}.");
      m.put("list-purged", "{prefix}&aRemoved &f{count} &ain-game entries from the {list}.");
      m.put("alts-usage", "{prefix}&cUsage: &f/proxyshield alts <ip|player>");
      m.put("alts-disabled", "{prefix}&7Account history is off (alts.enabled in config.yml).");
      m.put("alts-none", "{prefix}&7No address on record for &f{target}&7.");
      m.put("alts-header", "&8&m--------&r &c&lAccounts for {target} &8&m--------");
      m.put("alts-line", "&f{ip} &8(&f{count}&8)&7: &f{accounts}");
      m.put("time-in", "in {time}");
      m.put("time-ago", "{time} ago");
      m.put("word-unknown", "unknown");
      m.put("word-never", "never");
      m.put("restricted-server", "{prefix}&cYou cannot join &f{server} &cfrom this connection.");

      // Insertion order is kept so the generated message files stay grouped and readable.
      return Collections.unmodifiableMap(m);
   }
}
