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

package de.lucasthcr.bridgesave.proxyshield.command;

import de.lucasthcr.bridgesave.proxyshield.ProxyShieldCore;
import de.lucasthcr.bridgesave.proxyshield.check.AltTracker;
import de.lucasthcr.bridgesave.proxyshield.check.AppealStore;
import de.lucasthcr.bridgesave.proxyshield.check.CheckEngine;
import de.lucasthcr.bridgesave.proxyshield.check.CheckVerdict;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.lookup.FailoverLookupService;
import de.lucasthcr.bridgesave.proxyshield.lookup.IpLookupService;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import de.lucasthcr.bridgesave.proxyshield.message.Messages;
import de.lucasthcr.bridgesave.proxyshield.net.IpAddresses;
import de.lucasthcr.bridgesave.proxyshield.net.ManagedIpList;
import de.lucasthcr.bridgesave.proxyshield.platform.ShieldPlayer;
import de.lucasthcr.bridgesave.proxyshield.stats.Statistics;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The {@code /proxyshield} command, implemented once and shared by every platform.
 * <p>
 * Anything that can block (a lookup, a list download) is pushed onto an async task before it runs,
 * so no subcommand can stall the server thread. All text comes from the active message file.
 */
public final class CommandHandler {

   public static final String PERMISSION = "proxyshield.admin";

   private static final List<String> SUBCOMMANDS = List.of(
         "help", "info", "providers", "reload", "stats", "check", "lookup", "refresh", "recheck",
         "whitelist", "blacklist", "alts", "clearcache", "dryrun", "silent", "reporting", "update", "fpreport", "allow", "doctor", "explain", "report");

   private static final List<String> LIST_ACTIONS =
         List.of("add", "remove", "list", "info", "purge");

   /** Durations offered when completing {@code whitelist add <entry> }. */
   private static final List<String> DURATIONS = List.of("30m", "1h", "12h", "1d", "7d", "30d");

   /** Whoever ran the command; a player or the console. */
   public interface Sender {
      void send(String legacyMessage);

      boolean hasPermission(String permission);

      /** Who is running the command, recorded on list entries they add. */
      default String name() {
         return "console";
      }
   }

   private final ProxyShieldCore core;

   public CommandHandler(ProxyShieldCore core) {
      this.core = core;
   }

   private Messages messages() {
      Messages current = core.messages();
      return current == null ? Messages.builtIn() : current;
   }

   private void send(Sender sender, String key) {
      sender.send(messages().get(key));
   }

   private void send(Sender sender, String key, Map<String, String> placeholders) {
      sender.send(messages().get(key, placeholders));
   }

   private static Map<String, String> of(String... pairs) {
      Map<String, String> map = new LinkedHashMap<>();
      for (int i = 0; i + 1 < pairs.length; i += 2) {
         map.put(pairs[i], pairs[i + 1]);
      }
      return map;
   }

   public void execute(Sender sender, String[] args) {
      if (!sender.hasPermission(PERMISSION)) {
         send(sender, "no-permission");
         return;
      }

      if (args.length == 0) {
         sendHelp(sender);
         return;
      }

      switch (args[0].toLowerCase(Locale.ROOT)) {
         case "help" -> sendHelp(sender);
         case "info" -> sendInfo(sender);
         case "providers" -> sendProviders(sender);
         case "stats" -> sendStats(sender);
         case "reload" -> doReload(sender);
         case "refresh" -> doRefresh(sender);
         case "recheck" -> doRecheck(sender);
         case "clearcache" -> doClearCache(sender);
         case "check" -> doCheck(sender, args);
         case "fpreport" -> doFalsePositiveReport(sender, args);
         case "allow" -> doAllow(sender, args);
         case "doctor" -> doDoctor(sender);
         case "explain" -> doExplain(sender, args);
         case "report" -> doReport(sender, args);
         case "lookup" -> doLookup(sender, args);
         case "whitelist" -> doListCommand(sender, args, core.whitelist(), "whitelist");
         case "blacklist" -> doListCommand(sender, args, core.blacklist(), "blacklist");
         case "alts" -> doAlts(sender, args);
         case "reporting" -> doReporting(sender, args);
         case "update" -> doUpdate(sender, args);
         case "dryrun" -> sendToggleHint(sender, "detection.dry-run", core.config().dryRun());
         case "silent" -> sendToggleHint(sender, "notifications.silent", core.config().silent());
         default -> {
            send(sender, "unknown-subcommand", of("input", args[0]));
            sendHelp(sender);
         }
      }
   }

   public List<String> tabComplete(Sender sender, String[] args) {
      if (!sender.hasPermission(PERMISSION)) {
         return List.of();
      }

      if (args.length <= 1) {
         return filter(SUBCOMMANDS, args.length == 0 ? "" : args[0]);
      }

      String sub = args[0].toLowerCase(Locale.ROOT);
      if (args.length == 2 && (sub.equals("whitelist") || sub.equals("blacklist"))) {
         return filter(LIST_ACTIONS, args[1]);
      }
      if (args.length == 3 && sub.equals("whitelist") && args[1].equalsIgnoreCase("remove")) {
         return filter(core.whitelist().runtimeEntries(), args[2]);
      }
      if (args.length == 3 && sub.equals("blacklist") && args[1].equalsIgnoreCase("remove")) {
         return filter(core.blacklist().runtimeEntries(), args[2]);
      }
      if (args.length == 3 && (sub.equals("whitelist") || sub.equals("blacklist"))
            && args[1].equalsIgnoreCase("info")) {
         ManagedIpList list = sub.equals("whitelist") ? core.whitelist() : core.blacklist();
         return filter(list.runtimeEntries(), args[2]);
      }
      if (args.length == 4 && (sub.equals("whitelist") || sub.equals("blacklist"))
            && args[1].equalsIgnoreCase("add")) {
         return filter(DURATIONS, args[3]);
      }
      if (args.length == 2 && (sub.equals("check") || sub.equals("lookup")
            || sub.equals("alts") || sub.equals("fpreport") || sub.equals("explain") || sub.equals("report"))) {
         List<String> names = new ArrayList<>();
         for (ShieldPlayer online : core.platform().onlinePlayers()) {
            names.add(online.name());
         }
         return filter(names, args[1]);
      }
      if (args.length == 3 && sub.equals("report")) {
         return filter(List.of("vpn", "clean"), args[2]);
      }
      return List.of();
   }

   private static List<String> filter(List<String> candidates, String prefix) {
      String needle = prefix.toLowerCase(Locale.ROOT);
      List<String> out = new ArrayList<>();
      for (String candidate : candidates) {
         if (candidate.toLowerCase(Locale.ROOT).startsWith(needle)) {
            out.add(candidate);
         }
      }
      return out;
   }

   // ------------------------------------------------------------ subcommands

   private void sendHelp(Sender sender) {
      send(sender, "help-header", of("version", core.platform().version()));
      for (String key : List.of("help-info", "help-stats", "help-check", "help-lookup",
            "help-whitelist", "help-blacklist", "help-alts", "help-refresh", "help-recheck",
            "help-clearcache", "help-reporting", "help-update", "help-fpreport", "help-allow", "help-doctor", "help-explain", "help-report", "help-reload", "help-footer")) {
         send(sender, key);
      }
   }

   private void sendInfo(Sender sender) {
      ShieldConfig config = core.config();
      Messages m = messages();

      send(sender, "info-header");
      send(sender, "info-version", of(
            "version", core.platform().version(),
            "platform", core.platform().name(),
            "locale", m.locale()));
      send(sender, config.dryRun() ? "info-mode-dry-run" : "info-mode-enforcing");
      send(sender, "info-alerts", of(
            "silent", m.get(config.silent() ? "silent-mode" : "broadcast-mode"),
            "webhook", onOff(config.discordUsable()),
            "logfile", onOff(config.logToFile())));
      send(sender, "info-detection", of(
            "lists", onOff(config.useLists()),
            "api", onOff(config.useApi()),
            "proxy", onOff(config.blockProxy()),
            "hosting", onOff(config.blockHosting())));

      if (config.countryEnabled()) {
         send(sender, "info-country-on", of(
               "mode", config.countryMode().name().toLowerCase(Locale.ROOT),
               "codes", String.join(", ", config.countryCodes()),
               "unknown", onOff(config.blockUnknownCountry())));
      } else {
         send(sender, "info-country-off");
      }

      send(sender, "info-lists", of(
            "ranges", String.valueOf(core.lists().ranges().rangeCount()),
            "ok", String.valueOf(core.lists().sourceCount() - core.lists().failedSourceCount()),
            "total", String.valueOf(core.lists().sourceCount())));
      send(sender, "info-managed", of(
            "whitelist", String.valueOf(core.whitelist().rangeCount()),
            "blacklist", String.valueOf(core.blacklist().rangeCount())));
      send(sender, "info-provider", of(
            "provider", core.lookups().primaryHost()
                  + " (+" + Math.max(0, core.lookups().providerCount() - 1) + ")",
            "failmode", m.get(config.failClosed() ? "fail-closed" : "fail-open")));
      send(sender, "info-lookup-mode", of(
            "mode", config.lookupMode().name().toLowerCase(Locale.ROOT),
            "score", String.format(Locale.ROOT, "%.1f", config.requiredScore()),
            "count", String.valueOf(core.lookups().providerCount())));
      send(sender, "info-storage", of(
            "storage", core.storage().name(),
            "shared", onOff(core.storage().shared())));
      send(sender, "info-decisions", of(
            "intel", String.valueOf(core.statistics().intelDecided()),
            "unchecked", String.valueOf(core.statistics().uncheckedAdmitted())));
      send(sender, "info-signals", of(
            "asn", onOff(config.asnEnabled()),
            "rdns", onOff(config.rdnsEnabled()),
            "heuristics", onOff(config.heuristicsEnabled()),
            "trust", onOff(config.trustEnabled())));
   }

   /** One line per configured provider, with its live health. */
   private void sendProviders(Sender sender) {
      Messages m = messages();
      List<IpLookupService> providers = core.lookups().providers();
      if (providers.isEmpty()) {
         send(sender, "providers-none");
         return;
      }

      send(sender, "providers-header");
      for (IpLookupService provider : providers) {
         send(sender, "providers-line", of(
               "id", provider.id(),
               "host", provider.host(),
               "weight", String.format(Locale.ROOT, "%.1f", provider.weight()),
               "status", m.get(provider.tripped()
                     ? "provider-status-tripped" : "provider-status-ok"),
               "queries", String.valueOf(provider.queryCount()),
               "failures", String.valueOf(provider.failureCount()),
               "latency", String.valueOf(provider.averageLatencyMillis())));
      }
   }

   private void sendStats(Sender sender) {
      Statistics stats = core.statistics();
      send(sender, "stats-header");
      send(sender, "stats-uptime", of("uptime", stats.uptimeFormatted()));
      send(sender, "stats-checked", of("checked", String.valueOf(stats.checked())));
      send(sender, "stats-blocked", of(
            "blocked", String.valueOf(stats.blocked()),
            "dryrun", stats.wouldHaveBlocked() > 0
                  ? " &8(&6" + stats.wouldHaveBlocked() + " dry-run&8)" : ""));
      send(sender, "stats-reasons-1", of(
            "list", String.valueOf(stats.count(CheckVerdict.Reason.IP_LIST)),
            "proxy", String.valueOf(stats.count(CheckVerdict.Reason.PROXY)),
            "hosting", String.valueOf(stats.count(CheckVerdict.Reason.HOSTING))));
      send(sender, "stats-reasons-2", of(
            "country", String.valueOf(stats.count(CheckVerdict.Reason.COUNTRY)),
            "blacklist", String.valueOf(stats.count(CheckVerdict.Reason.BLACKLISTED)),
            "failed", String.valueOf(stats.count(CheckVerdict.Reason.LOOKUP_FAILED))));
      send(sender, "stats-reasons-3", of(
            "network", String.valueOf(stats.count(CheckVerdict.Reason.ASN)
                  + stats.count(CheckVerdict.Reason.ISP)),
            "limit", String.valueOf(stats.count(CheckVerdict.Reason.CONNECTION_LIMIT)),
            "bogon", String.valueOf(stats.count(CheckVerdict.Reason.BOGON))));
      send(sender, "stats-allowed", of(
            "bypass", String.valueOf(stats.count(CheckVerdict.Reason.BYPASS_PERMISSION)),
            "whitelist", String.valueOf(stats.count(CheckVerdict.Reason.WHITELISTED_IP)
                  + stats.count(CheckVerdict.Reason.WHITELISTED_PLAYER))));
      send(sender, "stats-lookups", of(
            "lookups", String.valueOf(core.lookups().lookups()),
            "cachesize", String.valueOf(core.lookups().cacheSize()),
            "cachehits", String.valueOf(core.lookups().cacheHits()),
            "limited", String.valueOf(core.lookups().rateLimitedCount()),
            "failed", String.valueOf(core.lookups().failureCount())));
      send(sender, "stats-efficiency", of(
            "coalesced", String.valueOf(core.lookups().coalescedCount()),
            "budget", String.valueOf(core.lookups().budgetExceededCount()),
            "trusted", String.valueOf(core.trust().size())));
      send(sender, "stats-webhook", of(
            "sent", String.valueOf(core.webhook().sentCount()),
            "dropped", String.valueOf(core.webhook().droppedCount()),
            "queued", String.valueOf(core.webhook().queueSize())));
   }

   private void doReload(Sender sender) {
      ProxyShieldCore.ReloadReport report = core.reload();
      if (report.success()) {
         send(sender, "reload-success");
         if (report.config().dryRun()) {
            send(sender, "reload-dry-run");
         }
      } else {
         send(sender, "reload-failed", of("error", String.valueOf(report.error())));
         send(sender, "reload-kept");
      }
   }

   private void doRefresh(Sender sender) {
      if (core.lists().isRefreshing()) {
         send(sender, "refresh-running");
         return;
      }

      send(sender, "refresh-start");
      core.platform().runAsync(() -> {
         core.refreshIntel();
         if (core.refreshLists()) {
            send(sender, "refresh-done", of(
                  "ranges", String.valueOf(core.lists().ranges().rangeCount()),
                  "addresses", String.valueOf(core.lists().ranges().ipv4AddressCount())));
         } else {
            String error = core.lists().lastError();
            send(sender, "refresh-failed", of("error", error == null ? "unknown" : error));
         }
      });
   }

   private void doRecheck(Sender sender) {
      send(sender, "recheck-start");
      core.platform().runAsync(() -> {
         int disconnected = core.recheckOnlinePlayers();
         if (core.config().dryRun()) {
            send(sender, "recheck-dry-run");
         } else {
            send(sender, "recheck-done", of("count", String.valueOf(disconnected)));
         }
      });
   }

   private void doUpdate(Sender sender, String[] args) {
      boolean install = args.length >= 2 && args[1].equalsIgnoreCase("install");
      send(sender, "update-checking");
      core.platform().runAsync(() -> {
         try {
            if (install) {
               var staged = core.updates().stage();
               switch (staged.status()) {
                  case STAGED, ALREADY_STAGED -> send(sender, "update-staged", of("version", String.valueOf(staged.version())));
                  case UP_TO_DATE -> send(sender, "update-latest", of("current", core.platform().version()));
                  case DISABLED -> send(sender, "update-no-folder");
                  default -> send(sender, "update-failed", of("error", String.valueOf(staged.detail())));
               }
               return;
            }
            var result = core.updates().checkNow();
            if (result.updateAvailable()) {
               send(sender, "update-found", of("version", result.best().versionNumber(),
                     "current", core.platform().version(), "source", result.best().sourceName()));
            } else if (result.found()) {
               send(sender, "update-latest", of("current", core.platform().version()));
            } else {
               send(sender, "update-failed", of("error", "no source answered"));
            }
         } catch (RuntimeException failure) {
            send(sender, "update-failed", of("error", String.valueOf(failure.getMessage())));
         }
      });
   }

   private void doReporting(Sender sender, String[] args) {
      if (args.length >= 2 && args[1].equalsIgnoreCase("forget")) {
         core.platform().runAsync(() -> {
            int deleted = core.reporter().forget();
            if (deleted == -2) {
               send(sender, "reporting-nothing");
            } else if (deleted < 0) {
               send(sender, "reporting-failed");
            } else {
               send(sender, "reporting-forgotten", of("count", String.valueOf(deleted)));
            }
         });
         return;
      }
      var status = core.reporter().status();
      send(sender, status.enabled() ? "reporting-on" : "reporting-off", of(
            "url", status.url(),
            "queued", String.valueOf(status.queued()),
            "sent", String.valueOf(status.sent()),
            "error", status.lastError().isEmpty() ? "none" : status.lastError()));
   }

   private void doClearCache(Sender sender) {
      int size = core.lookups().cacheSize();
      core.lookups().clearCache();
      send(sender, "cache-cleared", of("count", String.valueOf(size)));
   }

   private void doCheck(Sender sender, String[] args) {
      if (args.length < 2) {
         send(sender, "usage-check");
         return;
      }

      String target = args[1];
      String ip = resolveIp(target);
      if (ip == null) {
         send(sender, "player-not-found", of("input", target));
         return;
      }

      send(sender, "check-start", of("ip", ip));
      core.platform().runAsync(() -> {
         // Deliberately without the join heuristics: an admin running /proxyshield check is not a
         // login, and counting it would move the very rate windows the command is meant to report.
         CheckEngine engine = adminEngine();
         CheckVerdict verdict = engine.check(target, null, ip, CheckEngine.PermissionProbe.NONE);
         LookupResult lookup = verdict.lookup();

         send(sender, "check-header");
         send(sender, "check-target", of("target", target, "ip", ip));
         send(sender, verdict.blocked() ? "check-verdict-blocked" : "check-verdict-allowed",
               of("reason", verdict.describe()));

         if (lookup.resolved()) {
            send(sender, "check-country", of(
                  "code", lookup.countryOrUnknown(),
                  "name", countryName(lookup)));
            send(sender, "check-isp", of("isp", lookup.ispOrUnknown()));
            send(sender, "check-flags", of(
                  "proxy", yesNo(lookup.proxy()),
                  "hosting", yesNo(lookup.hosting())));
            send(sender, "check-score", of(
                  "score", String.format(Locale.ROOT, "%.1f", lookup.confidence()),
                  "required", String.format(Locale.ROOT, "%.1f", core.config().requiredScore()),
                  "signals", lookup.sourceSummary()));
         } else {
            send(sender, "check-unresolved", of("error", String.valueOf(lookup.failureReason())));
         }

         send(sender, "check-lists", of(
               "list", yesNo(core.lists().matches(ip)),
               "whitelist", yesNo(core.whitelist().matches(ip)),
               "blacklist", yesNo(core.blacklist().matches(ip))));

         sendProviderBreakdown(sender, ip);

         if (verdict.blocked() && core.config().dryRun()) {
            send(sender, "check-dry-run-note");
         }
      });
   }

   /**
    * Asks every provider individually and prints what each one said.
    * <p>
    * Without this, a false positive report can only be answered with "a provider flagged it", and
    * an operator has no way to tell which service to drop or down-weight.
    */
   private void sendProviderBreakdown(Sender sender, String ip) {
      List<FailoverLookupService.ProviderAnswer> answers = core.lookups().diagnose(ip);
      if (answers.isEmpty()) {
         return;
      }

      Messages m = messages();
      send(sender, "check-provider-header");
      for (FailoverLookupService.ProviderAnswer answer : answers) {
         LookupResult result = answer.result();
         String verdict;
         String detail;
         if (!result.resolved()) {
            verdict = yesNo(false);
            detail = String.valueOf(result.failureReason());
         } else if (result.proxy() || result.hosting() || result.tor()) {
            verdict = yesNo(true);
            detail = (result.proxy() ? "proxy " : "") + (result.hosting() ? "hosting " : "")
                  + (result.tor() ? "tor" : "");
         } else {
            verdict = yesNo(false);
            detail = "clean";
         }

         send(sender, "check-provider-line", of(
               "id", answer.id(),
               "weight", String.format(Locale.ROOT, "%.1f", answer.weight()),
               "verdict", verdict,
               "detail", detail.trim()));
      }
   }

   /** Lets a refused player through for a while, with the code from the kick screen. */
   private void doAllow(Sender sender, String[] args) {
      if (args.length < 2) {
         send(sender, "usage-allow");
         return;
      }
      Optional<AppealStore.Entry> entry = core.appeals().resolve(args[1]);
      if (entry.isEmpty()) {
         send(sender, "allow-unknown");
         return;
      }
      int minutes = core.config().appealAllowMinutes();
      if (args.length > 2) {
         try {
            minutes = Math.max(1, Math.min(10080, Integer.parseInt(args[2])));
         } catch (NumberFormatException ignored) {
            send(sender, "usage-allow");
            return;
         }
      }
      String code = args[1].toUpperCase(Locale.ROOT);
      try {
         // An address that is already on the list stays as it is, the player gets through either way.
         core.whitelist().add(entry.get().ip(), "appeal " + code, sender.name(), minutes * 60_000L);
         send(sender, "allow-done", of("ip", entry.get().ip(), "minutes", String.valueOf(minutes),
               "player", entry.get().player(), "code", code));
      } catch (IOException failure) {
         send(sender, "allow-failed", of("error", String.valueOf(failure.getMessage())));
      }
   }

   private void doFalsePositiveReport(Sender sender, String[] args) {
      if (args.length < 2) {
         send(sender, "usage-fpreport");
         return;
      }

      String target = args[1];
      String ip = resolveIp(target);
      if (ip == null) {
         send(sender, "player-not-found", of("input", target));
         return;
      }

      send(sender, "fp-report-start");
      core.platform().runAsync(() -> {
         CheckEngine engine = new CheckEngine(core.config(), core.lists(), core.lookups(),
               core.whitelist(), core.blacklist(), core.reverseDns(), core.trust(), null);
         CheckVerdict verdict = engine.check(target, null, ip, CheckEngine.PermissionProbe.NONE);
         LookupResult lookup = verdict.lookup();
         var network = core.networkData().loaded() ? core.networkData().classify(ip) : null;

         List<String> lines = new ArrayList<>();
         lines.add("ProxyShield false positive report | " + core.platform().version() + " | "
               + core.platform().name());
         lines.add("verdict: " + (verdict.blocked() ? "blocked" : "allowed") + " | " + verdict.describe());
         if (network != null) {
            String kind = network.endUser() ? "end user" : network.hosting() ? "hosting"
                  : network.noUsers() ? "no measured users" : "other";
            lines.add("network: " + kind + " | " + network.country() + " | AS" + network.asn());
         } else {
            lines.add("network: not in the feed");
         }
         if (lookup.resolved()) {
            lines.add("isp: " + lookup.ispOrUnknown() + " | country: " + lookup.countryOrUnknown());
            lines.add("score: " + String.format(Locale.ROOT, "%.1f", lookup.confidence()) + " of "
                  + String.format(Locale.ROOT, "%.1f", core.config().requiredScore())
                  + " | signals: " + lookup.sourceSummary());
         } else {
            lines.add("lookup failed: " + lookup.failureReason());
         }
         lines.add("on a list: " + yesNo(core.lists().matches(ip)));
         StringBuilder providers = new StringBuilder("providers:");
         for (FailoverLookupService.ProviderAnswer answer : core.lookups().diagnose(ip)) {
            LookupResult result = answer.result();
            String said = !result.resolved() ? "error"
                  : result.proxy() || result.hosting() || result.tor() ? "flagged" : "clean";
            providers.append(' ').append(answer.id()).append('(')
                  .append(String.format(Locale.ROOT, "%.1f", answer.weight())).append(")=").append(said);
         }
         lines.add(providers.toString());

         // Weder Adresse noch Spielername duerfen im Text landen
         for (String line : lines) {
            send(sender, "fp-report-line", of("line",
                  line.replace(ip, "<ip>").replace(target, "<player>")));
         }
         send(sender, "fp-report-footer", of("url", "https://codeberg.org/LucasTHCR/ProxyShield/issues"));
      });
   }

   private void doLookup(Sender sender, String[] args) {
      if (args.length < 2) {
         send(sender, "usage-lookup");
         return;
      }

      String ip = resolveIp(args[1]);
      if (ip == null) {
         send(sender, "player-not-found", of("input", args[1]));
         return;
      }

      send(sender, "lookup-start", of("ip", ip));
      core.platform().runAsync(() -> {
         core.lookups().invalidate(ip);
         LookupResult result = core.lookups().lookup(ip);
         if (!result.resolved()) {
            send(sender, "lookup-failed", of("error", String.valueOf(result.failureReason())));
            return;
         }
         send(sender, "lookup-details", of(
               "asn", result.asnOrUnknown(),
               "type", result.connectionType() == null ? "?" : result.connectionType(),
               "score", String.format(Locale.ROOT, "%.1f", result.confidence()),
               "sources", result.sourceSummary()));
         send(sender, "lookup-result", of(
               "ip", ip,
               "country", result.countryOrUnknown(),
               "proxy", yesNo(result.proxy()),
               "hosting", yesNo(result.hosting()),
               "isp", result.ispOrUnknown()));
      });
   }

   private void doListCommand(Sender sender, String[] args, ManagedIpList list, String label) {
      if (args.length < 2) {
         send(sender, "list-usage", of("list", label));
         return;
      }

      switch (args[1].toLowerCase(Locale.ROOT)) {
         case "list" -> {
            List<String> fromConfig = list.configEntries();
            List<String> atRuntime = list.runtimeEntries();
            String empty = messages().get("list-empty");

            send(sender, "list-header", of("list", label));
            send(sender, "list-config", of(
                  "count", String.valueOf(fromConfig.size()),
                  "entries", fromConfig.isEmpty() ? empty : String.join(", ", fromConfig)));
            List<String> described = new ArrayList<>(atRuntime.size());
            for (String entry : atRuntime) {
               ManagedIpList.Details details = list.details(entry);
               described.add(details == null || details.permanent()
                     ? entry
                     : entry + " (" + remaining(details.expiresAt()) + ")");
            }
            send(sender, "list-runtime", of(
                  "count", String.valueOf(atRuntime.size()),
                  "entries", atRuntime.isEmpty() ? empty : String.join(", ", described)));
            send(sender, "list-ranges", of("count", String.valueOf(list.rangeCount())));
         }
         case "add" -> {
            if (args.length < 3) {
               send(sender, "list-usage", of("list", label));
               return;
            }
            String entry = resolveEntry(args[2]);
            if (!ManagedIpList.isAcceptable(entry)) {
               send(sender, "invalid-entry", of("input", args[2]));
               return;
            }
            // Optional: a duration, then a free-text reason.
            long duration = 0L;
            int reasonFrom = 3;
            if (args.length > 3) {
               long parsed = parseDuration(args[3]);
               if (parsed > 0L) {
                  duration = parsed;
                  reasonFrom = 4;
               } else if (args[3].equalsIgnoreCase("perm")
                     || args[3].equalsIgnoreCase("permanent")) {
                  reasonFrom = 4;
               }
            }
            String reason = args.length > reasonFrom
                  ? String.join(" ", Arrays.copyOfRange(args, reasonFrom, args.length))
                  : null;
            try {
               boolean added = list.add(entry, reason, sender.name(), duration);
               send(sender, added ? (duration > 0L ? "list-added-timed" : "list-added")
                     : "list-already",
                     of("entry", entry, "list", label, "duration", remaining(
                           System.currentTimeMillis() + duration)));
            } catch (IOException failure) {
               send(sender, "list-save-failed",
                     of("list", label, "error", String.valueOf(failure.getMessage())));
            }
         }
         case "remove" -> {
            if (args.length < 3) {
               send(sender, "list-usage", of("list", label));
               return;
            }
            String entry = resolveEntry(args[2]);
            try {
               send(sender, list.remove(entry) ? "list-removed" : "list-not-runtime",
                     of("entry", entry, "list", label));
            } catch (IOException failure) {
               send(sender, "list-save-failed",
                     of("list", label, "error", String.valueOf(failure.getMessage())));
            }
         }
         case "info" -> {
            if (args.length < 3) {
               send(sender, "list-usage", of("list", label));
               return;
            }
            String entry = resolveEntry(args[2]);
            ManagedIpList.Details details = list.details(entry);
            if (details == null) {
               send(sender, list.contains(entry, true) ? "list-info-config" : "list-info-missing",
                     of("entry", entry, "list", label));
               return;
            }
            String unknown = messages().get("word-unknown");
            send(sender, "list-info", of(
                  "entry", entry,
                  "list", label,
                  "reason", details.reason() == null ? unknown : details.reason(),
                  "by", details.addedBy() == null ? unknown : details.addedBy(),
                  "added", details.addedAt() > 0L ? ago(details.addedAt()) : unknown,
                  "expires", details.permanent() ? messages().get("word-never")
                        : remaining(details.expiresAt())));
         }
         case "purge" -> {
            try {
               send(sender, "list-purged", of("count", String.valueOf(list.purge()),
                     "list", label));
            } catch (IOException failure) {
               send(sender, "list-save-failed",
                     of("list", label, "error", String.valueOf(failure.getMessage())));
            }
         }
         default -> send(sender, "list-usage", of("list", label));
      }
   }

   private void doAlts(Sender sender, String[] args) {
      if (args.length < 2) {
         send(sender, "alts-usage");
         return;
      }
      if (!core.config().altsEnabled()) {
         send(sender, "alts-disabled");
         return;
      }
      String target = args[1];
      core.platform().runAsync(() -> {
         Set<String> addresses = new LinkedHashSet<>();
         if (IpAddresses.isValid(target)) {
            addresses.add(target);
         } else {
            core.platform().player(target).map(ShieldPlayer::ip).ifPresent(addresses::add);
            addresses.addAll(core.alts().addressesOf(target));
         }
         if (addresses.isEmpty()) {
            send(sender, "alts-none", of("target", target));
            return;
         }
         send(sender, "alts-header", of("target", target));
         for (String address : addresses) {
            List<AltTracker.Sighting> accounts = core.alts().accountsOn(address);
            List<String> names = new ArrayList<>(accounts.size());
            for (AltTracker.Sighting sighting : accounts) {
               names.add(sighting.name() + " (" + ago(sighting.lastSeen()) + ")");
            }
            send(sender, "alts-line", of(
                  "ip", address,
                  "count", String.valueOf(accounts.size()),
                  "accounts", names.isEmpty() ? messages().get("list-empty")
                        : String.join(", ", names)));
         }
      });
   }

   /**
    * Reads {@code 30m}, {@code 12h}, {@code 7d}, {@code 2w} or {@code 90s}.
    *
    * @return the duration in milliseconds, or 0 if the text is not a duration
    */
   static long parseDuration(String raw) {
      if (raw == null || raw.length() < 2) {
         return 0L;
      }
      String text = raw.trim().toLowerCase(Locale.ROOT);
      char unit = text.charAt(text.length() - 1);
      long factor = switch (unit) {
         case 's' -> 1_000L;
         case 'm' -> 60_000L;
         case 'h' -> 3_600_000L;
         case 'd' -> 86_400_000L;
         case 'w' -> 604_800_000L;
         default -> 0L;
      };
      if (factor == 0L) {
         return 0L;
      }
      try {
         long amount = Long.parseLong(text.substring(0, text.length() - 1));
         return amount > 0L && amount < 100_000L ? amount * factor : 0L;
      } catch (NumberFormatException notADuration) {
         return 0L;
      }
   }

   /** "in 2h 5m" style text for a moment in the future. */
   private String remaining(long at) {
      return messages().get("time-in", of("time", span(at - System.currentTimeMillis())));
   }

   /** "3d ago" style text for a moment in the past. */
   private String ago(long at) {
      return messages().get("time-ago", of("time", span(System.currentTimeMillis() - at)));
   }

   private static String span(long millis) {
      long minutes = Math.max(0L, millis) / 60_000L;
      if (minutes < 1L) {
         return "<1m";
      }
      long days = minutes / 1440L;
      long hours = minutes % 1440L / 60L;
      long rest = minutes % 60L;
      if (days > 0L) {
         return hours > 0L ? days + "d " + hours + "h" : days + "d";
      }
      return hours > 0L ? hours + "h " + rest + "m" : rest + "m";
   }

   private void sendToggleHint(Sender sender, String key, boolean enabled) {
      send(sender, "toggle-state", of(
            "key", key,
            "state", messages().get(enabled ? "enabled" : "disabled")));
      send(sender, "toggle-hint");
   }

   /** Accepts an IP literal directly, otherwise resolves an online player's address. */
   private CheckEngine adminEngine() {
      return new CheckEngine(core.config(), core.lists(), core.lookups(), core.whitelist(), core.blacklist(),
            core.reverseDns(), core.trust(), null).withNetworkData(core.networkData()).withIntel(core.intel());
   }

   private static String hoursAgo(long epochMillis) {
      if (epochMillis <= 0) {
         return "?";
      }
      return String.format(Locale.ROOT, "%.1f", (System.currentTimeMillis() - epochMillis) / 3_600_000.0);
   }

   private void doDoctor(Sender sender) {
      ShieldConfig config = core.config();
      send(sender, "doctor-header");
      int problems = 0;

      if (!config.intelEnabled()) {
         send(sender, "doctor-intel-off");
      } else if (!core.intel().loaded()) {
         send(sender, "doctor-intel-missing");
         problems++;
      } else if (core.intel().stale(config.intelMaxAgeHours())) {
         send(sender, "doctor-intel-stale", of("hours", hoursAgo(core.intel().buildEpoch() * 1000L)));
         problems++;
      } else {
         send(sender, "doctor-intel-ok", of("hours", hoursAgo(core.intel().buildEpoch() * 1000L),
               "nodes", String.valueOf(core.intel().nodeCount())));
      }

      if (config.useLists()) {
         if (core.lists().ranges().isEmpty()) {
            send(sender, "doctor-lists-empty");
            problems++;
         } else {
            send(sender, "doctor-lists-ok", of("sources", String.valueOf(core.lists().sourceCount()),
                  "failed", String.valueOf(core.lists().failedSourceCount()),
                  "hours", hoursAgo(core.lists().lastRefreshMillis())));
         }
      }

      if (!config.networkDataSource().isEmpty() && !core.networkData().loaded()) {
         send(sender, "doctor-network-missing");
         problems++;
      }

      if (config.useApi()) {
         List<IpLookupService> providers = core.lookups().providers();
         List<String> tripped = new ArrayList<>();
         for (IpLookupService provider : providers) {
            if (provider.tripped()) {
               tripped.add(provider.id());
            }
         }
         if (providers.isEmpty()) {
            send(sender, "doctor-providers-none");
            problems++;
         } else if (!tripped.isEmpty()) {
            send(sender, "doctor-providers-tripped", of("ids", String.join(", ", tripped)));
            problems++;
         } else {
            send(sender, "doctor-providers-ok", of("count", String.valueOf(providers.size())));
         }
      }

      long unchecked = core.statistics().uncheckedAdmitted();
      if (unchecked > 0) {
         send(sender, "doctor-unchecked", of("count", String.valueOf(unchecked)));
         problems++;
      }
      if (config.dryRun()) {
         send(sender, "doctor-dry-run");
         problems++;
      }
      if (config.failClosed()) {
         send(sender, "doctor-fail-closed");
      }
      if (!"never".equals(config.networkFastAdmitMode())) {
         send(sender, "doctor-fast-admit", of("mode", config.networkFastAdmitMode()));
      }
      send(sender, problems == 0 ? "doctor-result-ok" : "doctor-result-problems",
            of("count", String.valueOf(problems)));
   }

   private void doExplain(Sender sender, String[] args) {
      if (args.length < 2) {
         send(sender, "usage-explain");
         return;
      }
      String target = args[1];
      String ip = resolveIp(target);
      if (ip == null) {
         send(sender, "player-not-found", of("input", target));
         return;
      }
      send(sender, "check-start", of("ip", ip));
      core.platform().runAsync(() -> {
         ShieldConfig config = core.config();
         CheckEngine engine = adminEngine();
         send(sender, "explain-header", of("target", target, "ip", ip));
         send(sender, "explain-own-lists", of(
               "whitelist", yesNo(core.whitelist().matches(ip)),
               "blacklist", yesNo(core.blacklist().matches(ip))));
         send(sender, "explain-address", of(
               "local", yesNo(IpAddresses.isLocal(ip)),
               "bogon", yesNo(IpAddresses.isBogon(ip))));
         send(sender, "explain-lists", of("match", yesNo(config.useLists() && core.lists().matches(ip))));

         var hit = engine.intelHit(ip);
         if (hit == null) {
            send(sender, core.intel().loaded() ? "explain-intel-none" : "explain-intel-missing");
         } else {
            send(sender, "explain-intel", of(
                  "score", String.valueOf(hit.score()),
                  "required", String.valueOf(config.intelBlockScore()),
                  "reasons", hit.reasons().isEmpty() ? "-" : String.join(", ", hit.reasons()),
                  "network", hit.network(),
                  "country", hit.country() == null ? "?" : hit.country(),
                  "asn", hit.asnName() == null ? "?" : hit.asnName()));
         }
         send(sender, "explain-cache", of("cached", yesNo(core.lookups().cached(ip).isPresent())));

         CheckVerdict verdict = engine.check(target, null, ip, CheckEngine.PermissionProbe.NONE);
         send(sender, verdict.blocked() ? "check-verdict-blocked" : "check-verdict-allowed",
               of("reason", verdict.describe()));
         LookupResult lookup = verdict.lookup();
         if (lookup.resolved()) {
            send(sender, "check-score", of(
                  "score", String.format(Locale.ROOT, "%.1f", lookup.confidence()),
                  "required", String.format(Locale.ROOT, "%.1f", config.requiredScore()),
                  "signals", lookup.sourceSummary()));
         } else if (lookup.failureReason() != null) {
            send(sender, "check-unresolved", of("error", String.valueOf(lookup.failureReason())));
         }
         if (verdict.blocked() && config.dryRun()) {
            send(sender, "check-dry-run-note");
         }
      });
   }

   private void doReport(Sender sender, String[] args) {
      if (args.length < 3) {
         send(sender, "usage-report");
         return;
      }
      String kind = args[2].toLowerCase(Locale.ROOT);
      if (!kind.equals("vpn") && !kind.equals("clean")) {
         send(sender, "usage-report");
         return;
      }
      String ip = resolveIp(args[1]);
      if (ip == null) {
         send(sender, "player-not-found", of("input", args[1]));
         return;
      }
      if (IpAddresses.isLocal(ip) || IpAddresses.isBogon(ip)) {
         send(sender, "report-local");
         return;
      }
      core.platform().runAsync(() -> {
         int status = core.reporter().feedback(ip, kind);
         if (status == 200) {
            send(sender, kind.equals("vpn") ? "report-sent-vpn" : "report-sent-clean");
            if (kind.equals("clean")) {
               send(sender, "report-whitelist-hint", of("ip", ip));
            }
         } else {
            send(sender, "report-failed", of("status", String.valueOf(status)));
         }
      });
   }

   private String resolveIp(String target) {
      if (IpAddresses.isValid(target)) {
         return target;
      }
      Optional<ShieldPlayer> player = core.platform().player(target);
      return player.map(ShieldPlayer::ip).orElse(null);
   }

   /** Same as {@link #resolveIp} but falls back to the raw input so CIDR entries pass through. */
   private String resolveEntry(String target) {
      if (target.indexOf('/') >= 0 || target.indexOf('-') >= 0 || IpAddresses.isValid(target)) {
         return target;
      }
      Optional<ShieldPlayer> player = core.platform().player(target);
      return player.map(ShieldPlayer::ip).orElse(target);
   }

   private String yesNo(boolean value) {
      return messages().get(value ? "word-yes" : "word-no");
   }

   private String onOff(boolean value) {
      return messages().get(value ? "word-on" : "word-off");
   }

   // Ohne Namen vom Dienst den Laendernamen aus dem Code bilden
   private static String countryName(LookupResult lookup) {
      if (lookup.countryName() != null) {
         return lookup.countryName();
      }
      String code = lookup.countryOrUnknown();
      String name = code.length() == 2
            ? new Locale("", code).getDisplayCountry(Locale.ENGLISH) : "";
      return name.isEmpty() || name.equals(code) ? "?" : name;
   }
}
