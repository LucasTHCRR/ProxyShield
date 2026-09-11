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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

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
         "whitelist", "blacklist", "clearcache", "dryrun", "silent");

   private static final List<String> LIST_ACTIONS = List.of("add", "remove", "list");

   /** Whoever ran the command; a player or the console. */
   public interface Sender {
      void send(String legacyMessage);

      boolean hasPermission(String permission);
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
         case "lookup" -> doLookup(sender, args);
         case "whitelist" -> doListCommand(sender, args, core.whitelist(), "whitelist");
         case "blacklist" -> doListCommand(sender, args, core.blacklist(), "blacklist");
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
      if (args.length == 2 && (sub.equals("check") || sub.equals("lookup"))) {
         List<String> names = new ArrayList<>();
         for (ShieldPlayer online : core.platform().onlinePlayers()) {
            names.add(online.name());
         }
         return filter(names, args[1]);
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
            "help-whitelist", "help-blacklist", "help-refresh", "help-recheck",
            "help-clearcache", "help-reload", "help-footer")) {
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
         if (core.refreshLists()) {
            send(sender, "refresh-done", of(
                  "ranges", String.valueOf(core.lists().ranges().rangeCount()),
                  "addresses", String.valueOf(core.lists().ranges().addressCount())));
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
         CheckEngine engine = new CheckEngine(core.config(), core.lists(), core.lookups(),
               core.whitelist(), core.blacklist(), core.reverseDns(), core.trust(), null);
         CheckVerdict verdict = engine.check(target, null, ip, CheckEngine.PermissionProbe.NONE);
         LookupResult lookup = verdict.lookup();

         send(sender, "check-header");
         send(sender, "check-target", of("target", target, "ip", ip));
         send(sender, verdict.blocked() ? "check-verdict-blocked" : "check-verdict-allowed",
               of("reason", verdict.describe()));

         if (lookup.resolved()) {
            send(sender, "check-country", of(
                  "code", lookup.countryOrUnknown(),
                  "name", lookup.countryName() == null ? "?" : lookup.countryName()));
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
            send(sender, "list-runtime", of(
                  "count", String.valueOf(atRuntime.size()),
                  "entries", atRuntime.isEmpty() ? empty : String.join(", ", atRuntime)));
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
            try {
               send(sender, list.add(entry) ? "list-added" : "list-already",
                     of("entry", entry, "list", label));
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
         default -> send(sender, "list-usage", of("list", label));
      }
   }

   private void sendToggleHint(Sender sender, String key, boolean enabled) {
      send(sender, "toggle-state", of(
            "key", key,
            "state", messages().get(enabled ? "enabled" : "disabled")));
      send(sender, "toggle-hint");
   }

   /** Accepts an IP literal directly, otherwise resolves an online player's address. */
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
}
