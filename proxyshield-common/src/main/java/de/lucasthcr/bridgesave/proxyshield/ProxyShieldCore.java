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

package de.lucasthcr.bridgesave.proxyshield;

import de.lucasthcr.bridgesave.proxyshield.api.ProxyShieldApi;
import de.lucasthcr.bridgesave.proxyshield.check.AltTracker;
import de.lucasthcr.bridgesave.proxyshield.check.CheckEngine;
import de.lucasthcr.bridgesave.proxyshield.check.CheckVerdict;
import de.lucasthcr.bridgesave.proxyshield.check.ConnectionLimiter;
import de.lucasthcr.bridgesave.proxyshield.check.JoinHeuristics;
import de.lucasthcr.bridgesave.proxyshield.check.TrustStore;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.list.AsnFeed;
import de.lucasthcr.bridgesave.proxyshield.list.ListManager;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import de.lucasthcr.bridgesave.proxyshield.message.Messages;
import de.lucasthcr.bridgesave.proxyshield.lookup.FailoverLookupService;
import de.lucasthcr.bridgesave.proxyshield.net.NetworkData;
import de.lucasthcr.bridgesave.proxyshield.net.ManagedIpList;
import de.lucasthcr.bridgesave.proxyshield.net.ReverseDns;
import de.lucasthcr.bridgesave.proxyshield.notify.AlertDispatcher;
import de.lucasthcr.bridgesave.proxyshield.report.SightingReporter;
import de.lucasthcr.bridgesave.proxyshield.notify.CommandActions;
import de.lucasthcr.bridgesave.proxyshield.notify.DiscordWebhook;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import de.lucasthcr.bridgesave.proxyshield.platform.ShieldPlayer;
import de.lucasthcr.bridgesave.proxyshield.stats.Statistics;
import de.lucasthcr.bridgesave.proxyshield.storage.ShieldStorage;
import de.lucasthcr.bridgesave.proxyshield.storage.StorageFactory;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Owns every piece of plugin state and exposes the two things a platform adapter needs: a decision
 * for an incoming connection, and a command entry point.
 * <p>
 * All mutable state is swapped atomically on reload, so a check running on a login thread always
 * sees one consistent configuration.
 */
public final class ProxyShieldCore {

   /** How often the heartbeat runs. List refreshes and cache purges are driven from it. */
   private static final long HEARTBEAT_SECONDS = 300L;

   /** Grace period before the first feed download, to stay clear of the startup rush. */
   private static final long STARTUP_DELAY_SECONDS = 8L;

   private final Platform platform;
   private final ListManager lists;
   private final ManagedIpList whitelist;
   private final ManagedIpList blacklist;
   private final Statistics statistics = new Statistics();
   private final JoinHeuristics heuristics = new JoinHeuristics();
   private final ConnectionLimiter limiter = new ConnectionLimiter();
   private final AltTracker alts;
   private final AsnFeed asnFeed;
   private final NetworkData networks;
   private final SightingReporter reporter;
   private final Set<UUID> restricted = ConcurrentHashMap.newKeySet();

   private volatile ShieldConfig config;
   private volatile Messages messages;
   private volatile FailoverLookupService lookups;
   private volatile CheckEngine engine;
   private volatile DiscordWebhook webhook;
   private volatile CommandActions commands;
   private volatile AlertDispatcher alerts;
   private volatile ReverseDns reverseDns;
   private volatile ShieldStorage storage;
   private volatile TrustStore trust;
   private volatile boolean running;

   public ProxyShieldCore(Platform platform) {
      this.platform = platform;
      this.lists = new ListManager(platform);
      this.whitelist = new ManagedIpList(platform.dataFolder().resolve("whitelist.txt"));
      this.blacklist = new ManagedIpList(platform.dataFolder().resolve("blacklist.txt"));
      this.alts = new AltTracker(platform.dataFolder().resolve("alts.tsv"));
      this.asnFeed = new AsnFeed(platform);
      this.networks = new NetworkData(platform);
      this.reporter = new SightingReporter(platform, () -> config);
   }

   /** Reads the config, restores caches and starts the background work. */
   public void start() {
      platform.saveDefaultConfig();
      config = ShieldConfig.from(platform.loadConfig());
      config.warnings().forEach(platform::warn);
      messages = Messages.load(platform, config.language());

      storage = StorageFactory.create(platform, config);
      trust = new TrustStore(storage);
      lookups = new FailoverLookupService(platform, config, null, storage);
      reverseDns = newReverseDns(config);
      webhook = new DiscordWebhook(platform, config);
      commands = new CommandActions(platform, config);
      alerts = new AlertDispatcher(platform, config, messages, webhook, commands);

      if (config.apiPersistCache()) {
         lookups.preloadFrom(storage);
      }
      // Another server clearing or whitelisting an address has to reach this one immediately,
      // otherwise every proxy keeps serving its own stale copy until the entry expires.
      storage.onRemoteInvalidation(key -> lookups.invalidateLocally(key));
      trust.load();
      alts.load();
      asnFeed.loadFromDisk();
      networks.loadFromDisk();

      if (storage.shared()) {
         platform.info("Verdicts and trust are shared through " + storage.name()
               + ", so one lookup now covers every server pointed at it.");
      }

      loadManagedLists();
      rebuildEngine();

      lookups.warnIfInsecure();
      if (config.dryRun()) {
         platform.warn("Dry-run mode is enabled: detections are reported but nobody is kicked.");
      }
      if (!config.flagCommands().isEmpty()) {
         platform.info("Flag actions: " + config.flagCommands().size() + " console command(s), "
               + "run-when=" + config.flagCommandTrigger().name().toLowerCase(Locale.ROOT)
               + ", delay=" + config.flagCommandDelaySeconds() + "s.");
      }

      running = true;
      lists.loadFromDisk(config.activeListSources());
      platform.runAsync(this::initialRefresh);
      platform.runAsyncTimer(this::heartbeat, HEARTBEAT_SECONDS);
      platform.runAsyncTimer(reporter::tick, 60);
      announceReporting(config);

      ProxyShieldApi.bind(this);
      platform.info("ProxyShield " + platform.version() + " enabled on " + platform.name() + ".");
   }

   public void shutdown() {
      running = false;
      ProxyShieldApi.unbind();
      platform.cancelTasks();

      ShieldConfig current = config;
      trust.save();
      saveAlts(current);
      if (current != null && current.apiPersistCache()) {
         storage.flush();
      }
      lookups.close();
      storage.close();
      if (reverseDns != null) {
         reverseDns.close();
      }
   }

   private void saveAlts(ShieldConfig current) {
      if (current == null || !current.altsEnabled()) {
         return;
      }
      try {
         alts.save(current.altsRetentionDays());
      } catch (IOException failure) {
         platform.error("Could not write alts.tsv", failure);
      }
   }

   private ReverseDns newReverseDns(ShieldConfig current) {
      return new ReverseDns(current.rdnsTimeoutMillis(), current.apiMaxCacheEntries(),
            current.apiCacheMinutes() * 60_000L);
   }

   /**
    * First download after start-up, held back for a moment.
    * <p>
    * Server start is when every plugin that polls GitHub does so at once, which is exactly when a
    * shared address runs into a rate limit. Waiting a few seconds costs nothing, because startup
    * protection comes from the on-disk cache anyway.
    */
   private void initialRefresh() {
      // With a cached copy the server is already protected, so the download can wait for the
      // startup rush. On a first start nothing is, so it begins at once.
      long delaySeconds = lists.ranges().isEmpty() ? 0L : STARTUP_DELAY_SECONDS;
      try {
         Thread.sleep(delaySeconds * 1000L);
      } catch (InterruptedException interrupted) {
         Thread.currentThread().interrupt();
         return;
      }
      if (running) {
         refreshLists();
      }
   }

   private void loadManagedLists() {
      try {
         whitelist.load();
      } catch (IOException failure) {
         platform.error("Could not read whitelist.txt", failure);
      }
      try {
         blacklist.load();
      } catch (IOException failure) {
         platform.error("Could not read blacklist.txt", failure);
      }
      whitelist.setConfigEntries(config.whitelistIps());
      blacklist.setConfigEntries(config.blacklistIps());
   }

   private void rebuildEngine() {
      engine = new CheckEngine(config, lists, lookups, whitelist, blacklist, reverseDns, trust,
            heuristics).withAsnFeed(asnFeed::contains).withNetworkData(networks);
   }

   /** Re-reads config.yml and rebuilds everything derived from it. */
   public synchronized ReloadReport reload() {
      ShieldConfig previous = config;
      ShieldConfig updated;
      try {
         updated = ShieldConfig.from(platform.loadConfig());
      } catch (RuntimeException broken) {
         platform.error("Reload failed, keeping the previous configuration", broken);
         return new ReloadReport(false, broken.getMessage(), previous);
      }

      config = updated;
      updated.warnings().forEach(platform::warn);
      messages = Messages.load(platform, updated.language());

      // Rebuilt because providers, weights and cache sizing all come from config - but the
      // cached answers carry over, so a reload no longer costs a fresh round of provider quota.
      FailoverLookupService previousLookups = lookups;
      lookups = new FailoverLookupService(platform, updated, previousLookups, storage);
      previousLookups.close();

      ReverseDns previousDns = reverseDns;
      reverseDns = newReverseDns(updated);
      if (previousDns != null) {
         previousDns.close();
      }

      webhook.applyConfig(updated);
      alerts.applyConfig(updated, messages);
      announceReporting(updated);
      whitelist.setConfigEntries(updated.whitelistIps());
      blacklist.setConfigEntries(updated.blacklistIps());
      rebuildEngine();

      platform.runAsync(this::refreshLists);
      if (updated.recheckOnline()) {
         platform.runAsync(this::recheckOnlinePlayers);
      }
      return new ReloadReport(true, null, updated);
   }

   /**
    * Re-runs the pipeline for everyone currently online and disconnects those who no longer pass.
    * <p>
    * Useful after tightening the rules or adding a blacklist entry, since the normal check only
    * ever runs at login. Blocking; call from an async context.
    *
    * @return how many players were actually disconnected
    */
   public int recheckOnlinePlayers() {
      ShieldConfig current = config;
      int disconnected = 0;

      for (ShieldPlayer player : platform.onlinePlayers()) {
         String ip = player.ip();
         if (ip == null) {
            continue;
         }

         CheckVerdict verdict;
         try {
            verdict = engine.check(player.name(), player.uuid(), ip, player::hasPermission);
         } catch (RuntimeException unexpected) {
            platform.error("Recheck failed for " + player.name(), unexpected);
            continue;
         }

         boolean enforced = verdict.blocked() && !current.dryRun();
         statistics.record(verdict, enforced);

         if (verdict.blocked()) {
            alerts.alert(player.name(), player.uuid(), ip, verdict, enforced);
            reporter.offer(ip, verdict);
            if (enforced) {
               player.kick(kickMessage(verdict, player.name(), ip));
               disconnected++;
            }
         }
      }

      return disconnected;
   }

   private void heartbeat() {
      if (!running) {
         return;
      }

      ShieldConfig current = config;
      long dueAfter = current.listUpdateIntervalHours() * 3_600_000L;
      long lastRefresh = lists.lastRefreshMillis();
      if (lastRefresh == 0L || System.currentTimeMillis() - lastRefresh >= dueAfter) {
         refreshLists();
      }
      // With the address lists switched off the check above fires every beat, and refreshLists
      // returns before reaching the network feed, so the feed keeps its own schedule.
      if (!current.useLists() && current.asnEnabled() && asnFeed.due(dueAfter)) {
         asnFeed.refresh(current.asnSources(), current.listTimeoutSeconds());
      }

      lookups.purgeExpired();
      heuristics.purgeExpired();
      limiter.purgeExpired(current.limiterWindowMinutes());
      whitelist.expireNow();
      blacklist.expireNow();
      saveAlts(current);
      storage.purgeExpired();
      storage.flush();
      trust.saveIfDue();
      alerts.rotateLogIfLarge();
   }

   /** Downloads every configured list source. Blocking; always call from an async context. */
   public boolean refreshLists() {
      ShieldConfig current = config;
      if (!current.useLists()) {
         return false;
      }
      // The network feed and the address lists come from different hosts, so they download side by
      // side and the plugin is ready after the slower one instead of after both.
      Thread asnWorker = null;
      if (current.asnEnabled()) {
         asnWorker = new Thread(
               () -> asnFeed.refresh(current.asnSources(), current.listTimeoutSeconds()),
               "ProxyShield-asn-feed");
         asnWorker.setDaemon(true);
         asnWorker.start();
      }
      Thread networkWorker = null;
      if (!current.networkDataSource().isEmpty()) {
         networkWorker = new Thread(
               () -> networks.refresh(current.networkDataSource(), current.listTimeoutSeconds()),
               "ProxyShield-network-feed");
         networkWorker.setDaemon(true);
         networkWorker.start();
      }
      boolean refreshed = lists.refresh(current.activeListSources(), current.listTimeoutSeconds(),
            current.listDiskCache());
      if (networkWorker != null) {
         try {
            networkWorker.join();
         } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
         }
      }
      if (asnWorker != null) {
         try {
            asnWorker.join();
         } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
         }
      }
      return refreshed;
   }

   /**
    * Runs the full check and reports the outcome.
    * <p>
    * Blocking: this may perform an HTTP lookup, so platform adapters must call it from an async
    * login hook, never from the main thread.
    */
   public ConnectionDecision handleLogin(String playerName, UUID uuid, String ip,
         CheckEngine.PermissionProbe probe) {
      ShieldConfig current = config;
      if (current.passive()) {
         // Nothing runs at login; /proxyshield check and the API still look addresses up.
         return new ConnectionDecision(false, null,
               CheckVerdict.allow(CheckVerdict.Reason.PASSIVE));
      }
      CheckVerdict verdict;
      try {
         verdict = engine.check(playerName, uuid, ip, probe);
         verdict = applyLimiter(current, verdict, uuid, ip);
      } catch (RuntimeException unexpected) {
         platform.error("Check failed for " + playerName + " (" + ip + ")", unexpected);
         // An internal error must not lock players out unless the operator asked for that.
         if (!current.failClosed()) {
            return new ConnectionDecision(false, null, CheckVerdict.allow(
                  CheckVerdict.Reason.ALLOWED));
         }
         verdict = CheckVerdict.deny(CheckVerdict.Reason.LOOKUP_FAILED,
               "internal error", LookupResult.UNKNOWN);
      }

      boolean enforced = verdict.blocked() && !current.dryRun();
      statistics.record(verdict, enforced);
      // On a proxy the player can instead be fenced into the allowed backends.
      boolean fenced = enforced && uuid != null && platform.proxy()
            && current.restrictedEnabled();
      if (fenced) {
         restricted.add(uuid);
      }
      if (current.altsEnabled() && ip != null) {
         alts.record(ip, uuid, playerName);
      }

      if (verdict.blocked()) {
         alerts.alert(playerName, uuid, ip, verdict, enforced);
         reporter.offer(ip, verdict);
         // An account caught behind a proxy starts earning its exemption again from scratch.
         trust.forget(uuid);
      } else if (current.trustEnabled()
            && verdict.reason() == CheckVerdict.Reason.ALLOWED) {
         trust.recordCleanLogin(uuid);
      }

      boolean deny = enforced && !fenced;
      return new ConnectionDecision(deny, deny ? kickMessage(verdict, playerName, ip) : null,
            verdict);
   }

   /**
    * Whether a player may be routed to the named backend. Only players flagged while
    * restricted-server mode was on are limited; everyone else may go anywhere.
    */
   public boolean mayJoinServer(UUID uuid, String server) {
      ShieldConfig current = config;
      return uuid == null || !restricted.contains(uuid) || !current.restrictedEnabled()
            || current.restrictedAllows(server);
   }

   /** Whether the player was flagged and is limited to the allowed backends. */
   public boolean isRestricted(UUID uuid) {
      return uuid != null && restricted.contains(uuid);
   }

   /** Called when a player leaves the proxy, so the next login is judged afresh. */
   public void playerLeft(UUID uuid) {
      if (uuid != null) {
         restricted.remove(uuid);
      }
   }

   /** The text shown when a restricted player is refused a backend. */
   public String restrictedMessage(String server) {
      return messages.get("restricted-server", Map.of("server", server == null ? "?" : server));
   }

   /**
    * Applies the per-address cap to a connection the engine let through. Whitelisted, local and
    * bypassing connections are left alone: a LAN party or a staff member must never hit the cap.
    */
   private CheckVerdict applyLimiter(ShieldConfig current, CheckVerdict verdict, UUID uuid,
         String ip) {
      if (!current.limiterEnabled() || verdict.blocked() || ip == null) {
         return verdict;
      }
      switch (verdict.reason()) {
         case BYPASS_PERMISSION, WHITELISTED_IP, WHITELISTED_PLAYER, LOCAL_ADDRESS -> {
            return verdict;
         }
         default -> {
         }
      }
      if (limiter.exceeds(ip, uuid, current.limiterMax(), current.limiterWindowMinutes(),
            platform.onlinePlayers())) {
         return CheckVerdict.deny(CheckVerdict.Reason.CONNECTION_LIMIT,
               current.limiterMax() + " per address", verdict.lookup());
      }
      return verdict;
   }

   private String kickMessage(CheckVerdict verdict, String player, String ip) {
      Map<String, String> values = new LinkedHashMap<>();
      values.put("player", player == null ? "unknown" : player);
      values.put("ip", ip == null ? "unknown" : ip);
      values.put("reason", verdict.describe());
      values.put("country", verdict.lookup().countryOrUnknown());
      values.put("isp", verdict.lookup().ispOrUnknown());
      values.put("asn", verdict.lookup().asnOrUnknown());
      return messages.get("kick-message", values);
   }

   public Platform platform() {
      return platform;
   }

   public ShieldConfig config() {
      return config;
   }

   public Messages messages() {
      return messages;
   }

   public ListManager lists() {
      return lists;
   }

   public FailoverLookupService lookups() {
      return lookups;
   }

   public ManagedIpList whitelist() {
      return whitelist;
   }

   public ManagedIpList blacklist() {
      return blacklist;
   }

   public Statistics statistics() {
      return statistics;
   }

   public SightingReporter reporter() {
      return reporter;
   }

   private void announceReporting(ShieldConfig current) {
      if (current.reportingEnabled()) {
         platform.info("Reporting is on: addresses refused as proxies are sent to " + current.reportingUrl()
               + " (no names, no UUIDs). Turn it off with reporting.enabled, delete what was sent with"
               + " /proxyshield reporting forget.");
      }
   }

   public NetworkData networkData() {
      return networks;
   }

   public AsnFeed asnFeed() {
      return asnFeed;
   }

   public AltTracker alts() {
      return alts;
   }

   public TrustStore trust() {
      return trust;
   }

   public JoinHeuristics heuristics() {
      return heuristics;
   }

   public ReverseDns reverseDns() {
      return reverseDns;
   }

   public ShieldStorage storage() {
      return storage;
   }

   public DiscordWebhook webhook() {
      return webhook;
   }

   public AlertDispatcher alerts() {
      return alerts;
   }

   public CommandActions commands() {
      return commands;
   }

   /** Result of a connection check, already reduced to what the platform has to act on. */
   public record ConnectionDecision(boolean deny, String kickMessage, CheckVerdict verdict) {
   }

   public record ReloadReport(boolean success, String error, ShieldConfig config) {
   }
}
