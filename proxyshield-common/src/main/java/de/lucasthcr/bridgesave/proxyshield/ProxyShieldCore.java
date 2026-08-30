package de.lucasthcr.bridgesave.proxyshield;

import de.lucasthcr.bridgesave.proxyshield.api.ProxyShieldApi;
import de.lucasthcr.bridgesave.proxyshield.check.CheckEngine;
import de.lucasthcr.bridgesave.proxyshield.check.CheckVerdict;
import de.lucasthcr.bridgesave.proxyshield.check.JoinHeuristics;
import de.lucasthcr.bridgesave.proxyshield.check.TrustStore;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.list.ListManager;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import de.lucasthcr.bridgesave.proxyshield.message.Messages;
import de.lucasthcr.bridgesave.proxyshield.lookup.FailoverLookupService;
import de.lucasthcr.bridgesave.proxyshield.net.ManagedIpList;
import de.lucasthcr.bridgesave.proxyshield.net.ReverseDns;
import de.lucasthcr.bridgesave.proxyshield.notify.AlertDispatcher;
import de.lucasthcr.bridgesave.proxyshield.notify.DiscordWebhook;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import de.lucasthcr.bridgesave.proxyshield.platform.ShieldPlayer;
import de.lucasthcr.bridgesave.proxyshield.stats.Statistics;
import de.lucasthcr.bridgesave.proxyshield.storage.ShieldStorage;
import de.lucasthcr.bridgesave.proxyshield.storage.StorageFactory;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

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

   private volatile ShieldConfig config;
   private volatile Messages messages;
   private volatile FailoverLookupService lookups;
   private volatile CheckEngine engine;
   private volatile DiscordWebhook webhook;
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
   }

   /** Reads the config, restores caches and starts the background work. */
   public void start() {
      platform.saveDefaultConfig();
      config = ShieldConfig.from(platform.loadConfig());
      messages = Messages.load(platform, config.language());

      storage = StorageFactory.create(platform, config);
      trust = new TrustStore(storage);
      lookups = new FailoverLookupService(platform, config, null, storage);
      reverseDns = newReverseDns(config);
      webhook = new DiscordWebhook(platform, config);
      alerts = new AlertDispatcher(platform, config, messages, webhook);

      if (config.apiPersistCache()) {
         lookups.preloadFrom(storage);
      }
      // Another server clearing or whitelisting an address has to reach this one immediately,
      // otherwise every proxy keeps serving its own stale copy until the entry expires.
      storage.onRemoteInvalidation(key -> lookups.invalidateLocally(key));
      trust.load();

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

      running = true;
      lists.loadFromDisk(config.activeListSources());
      platform.runAsync(this::initialRefresh);
      platform.runAsyncTimer(this::heartbeat, HEARTBEAT_SECONDS);

      ProxyShieldApi.bind(this);
      platform.info("ProxyShield " + platform.version() + " enabled on " + platform.name() + ".");
   }

   public void shutdown() {
      running = false;
      ProxyShieldApi.unbind();
      platform.cancelTasks();

      ShieldConfig current = config;
      trust.save();
      if (current != null && current.apiPersistCache()) {
         storage.flush();
      }
      lookups.close();
      storage.close();
      if (reverseDns != null) {
         reverseDns.close();
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
      try {
         Thread.sleep(STARTUP_DELAY_SECONDS * 1000L);
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
            heuristics);
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
      messages = Messages.load(platform, updated.language());

      // Rebuilt because providers, weights and cache sizing all come from config — but the
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
            alerts.alert(player.name(), ip, verdict, enforced);
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

      lookups.purgeExpired();
      heuristics.purgeExpired();
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
      return lists.refresh(current.activeListSources(), current.listTimeoutSeconds(),
            current.listDiskCache());
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
      CheckVerdict verdict;
      try {
         verdict = engine.check(playerName, uuid, ip, probe);
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

      if (verdict.blocked()) {
         alerts.alert(playerName, ip, verdict, enforced);
         // An account caught behind a proxy starts earning its exemption again from scratch.
         trust.forget(uuid);
      } else if (current.trustEnabled()
            && verdict.reason() == CheckVerdict.Reason.ALLOWED) {
         trust.recordCleanLogin(uuid);
      }

      return new ConnectionDecision(enforced, enforced ? kickMessage(verdict, playerName, ip)
            : null, verdict);
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

   /** Result of a connection check, already reduced to what the platform has to act on. */
   public record ConnectionDecision(boolean deny, String kickMessage, CheckVerdict verdict) {
   }

   public record ReloadReport(boolean success, String error, ShieldConfig config) {
   }
}
