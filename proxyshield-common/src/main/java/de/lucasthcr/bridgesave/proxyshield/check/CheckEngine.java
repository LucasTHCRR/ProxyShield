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

package de.lucasthcr.bridgesave.proxyshield.check;

import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.list.ListManager;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupProvider;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import de.lucasthcr.bridgesave.proxyshield.net.IpAddresses;
import de.lucasthcr.bridgesave.proxyshield.net.ManagedIpList;
import de.lucasthcr.bridgesave.proxyshield.net.ReverseDns;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Decides whether a connection may proceed.
 * <p>
 * The order below is deliberate: everything that can allow a player is evaluated before anything
 * that can block one, so an operator can always whitelist their way out of a false positive.
 * <p>
 * Blocking is not decided by a single yes/no from one service. Provider answers, reverse DNS and
 * the behaviour of the connection each contribute weight, and the connection is refused once that
 * weight reaches {@code api.required-score}. A commercial VPN that one dataset has never heard of
 * still trips the threshold on the strength of the others; a single provider having a bad day no
 * longer kicks anybody on its own.
 */
public final class CheckEngine {

   /** Permission test for the connecting player, where the platform can provide one. */
   @FunctionalInterface
   public interface PermissionProbe {
      PermissionProbe NONE = permission -> false;

      boolean has(String permission);
   }

   private final ShieldConfig config;
   private final ListManager lists;
   private final LookupProvider lookups;
   private final ManagedIpList whitelist;
   private final ManagedIpList blacklist;
   private final ReverseDns reverseDns;
   private final TrustStore trust;
   private final JoinHeuristics heuristics;
   private volatile Predicate<String> listedAsn = asn -> false;

   public CheckEngine(ShieldConfig config, ListManager lists, LookupProvider lookups,
         ManagedIpList whitelist, ManagedIpList blacklist) {
      this(config, lists, lookups, whitelist, blacklist, null, null, null);
   }

   public CheckEngine(ShieldConfig config, ListManager lists, LookupProvider lookups,
         ManagedIpList whitelist, ManagedIpList blacklist, ReverseDns reverseDns, TrustStore trust,
         JoinHeuristics heuristics) {
      this.config = config;
      this.lists = lists;
      this.lookups = lookups;
      this.whitelist = whitelist;
      this.blacklist = blacklist;
      this.reverseDns = reverseDns;
      this.trust = trust;
      this.heuristics = heuristics;
   }

   /** Supplies networks blocked by a downloaded list, on top of {@code detection.asn.blocked}. */
   public CheckEngine withAsnFeed(Predicate<String> feed) {
      this.listedAsn = feed == null ? asn -> false : feed;
      return this;
   }

   /**
    * Runs the full pipeline. Performs a blocking HTTP lookup when needed, so this must be called
    * off the main thread.
    *
    * @param uuid the connecting player's UUID, or {@code null} where the platform has none yet
    */
   public CheckVerdict check(String playerName, UUID uuid, String ip, PermissionProbe probe) {
      if (probe != null && probe.has(config.bypassPermission())) {
         return CheckVerdict.allow(CheckVerdict.Reason.BYPASS_PERMISSION);
      }

      if (config.exemptBedrock() && BedrockPlayers.isBedrock(uuid)) {
         return CheckVerdict.allow(CheckVerdict.Reason.BEDROCK_PLAYER);
      }

      if (playerName != null
            && config.whitelistPlayers().contains(playerName.toLowerCase(Locale.ROOT))) {
         return CheckVerdict.allow(CheckVerdict.Reason.WHITELISTED_PLAYER);
      }

      if (ip == null || !IpAddresses.isValid(ip)) {
         // Nothing to check against; never punish a player for an address we cannot read.
         return CheckVerdict.allow(CheckVerdict.Reason.ALLOWED);
      }

      if (whitelist.matches(ip)) {
         return CheckVerdict.allow(CheckVerdict.Reason.WHITELISTED_IP);
      }

      if (IpAddresses.isLocal(ip)) {
         return CheckVerdict.allow(CheckVerdict.Reason.LOCAL_ADDRESS);
      }

      if (config.blockBogon() && IpAddresses.isBogon(ip)) {
         return CheckVerdict.deny(CheckVerdict.Reason.BOGON, ip, LookupResult.UNKNOWN);
      }

      // An operator's explicit blacklist outranks any inference below, trust included.
      if (blacklist.matches(ip)) {
         return CheckVerdict.deny(CheckVerdict.Reason.BLACKLISTED, null, LookupResult.UNKNOWN);
      }

      if (config.trustEnabled() && trust != null
            && trust.trusted(uuid, config.trustMinLogins(), config.trustMinDays())) {
         return CheckVerdict.allow(CheckVerdict.Reason.TRUSTED_PLAYER);
      }

      if (config.useLists() && lists.matches(ip)) {
         return CheckVerdict.deny(CheckVerdict.Reason.IP_LIST, null, LookupResult.UNKNOWN);
      }

      boolean needsLookup = config.useApi() || config.countryEnabled();
      LookupResult result = needsLookup ? lookups.lookup(ip) : LookupResult.UNKNOWN;

      if (needsLookup && !result.resolved()) {
         // Local signals still have something to say when every provider is unreachable, so the
         // choice is between them and the fail-open policy, not between nothing and a kick.
         CheckVerdict local = localSignalsOnly(uuid, ip, result);
         if (local != null) {
            return local;
         }
         if (config.failClosed()) {
            return CheckVerdict.deny(CheckVerdict.Reason.LOOKUP_FAILED, result.failureReason(),
                  result);
         }
         return CheckVerdict.allow(CheckVerdict.Reason.ALLOWED, result);
      }

      // With use-api off the providers are queried for country data only, so nothing they say
      // about proxies may influence the verdict. Local signals still count.
      boolean useProviderFlags = config.useApi();
      Set<String> signals = useProviderFlags
            ? new LinkedHashSet<>(result.sources())
            : new LinkedHashSet<>();
      double score = useProviderFlags ? result.confidence() : 0.0;

      CheckVerdict asnVerdict = useProviderFlags ? checkAsn(result) : null;
      if (asnVerdict != null) {
         return asnVerdict;
      }

      CheckVerdict ispVerdict = checkIsp(result);
      if (ispVerdict != null) {
         return ispVerdict;
      }

      score += reverseDnsWeight(ip, signals);
      score += heuristicWeight(uuid, ip, result.countryCode(), signals);

      if (useProviderFlags && config.blockTor() && result.tor()) {
         return CheckVerdict.deny(CheckVerdict.Reason.TOR, joined(signals), result);
      }

      if (config.blockProxy()
            && ((useProviderFlags && result.proxy()) || score >= config.requiredScore())) {
         CheckVerdict.Reason reason = useProviderFlags && result.proxy()
               ? CheckVerdict.Reason.PROXY
               : CheckVerdict.Reason.SUSPICIOUS;
         return CheckVerdict.deny(reason, detailFor(result, signals, score),
               withSignals(result, score, signals));
      }

      if (useProviderFlags && config.blockHosting() && result.hosting()
            && !exemptHosting(result)) {
         return CheckVerdict.deny(CheckVerdict.Reason.HOSTING, detailFor(result, signals, score),
               withSignals(result, score, signals));
      }

      CheckVerdict countryVerdict = checkCountry(result);
      if (countryVerdict != null) {
         return countryVerdict;
      }

      return CheckVerdict.allow(CheckVerdict.Reason.ALLOWED, withSignals(result, score, signals));
   }

   /**
    * Evaluates reverse DNS and behaviour when no provider answered.
    *
    * @return a denial when the local signals alone clear the threshold, otherwise {@code null}
    */
   private CheckVerdict localSignalsOnly(UUID uuid, String ip, LookupResult result) {
      Set<String> signals = new LinkedHashSet<>();
      double score = reverseDnsWeight(ip, signals) + heuristicWeight(uuid, ip, null, signals);

      if (score < config.requiredScore() || !config.blockProxy()) {
         return null;
      }
      return CheckVerdict.deny(CheckVerdict.Reason.SUSPICIOUS, joined(signals),
            withSignals(result, score, signals));
   }

   private double reverseDnsWeight(String ip, Set<String> signals) {
      if (!config.rdnsEnabled() || reverseDns == null) {
         return 0.0;
      }
      Optional<String> matched = reverseDns.match(ip, config.rdnsPatterns());
      if (matched.isEmpty()) {
         return 0.0;
      }
      signals.add("rdns:" + matched.get());
      return config.rdnsWeight();
   }

   private double heuristicWeight(UUID uuid, String ip, String countryCode, Set<String> signals) {
      if (!config.heuristicsEnabled() || heuristics == null) {
         return 0.0;
      }
      JoinHeuristics.Signals observed = heuristics.observe(uuid, ip, countryCode,
            config.maxJoinsPerSubnetPerMinute(), config.maxAccountsPerIp(),
            config.geoJumpMinutes());
      if (!observed.any()) {
         return 0.0;
      }
      signals.addAll(observed.descriptions());
      return config.heuristicWeight();
   }

   /**
    * Applies the ASN rules.
    * <p>
    * Address lists always lag: a VPN provider rents a new range and the feeds catch up days later.
    * The network number does not change nearly as often, so blocking the ASN catches every address
    * inside it the moment the first one is identified.
    *
    * @return a verdict when a rule decided the matter, otherwise {@code null}
    */
   private CheckVerdict checkAsn(LookupResult result) {
      if (!config.asnEnabled() || result.asn() == null) {
         return null;
      }
      if (config.allowedAsns().contains(result.asn())) {
         return CheckVerdict.allow(CheckVerdict.Reason.ALLOWED_ASN, result);
      }
      if (config.blockedAsns().contains(result.asn()) || listedAsn.test(result.asn())) {
         return CheckVerdict.deny(CheckVerdict.Reason.ASN,
               result.asn() + " " + result.ispOrUnknown(), result);
      }
      return null;
   }

   /**
    * Applies the ISP filter. Runs whether or not provider flags count, because an operator who
    * names an ISP has already made the decision the flags would otherwise make.
    *
    * @return a verdict when a pattern decided the matter, otherwise {@code null}
    */
   private CheckVerdict checkIsp(LookupResult result) {
      String isp = result.isp();
      if (isp == null || isp.isBlank()) {
         return null;
      }
      if (matchesAny(config.allowedIsps(), isp)) {
         return CheckVerdict.allow(CheckVerdict.Reason.ALLOWED_ISP, result);
      }
      if (matchesAny(config.blockedIsps(), isp)) {
         return CheckVerdict.deny(CheckVerdict.Reason.ISP, isp, result);
      }
      return null;
   }

   private static boolean matchesAny(List<Pattern> patterns, String value) {
      for (Pattern pattern : patterns) {
         if (pattern.matcher(value).find()) {
            return true;
         }
      }
      return false;
   }

   /** Whether a hosting flag is waved through because the connection type says otherwise. */
   private boolean exemptHosting(LookupResult result) {
      return config.allowResidentialHosting() && result.residentialOrMobile();
   }

   /** Returns a denial verdict, or {@code null} when the country is acceptable. */
   private CheckVerdict checkCountry(LookupResult result) {
      if (!config.countryEnabled()) {
         return null;
      }

      String code = result.countryCode();
      if (code == null) {
         return config.blockUnknownCountry()
               ? CheckVerdict.deny(CheckVerdict.Reason.COUNTRY, "unknown country", result)
               : null;
      }

      boolean listed = config.countryCodes().contains(code);
      boolean blocked = switch (config.countryMode()) {
         case BLACKLIST -> listed;
         case WHITELIST -> !listed;
      };

      return blocked ? CheckVerdict.deny(CheckVerdict.Reason.COUNTRY, code, result) : null;
   }

   private static LookupResult withSignals(LookupResult result, double score, Set<String> signals) {
      if (!result.resolved()) {
         return result;
      }
      return result.withFlags(result.proxy(), result.hosting(), score, List.copyOf(signals));
   }

   /** The "why" line an operator sees in the alert: which signals fired, and how much they weigh. */
   private String detailFor(LookupResult result, Set<String> signals, double score) {
      List<String> parts = new ArrayList<>();
      if (result.isp() != null) {
         parts.add(result.isp());
      }
      if (!signals.isEmpty()) {
         parts.add(joined(signals));
      }
      parts.add(String.format(Locale.ROOT, "score %.1f/%.1f", score, config.requiredScore()));
      return String.join(" | ", parts);
   }

   private static String joined(Set<String> signals) {
      return signals.isEmpty() ? "no signals" : String.join(", ", signals);
   }
}
