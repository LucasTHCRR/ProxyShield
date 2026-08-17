package de.lucasthcr.bridgesave.proxyshield.check;

import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.list.ListManager;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupProvider;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import de.lucasthcr.bridgesave.proxyshield.net.IpAddresses;
import de.lucasthcr.bridgesave.proxyshield.net.ManagedIpList;
import java.util.Locale;
import java.util.UUID;

/**
 * Decides whether a connection may proceed.
 * <p>
 * The order below is deliberate: everything that can allow a player is evaluated before anything
 * that can block one, so an operator can always whitelist their way out of a false positive.
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

   public CheckEngine(ShieldConfig config, ListManager lists, LookupProvider lookups,
         ManagedIpList whitelist, ManagedIpList blacklist) {
      this.config = config;
      this.lists = lists;
      this.lookups = lookups;
      this.whitelist = whitelist;
      this.blacklist = blacklist;
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

      if (blacklist.matches(ip)) {
         return CheckVerdict.deny(CheckVerdict.Reason.BLACKLISTED, null, LookupResult.UNKNOWN);
      }

      if (config.useLists() && lists.matches(ip)) {
         return CheckVerdict.deny(CheckVerdict.Reason.IP_LIST, null, LookupResult.UNKNOWN);
      }

      boolean needsLookup = config.useApi() || config.countryEnabled();
      if (!needsLookup) {
         return CheckVerdict.allow(CheckVerdict.Reason.ALLOWED);
      }

      LookupResult result = lookups.lookup(ip);
      if (!result.resolved()) {
         if (config.failClosed()) {
            return CheckVerdict.deny(CheckVerdict.Reason.LOOKUP_FAILED, result.failureReason(),
                  result);
         }
         return CheckVerdict.allow(CheckVerdict.Reason.ALLOWED, result);
      }

      if (config.useApi()) {
         if (config.blockProxy() && result.proxy()) {
            return CheckVerdict.deny(CheckVerdict.Reason.PROXY, result.ispOrUnknown(), result);
         }
         if (config.blockHosting() && result.hosting()) {
            return CheckVerdict.deny(CheckVerdict.Reason.HOSTING, result.ispOrUnknown(), result);
         }
      }

      CheckVerdict countryVerdict = checkCountry(result);
      if (countryVerdict != null) {
         return countryVerdict;
      }

      return CheckVerdict.allow(CheckVerdict.Reason.ALLOWED, result);
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
}
