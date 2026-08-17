package de.lucasthcr.bridgesave.proxyshield.check;

import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;

/** The outcome of running one connection through {@link CheckEngine}. */
public record CheckVerdict(Reason reason, String detail, LookupResult lookup) {

   public enum Reason {
      ALLOWED("allowed", false),
      BYPASS_PERMISSION("bypass permission", false),
      WHITELISTED_IP("whitelisted IP", false),
      WHITELISTED_PLAYER("whitelisted player", false),
      LOCAL_ADDRESS("local address", false),

      BLACKLISTED("blacklisted IP", true),
      IP_LIST("VPN list", true),
      PROXY("proxy/VPN", true),
      HOSTING("hosting/datacenter", true),
      COUNTRY("country block", true),
      LOOKUP_FAILED("lookup failed", true);

      private final String display;
      private final boolean blocking;

      Reason(String display, boolean blocking) {
         this.display = display;
         this.blocking = blocking;
      }

      public String display() {
         return display;
      }

      public boolean blocking() {
         return blocking;
      }
   }

   public static CheckVerdict allow(Reason reason) {
      return new CheckVerdict(reason, null, LookupResult.UNKNOWN);
   }

   public static CheckVerdict allow(Reason reason, LookupResult lookup) {
      return new CheckVerdict(reason, null, lookup);
   }

   public static CheckVerdict deny(Reason reason, String detail, LookupResult lookup) {
      return new CheckVerdict(reason, detail, lookup);
   }

   public boolean blocked() {
      return reason.blocking();
   }

   /** Short human readable reason, e.g. {@code "country block (RU)"}. */
   public String describe() {
      return detail == null || detail.isBlank()
            ? reason.display()
            : reason.display() + " (" + detail + ")";
   }
}
