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

import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;

/** The outcome of running one connection through {@link CheckEngine}. */
public record CheckVerdict(Reason reason, String detail, LookupResult lookup) {

   public enum Reason {
      ALLOWED("allowed", false),
      BYPASS_PERMISSION("bypass permission", false),
      WHITELISTED_IP("whitelisted IP", false),
      WHITELISTED_PLAYER("whitelisted player", false),
      LOCAL_ADDRESS("local address", false),
      BEDROCK_PLAYER("Bedrock player", false),
      TRUSTED_PLAYER("trusted player", false),
      ALLOWED_ASN("allowed network", false),
      ALLOWED_ISP("allowed ISP", false),
      PASSIVE("passive mode", false),

      BLACKLISTED("blacklisted IP", true),
      IP_LIST("VPN list", true),
      PROXY("proxy/VPN", true),
      HOSTING("hosting/datacenter", true),
      TOR("Tor exit node", true),
      ASN("blocked network", true),
      ISP("blocked ISP", true),
      BOGON("bogon address", true),
      CONNECTION_LIMIT("too many accounts from this address", true),
      SUSPICIOUS("suspicious connection", true),
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
