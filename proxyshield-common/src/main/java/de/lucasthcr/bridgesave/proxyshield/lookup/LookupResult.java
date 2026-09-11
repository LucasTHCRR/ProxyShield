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

package de.lucasthcr.bridgesave.proxyshield.lookup;

import java.util.List;
import java.util.Locale;

/**
 * What the lookup layer knows about an address.
 * <p>
 * {@link #resolved()} distinguishes "we got an answer" from "we could not find out", which is what
 * lets {@code settings.fail-closed} make a deliberate decision instead of silently treating every
 * error as clean like v1 did.
 * <p>
 * {@link #confidence()} and {@link #sources()} carry the consensus engine's reasoning: how much
 * weight flagged the address, and which services contributed it. Without those, a false positive
 * report can only ever be answered with "some provider said so", which is not something an operator
 * can act on.
 */
public record LookupResult(
      boolean resolved,
      boolean proxy,
      boolean hosting,
      boolean tor,
      String countryCode,
      String countryName,
      String isp,
      String asn,
      String connectionType,
      double confidence,
      List<String> sources,
      String failureReason) {

   public static final LookupResult UNKNOWN = failed("not checked");

   public LookupResult {
      sources = sources == null ? List.of() : List.copyOf(sources);
   }

   public static LookupResult failed(String reason) {
      return new LookupResult(false, false, false, false, null, null, null, null, null, 0.0,
            List.of(), reason);
   }

   public static LookupResult of(boolean proxy, boolean hosting, String countryCode,
         String countryName, String isp) {
      return of(proxy, hosting, false, countryCode, countryName, isp, null, null, 0.0, List.of());
   }

   public static LookupResult of(boolean proxy, boolean hosting, boolean tor, String countryCode,
         String countryName, String isp, String asn, String connectionType, double confidence,
         List<String> sources) {
      String code = countryCode == null || countryCode.isBlank()
            ? null
            : countryCode.trim().toUpperCase(Locale.ROOT);
      return new LookupResult(true, proxy, hosting, tor, code, blankToNull(countryName),
            blankToNull(isp), normalizeAsn(asn), blankToNull(connectionType), confidence,
            sources, null);
   }

   /** A copy carrying the flags the local heuristics added on top of the provider answers. */
   public LookupResult withFlags(boolean proxy, boolean hosting, double confidence,
         List<String> sources) {
      return new LookupResult(resolved, proxy, hosting, tor, countryCode, countryName, isp, asn,
            connectionType, confidence, sources, failureReason);
   }

   private static String blankToNull(String value) {
      return value == null || value.isBlank() ? null : value.trim();
   }

   /**
    * Reduces every ASN spelling to {@code AS####}.
    * <p>
    * ip-api.com sends {@code "AS9009 M247 Europe SRL"}, ipapi.is sends the number {@code 9009},
    * proxycheck.io sends {@code "AS9009"}. Rules in config.yml can only match one of those unless
    * they are all normalised first.
    */
   static String normalizeAsn(String raw) {
      if (raw == null || raw.isBlank()) {
         return null;
      }

      String trimmed = raw.trim();
      StringBuilder digits = new StringBuilder();
      int start = trimmed.regionMatches(true, 0, "AS", 0, 2) ? 2 : 0;
      for (int i = start; i < trimmed.length(); i++) {
         char c = trimmed.charAt(i);
         if (Character.isDigit(c)) {
            digits.append(c);
         } else if (digits.length() > 0) {
            break;
         } else if (!Character.isWhitespace(c)) {
            return null;
         }
      }
      return digits.length() == 0 ? null : "AS" + digits;
   }

   public boolean hasCountry() {
      return countryCode != null;
   }

   /** Country code for display, never {@code null}. */
   public String countryOrUnknown() {
      return countryCode == null ? "??" : countryCode;
   }

   public String ispOrUnknown() {
      return isp == null ? "unknown" : isp;
   }

   public String asnOrUnknown() {
      return asn == null ? "unknown" : asn;
   }

   /** Which services flagged the address, for alerts and {@code /proxyshield check}. */
   public String sourceSummary() {
      return sources.isEmpty() ? "none" : String.join(", ", sources);
   }

   /**
    * Whether the address looks like a residential or mobile connection.
    * <p>
    * Mobile carriers using CGNAT are the classic false positive for a hosting block, so a provider
    * that tells us the connection type is allowed to override it.
    */
   public boolean residentialOrMobile() {
      if (connectionType == null) {
         return false;
      }
      String type = connectionType.toLowerCase(Locale.ROOT);
      return type.contains("residential") || type.contains("mobile") || type.contains("cellular")
            || type.equals("isp") || type.equals("business");
   }
}
