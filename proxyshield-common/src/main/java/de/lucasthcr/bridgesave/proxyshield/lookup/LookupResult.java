package de.lucasthcr.bridgesave.proxyshield.lookup;

import java.util.Locale;

/**
 * What the lookup provider knows about an address.
 * <p>
 * {@link #resolved()} distinguishes "the provider answered" from "we could not find out", which is
 * what lets {@code settings.fail-closed} make a deliberate decision instead of silently treating
 * every error as clean like v1 did.
 */
public record LookupResult(
      boolean resolved,
      boolean proxy,
      boolean hosting,
      String countryCode,
      String countryName,
      String isp,
      String failureReason) {

   public static final LookupResult UNKNOWN = failed("not checked");

   public static LookupResult failed(String reason) {
      return new LookupResult(false, false, false, null, null, null, reason);
   }

   public static LookupResult of(boolean proxy, boolean hosting, String countryCode,
         String countryName, String isp) {
      String code = countryCode == null || countryCode.isBlank()
            ? null
            : countryCode.trim().toUpperCase(Locale.ROOT);
      return new LookupResult(true, proxy, hosting, code, blankToNull(countryName),
            blankToNull(isp), null);
   }

   private static String blankToNull(String value) {
      return value == null || value.isBlank() ? null : value.trim();
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
}
