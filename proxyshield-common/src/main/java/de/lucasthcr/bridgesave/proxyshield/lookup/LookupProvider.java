package de.lucasthcr.bridgesave.proxyshield.lookup;

/**
 * Source of IP intelligence for {@code CheckEngine}.
 * <p>
 * Extracted from {@link IpLookupService} so the decision pipeline can be exercised without a
 * network round trip, and so a different provider can be dropped in later.
 */
@FunctionalInterface
public interface LookupProvider {

   /** Provider that never resolves anything, used when lookups are disabled. */
   LookupProvider NONE = ip -> LookupResult.UNKNOWN;

   /**
    * Looks the address up, blocking if a request is needed.
    * <p>
    * Never throws: a failure comes back as an unresolved {@link LookupResult}.
    */
   LookupResult lookup(String ip);
}
