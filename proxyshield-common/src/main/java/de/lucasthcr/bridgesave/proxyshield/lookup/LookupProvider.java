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

   /**
    * Same lookup with a hint about the address: in a network the offline feed knows as home or mobile
    * access, a provider that is still slow may be stopped early once another one has said "clean".
    */
   default LookupResult lookup(String ip, boolean endUserNetwork) {
      return lookup(ip);
   }
}
