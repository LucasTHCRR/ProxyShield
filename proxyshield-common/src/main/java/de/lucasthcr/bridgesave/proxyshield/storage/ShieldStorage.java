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

package de.lucasthcr.bridgesave.proxyshield.storage;

import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * Where verdicts and player history are kept between restarts, and - on a network - between
 * servers.
 * <p>
 * A network running several proxies used to look each address up once per proxy, multiplying the
 * quota cost by the number of front ends and producing different answers on each. A shared store
 * turns that into one lookup for the whole network: whichever proxy asks first pays for it, and the
 * rest read the answer.
 * <p>
 * Implementations must never throw at a caller. A store that has gone away answers "nothing here"
 * and reports the problem once, because a database outage may not become a login outage.
 */
public interface ShieldStorage extends AutoCloseable {

   /** Display name for {@code /proxyshield info}, e.g. {@code "MySQL"} or {@code "file"}. */
   String name();

   /** Whether the store is currently usable. A failed store degrades to memory-only operation. */
   boolean available();

   /** Whether answers are visible to other servers, which is what makes the sync worthwhile. */
   boolean shared();

   /**
    * Entries to load into the in-memory cache at start-up.
    * <p>
    * Only the file store returns anything: pulling a shared database into every proxy's heap would
    * defeat the point of sharing it, so remote stores are consulted per address instead.
    */
   Map<String, CachedVerdict> preload();

   /** Looks one address up in the shared store. Blocking; called only on a lookup thread. */
   Optional<CachedVerdict> find(String key);

   void put(String key, CachedVerdict verdict);

   void invalidate(String key);

   void clearVerdicts();

   Map<UUID, TrustRecord> loadTrust();

   void saveTrust(Map<UUID, TrustRecord> records);

   /**
    * Registers a listener for invalidations published by another server.
    * <p>
    * Without it, whitelisting an address on one proxy would leave the others serving the old
    * verdict until it expired.
    */
   default void onRemoteInvalidation(Consumer<String> listener) {
   }

   /** Writes anything held in memory. Called from the heartbeat and at shutdown. */
   default void flush() {
   }

   /** Drops expired rows. Returns how many went. */
   default int purgeExpired() {
      return 0;
   }

   @Override
   void close();

   /** A verdict with the moment it stops being trustworthy. */
   record CachedVerdict(LookupResult result, long expiresAt) {

      public boolean isExpired() {
         return System.currentTimeMillis() >= expiresAt;
      }

      public long remainingMillis() {
         return Math.max(0L, expiresAt - System.currentTimeMillis());
      }
   }

   /** One account's login history, mirrored from {@code TrustStore}. */
   record TrustRecord(long firstSeen, long lastSeen, int cleanLogins) {
   }
}
