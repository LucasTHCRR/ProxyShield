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

import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import de.lucasthcr.bridgesave.proxyshield.storage.FileStorage;
import de.lucasthcr.bridgesave.proxyshield.storage.ShieldStorage;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Remembers which accounts have a history on this server, so a regular does not get thrown out by a
 * tightened rule or a provider having a bad day.
 * <p>
 * Every anti-VPN's real cost is false positives, and they land hardest on the people least able to
 * do anything about them: mobile players behind carrier-grade NAT, whose address can appear in a
 * datacenter range one evening and not the next. An account that has connected from a clean address
 * repeatedly over several days is almost certainly not the botnet, so it stops being re-judged on
 * every login.
 * <p>
 * Trust never overrides the manual blacklist - an operator's explicit decision outranks any
 * inference made here.
 */
public final class TrustStore {

   /** Written back at most this often, so a busy proxy is not doing constant I/O. */
   private static final long SAVE_INTERVAL_MILLIS = 300_000L;

   private final ShieldStorage storage;
   private final ConcurrentHashMap<UUID, Record> records = new ConcurrentHashMap<>();
   private final AtomicBoolean dirty = new AtomicBoolean();

   private volatile long lastSave = System.currentTimeMillis();

   public TrustStore(ShieldStorage storage) {
      this.storage = storage;
   }

   /** Convenience for the default file-backed store, used by tests and single-server setups. */
   public TrustStore(Platform platform) {
      this(new FileStorage(platform));
   }

   /** One account's history. */
   public record Record(long firstSeen, long lastSeen, int cleanLogins) {

      Record withLogin(long now) {
         return new Record(firstSeen == 0L ? now : firstSeen, now, cleanLogins + 1);
      }

      /** Whole days between the first sighting and now. */
      public long ageInDays() {
         return firstSeen == 0L ? 0L : (System.currentTimeMillis() - firstSeen) / 86_400_000L;
      }
   }

   /**
    * Whether this account has earned an exemption.
    *
    * @param minLogins how many clean logins are needed
    * @param minDays   how long the account has to have been around
    */
   public boolean trusted(UUID uuid, int minLogins, int minDays) {
      if (uuid == null) {
         return false;
      }
      Record record = records.get(uuid);
      return record != null && record.cleanLogins() >= minLogins && record.ageInDays() >= minDays;
   }

   /** Records a login that passed every check. */
   public void recordCleanLogin(UUID uuid) {
      if (uuid == null) {
         return;
      }
      long now = System.currentTimeMillis();
      records.compute(uuid, (key, existing) ->
            existing == null ? new Record(now, now, 1) : existing.withLogin(now));
      dirty.set(true);
   }

   /**
    * Drops an account's history, e.g. after it was caught on a proxy.
    * <p>
    * A shared or sold account that starts connecting through a VPN should have to earn its
    * exemption again rather than keep one built up by its previous owner.
    */
   public void forget(UUID uuid) {
      if (uuid != null && records.remove(uuid) != null) {
         dirty.set(true);
      }
   }

   public Record record(UUID uuid) {
      return uuid == null ? null : records.get(uuid);
   }

   public int size() {
      return records.size();
   }

   /** Reads the history from whichever store is configured, shared or local. */
   public void load() {
      for (Map.Entry<UUID, ShieldStorage.TrustRecord> entry : storage.loadTrust().entrySet()) {
         ShieldStorage.TrustRecord stored = entry.getValue();
         records.put(entry.getKey(), new Record(stored.firstSeen(), stored.lastSeen(),
               stored.cleanLogins()));
      }
   }

   /** Writes the store if anything changed and the interval has elapsed. */
   public void saveIfDue() {
      if (!dirty.get() || System.currentTimeMillis() - lastSave < SAVE_INTERVAL_MILLIS) {
         return;
      }
      save();
   }

   public void save() {
      if (!dirty.getAndSet(false)) {
         return;
      }
      lastSave = System.currentTimeMillis();

      Map<UUID, ShieldStorage.TrustRecord> snapshot = new LinkedHashMap<>(records.size());
      for (Map.Entry<UUID, Record> entry : records.entrySet()) {
         snapshot.put(entry.getKey(), new ShieldStorage.TrustRecord(entry.getValue().firstSeen(),
               entry.getValue().lastSeen(), entry.getValue().cleanLogins()));
      }
      storage.saveTrust(snapshot);
   }
}
