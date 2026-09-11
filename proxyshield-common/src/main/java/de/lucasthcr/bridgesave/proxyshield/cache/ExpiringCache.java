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

package de.lucasthcr.bridgesave.proxyshield.cache;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A bounded cache with per-entry expiry and least-recently-used eviction.
 * <p>
 * v1 used a plain {@code ConcurrentHashMap} that was never pruned, so a busy proxy would grow one
 * entry per unique address forever and a result stayed cached until the next restart.
 */
public final class ExpiringCache<K, V> {

   private final ReentrantLock lock = new ReentrantLock();
   private final LinkedHashMap<K, Entry<V>> entries;
   private final int maxEntries;
   private final long ttlMillis;

   private long hits;
   private long misses;

   public ExpiringCache(int maxEntries, long ttlMillis) {
      this.maxEntries = Math.max(1, maxEntries);
      this.ttlMillis = Math.max(1L, ttlMillis);
      // accessOrder = true turns this into an LRU
      this.entries = new LinkedHashMap<>(16, 0.75f, true);
   }

   public Optional<V> get(K key) {
      lock.lock();
      try {
         Entry<V> entry = entries.get(key);
         if (entry == null) {
            misses++;
            return Optional.empty();
         }
         if (entry.isExpired()) {
            entries.remove(key);
            misses++;
            return Optional.empty();
         }
         hits++;
         return Optional.of(entry.value);
      } finally {
         lock.unlock();
      }
   }

   public void put(K key, V value) {
      put(key, value, ttlMillis);
   }

   /**
    * Stores an entry with its own lifetime.
    * <p>
    * A confirmed VPN range stays a VPN range for far longer than "this address looked clean five
    * minutes ago" stays true, so the two are cached on different clocks: a longer one for flagged
    * addresses cuts requests without letting a wrongly flagged player wait out the default TTL.
    */
   public void put(K key, V value, long customTtlMillis) {
      lock.lock();
      try {
         entries.put(key, new Entry<>(value,
               System.currentTimeMillis() + Math.max(1L, customTtlMillis)));
         evictIfNeeded();
      } finally {
         lock.unlock();
      }
   }

   /** Restores an entry that already carries an absolute expiry, used by the on-disk cache. */
   public void putWithExpiry(K key, V value, long expiresAt) {
      if (expiresAt <= System.currentTimeMillis()) {
         return;
      }
      lock.lock();
      try {
         entries.put(key, new Entry<>(value, expiresAt));
         evictIfNeeded();
      } finally {
         lock.unlock();
      }
   }

   /** A copy of the live entries with their absolute expiry, for writing the cache to disk. */
   public Map<K, Long> expirySnapshot() {
      lock.lock();
      try {
         Map<K, Long> out = new LinkedHashMap<>(entries.size());
         for (Map.Entry<K, Entry<V>> entry : entries.entrySet()) {
            if (!entry.getValue().isExpired()) {
               out.put(entry.getKey(), entry.getValue().expiresAt());
            }
         }
         return out;
      } finally {
         lock.unlock();
      }
   }

   /** The live value for a key without counting a hit or a miss. */
   public V peek(K key) {
      lock.lock();
      try {
         Entry<V> entry = entries.get(key);
         return entry == null || entry.isExpired() ? null : entry.value;
      } finally {
         lock.unlock();
      }
   }

   public void invalidate(K key) {
      lock.lock();
      try {
         entries.remove(key);
      } finally {
         lock.unlock();
      }
   }

   public void clear() {
      lock.lock();
      try {
         entries.clear();
      } finally {
         lock.unlock();
      }
   }

   /** Drops every expired entry. Called periodically so idle servers do not hold stale data. */
   public int purgeExpired() {
      lock.lock();
      try {
         int removed = 0;
         Iterator<Map.Entry<K, Entry<V>>> iterator = entries.entrySet().iterator();
         while (iterator.hasNext()) {
            if (iterator.next().getValue().isExpired()) {
               iterator.remove();
               removed++;
            }
         }
         return removed;
      } finally {
         lock.unlock();
      }
   }

   public int size() {
      lock.lock();
      try {
         return entries.size();
      } finally {
         lock.unlock();
      }
   }

   public long hits() {
      lock.lock();
      try {
         return hits;
      } finally {
         lock.unlock();
      }
   }

   public long misses() {
      lock.lock();
      try {
         return misses;
      } finally {
         lock.unlock();
      }
   }

   private void evictIfNeeded() {
      if (entries.size() <= maxEntries) {
         return;
      }
      Iterator<Map.Entry<K, Entry<V>>> iterator = entries.entrySet().iterator();
      while (entries.size() > maxEntries && iterator.hasNext()) {
         iterator.next();
         iterator.remove();
      }
   }

   private record Entry<V>(V value, long expiresAt) {
      boolean isExpired() {
         return System.currentTimeMillis() > expiresAt;
      }
   }
}
