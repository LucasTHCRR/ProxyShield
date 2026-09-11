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

import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import de.lucasthcr.bridgesave.proxyshield.util.Json;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Verdicts and trust in Redis, shared across a whole network in real time.
 * <p>
 * This is the store for a network of proxies: one lookup is paid for by whichever front end sees
 * the player first, and every other server reads the answer instead of spending its own quota on
 * the same address. Expiry is Redis's own, so nothing has to be swept.
 * <p>
 * It also carries the one thing a database cannot: a push. Whitelisting an address or clearing the
 * cache on one server publishes an invalidation that the others act on immediately, instead of
 * leaving them serving a stale verdict until it expires on its own.
 */
public final class RedisStorage implements ShieldStorage {

   private static final String TRUST_KEY = "proxyshield:trust";

   private final Platform platform;
   private final RedisClient commands;
   private final RedisClient subscriber;
   private final String prefix;
   private final String channel;
   private final String serverId;
   private final AtomicBoolean healthy = new AtomicBoolean();
   private final AtomicBoolean reportedFailure = new AtomicBoolean();

   private volatile Thread subscriberThread;
   private volatile boolean closed;

   public RedisStorage(Platform platform, String host, int port, String username, String password,
         int database, int timeoutMillis, String prefix, String serverId) {
      this.platform = platform;
      this.prefix = prefix == null || prefix.isBlank() ? "proxyshield:" : prefix;
      this.channel = this.prefix + "invalidate";
      this.serverId = serverId == null || serverId.isBlank()
            ? UUID.randomUUID().toString()
            : serverId;
      this.commands = new RedisClient(host, port, username, password, database, timeoutMillis);
      this.subscriber = new RedisClient(host, port, username, password, database, timeoutMillis);

      try {
         commands.connect();
         healthy.set(true);
         platform.info("Connected to Redis at " + host + ":" + port
               + " for shared verdict and trust storage.");
      } catch (IOException failure) {
         reportFailure("connect", failure);
      }
   }

   @Override
   public String name() {
      return "Redis";
   }

   @Override
   public boolean available() {
      return healthy.get();
   }

   @Override
   public boolean shared() {
      return true;
   }

   /** Nothing is preloaded: a shared cache exists so it does not have to live in every heap. */
   @Override
   public Map<String, CachedVerdict> preload() {
      return Map.of();
   }

   @Override
   public Optional<CachedVerdict> find(String key) {
      try {
         String stored = commands.get(prefix + "ip:" + key);
         healthy.set(true);
         reportedFailure.set(false);
         CachedVerdict verdict = VerdictCodec.decode(stored);
         return verdict == null || verdict.isExpired() ? Optional.empty() : Optional.of(verdict);
      } catch (IOException | RuntimeException failure) {
         reportFailure("read a verdict", failure);
         return Optional.empty();
      }
   }

   @Override
   public void put(String key, CachedVerdict verdict) {
      try {
         // Redis expires the key itself, so the shared cache never needs sweeping.
         commands.setWithExpiry(prefix + "ip:" + key, VerdictCodec.encode(verdict),
               verdict.remainingMillis());
         healthy.set(true);
      } catch (IOException | RuntimeException failure) {
         reportFailure("store a verdict", failure);
      }
   }

   @Override
   public void invalidate(String key) {
      try {
         commands.delete(prefix + "ip:" + key);
         // Tell the other servers, tagged so this one ignores its own message.
         commands.publish(channel, serverId + " " + key);
      } catch (IOException | RuntimeException failure) {
         reportFailure("invalidate a verdict", failure);
      }
   }

   @Override
   public void clearVerdicts() {
      try {
         commands.publish(channel, serverId + " *");
      } catch (IOException | RuntimeException failure) {
         reportFailure("publish a cache clear", failure);
      }
   }

   @Override
   public Map<UUID, TrustRecord> loadTrust() {
      try {
         String stored = commands.get(TRUST_KEY);
         if (stored == null || stored.isBlank()) {
            return Map.of();
         }

         Map<UUID, TrustRecord> records = new LinkedHashMap<>();
         if (!(Json.parse(stored) instanceof List<?> entries)) {
            return Map.of();
         }
         for (Object element : entries) {
            String uuid = Json.stringAt(element, "uuid");
            Double firstSeen = Json.numberAt(element, "firstSeen");
            Double lastSeen = Json.numberAt(element, "lastSeen");
            Double logins = Json.numberAt(element, "logins");
            if (uuid == null || firstSeen == null || logins == null) {
               continue;
            }
            try {
               records.put(UUID.fromString(uuid), new TrustRecord(firstSeen.longValue(),
                     lastSeen == null ? firstSeen.longValue() : lastSeen.longValue(),
                     logins.intValue()));
            } catch (IllegalArgumentException notAUuid) {
               // Skip the entry rather than lose the whole set.
            }
         }
         return records;
      } catch (IOException | RuntimeException failure) {
         reportFailure("read the trust list", failure);
         return Map.of();
      }
   }

   @Override
   public void saveTrust(Map<UUID, TrustRecord> records) {
      if (records.isEmpty()) {
         return;
      }

      Json.Writer writer = new Json.Writer().beginArray();
      for (Map.Entry<UUID, TrustRecord> entry : records.entrySet()) {
         writer.beginObject()
               .field("uuid", entry.getKey().toString())
               .field("firstSeen", entry.getValue().firstSeen())
               .field("lastSeen", entry.getValue().lastSeen())
               .field("logins", entry.getValue().cleanLogins())
               .endObject();
      }

      try {
         // Trust has no natural expiry, so it is stored for a year and rewritten as it changes.
         commands.setWithExpiry(TRUST_KEY, writer.endArray().toString(), 365L * 86_400_000L);
      } catch (IOException | RuntimeException failure) {
         reportFailure("write the trust list", failure);
      }
   }

   /**
    * Starts the listener thread for invalidations published by the other servers.
    * <p>
    * {@code "*"} means "drop everything", anything else is one cache key. Messages tagged with this
    * server's own id are skipped, since it has already acted on them locally.
    */
   @Override
   public void onRemoteInvalidation(Consumer<String> listener) {
      if (subscriberThread != null) {
         return;
      }

      Thread thread = new Thread(() -> {
         while (!closed) {
            try {
               subscriber.subscribe(channel, (topic, message) -> {
                  int space = message.indexOf(' ');
                  if (space <= 0) {
                     return;
                  }
                  String origin = message.substring(0, space);
                  String key = message.substring(space + 1);
                  if (!origin.equals(serverId)) {
                     listener.accept(key);
                  }
               });
            } catch (IOException dropped) {
               if (closed) {
                  return;
               }
               // A dropped subscription is normal on a restart or a failover; wait and retry.
               try {
                  Thread.sleep(5_000L);
               } catch (InterruptedException interrupted) {
                  Thread.currentThread().interrupt();
                  return;
               }
            }
         }
      }, "ProxyShield-redis-subscriber");
      thread.setDaemon(true);
      thread.start();
      subscriberThread = thread;
   }

   private void reportFailure(String what, Exception failure) {
      healthy.set(false);
      if (reportedFailure.compareAndSet(false, true)) {
         platform.warn("Could not " + what + " on Redis: " + failure.getMessage()
               + ". ProxyShield keeps working from its in-memory cache; logins are not blocked "
               + "by this.");
      }
   }

   @Override
   public void close() {
      closed = true;
      Thread thread = subscriberThread;
      if (thread != null) {
         thread.interrupt();
      }
      List<RedisClient> clients = new ArrayList<>(List.of(commands, subscriber));
      for (RedisClient client : clients) {
         client.close();
      }
      healthy.set(false);
   }
}
