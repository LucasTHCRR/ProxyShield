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
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * A shared store that starts on a local one and moves over when the shared one answers.
 * <p>
 * Connecting to Redis or a database inside {@code enable} holds the whole start-up for as long as
 * the connect timeout, and when the server is unreachable the plugin used to stay on the local
 * store until somebody reloaded it. Here the local store serves from the first login, and a
 * background thread keeps trying the shared one, so a start while it is down and a recovery
 * afterwards need no operator.
 */
public final class FailoverStorage implements ShieldStorage {

   private static final long FIRST_RETRY_MILLIS = 5_000L;
   private static final long MAX_RETRY_MILLIS = 60_000L;

   private final long firstRetryMillis;

   private final Platform platform;
   private final ShieldStorage local;
   private final Supplier<ShieldStorage> shared;

   private volatile ShieldStorage active;
   private volatile Consumer<String> invalidationListener;
   private volatile boolean closed;
   private Thread connector;

   public FailoverStorage(Platform platform, ShieldStorage local, Supplier<ShieldStorage> shared) {
      this(platform, local, shared, FIRST_RETRY_MILLIS);
   }

   FailoverStorage(Platform platform, ShieldStorage local, Supplier<ShieldStorage> shared,
         long firstRetryMillis) {
      this.firstRetryMillis = firstRetryMillis;
      this.platform = platform;
      this.local = local;
      this.shared = shared;
      this.active = local;
      startConnector();
   }

   private void startConnector() {
      connector = new Thread(() -> {
         long wait = firstRetryMillis;
         boolean reported = false;
         while (!closed) {
            ShieldStorage candidate = null;
            try {
               candidate = shared.get();
            } catch (RuntimeException failure) {
               // treated like an unreachable server
            }
            if (candidate != null && candidate.available()) {
               synchronized (this) {
                  if (closed) {
                     candidate.close();
                     return;
                  }
                  Consumer<String> listener = invalidationListener;
                  if (listener != null) {
                     candidate.onRemoteInvalidation(listener);
                  }
                  active = candidate;
               }
               platform.info("The shared store (" + candidate.name() + ") is reachable, verdicts and "
                     + "trust are shared from now on.");
               return;
            }
            if (candidate != null) {
               candidate.close();
            }
            if (!reported) {
               reported = true;
               platform.warn("The shared store is unreachable. ProxyShield runs on its local store and "
                     + "keeps trying in the background.");
            }
            try {
               Thread.sleep(wait);
            } catch (InterruptedException interrupted) {
               Thread.currentThread().interrupt();
               return;
            }
            wait = Math.min(MAX_RETRY_MILLIS, wait * 2);
         }
      }, "ProxyShield-storage-connector");
      connector.setDaemon(true);
      connector.start();
   }

   @Override
   public String name() {
      return active.name();
   }

   @Override
   public boolean available() {
      return active.available();
   }

   @Override
   public boolean shared() {
      return active.shared();
   }

   @Override
   public Map<String, CachedVerdict> preload() {
      return local.preload();
   }

   @Override
   public Optional<CachedVerdict> find(String key) {
      return active.find(key);
   }

   @Override
   public void put(String key, CachedVerdict verdict) {
      active.put(key, verdict);
   }

   @Override
   public void invalidate(String key) {
      active.invalidate(key);
   }

   @Override
   public void clearVerdicts() {
      active.clearVerdicts();
   }

   @Override
   public Map<UUID, TrustRecord> loadTrust() {
      return active.loadTrust();
   }

   @Override
   public void saveTrust(Map<UUID, TrustRecord> records) {
      active.saveTrust(records);
   }

   @Override
   public synchronized void onRemoteInvalidation(Consumer<String> listener) {
      invalidationListener = listener;
      if (active != local) {
         active.onRemoteInvalidation(listener);
      }
   }

   @Override
   public void flush() {
      active.flush();
      if (active != local) {
         local.flush();
      }
   }

   @Override
   public int purgeExpired() {
      return active.purgeExpired();
   }

   @Override
   public void close() {
      synchronized (this) {
         closed = true;
      }
      Thread thread = connector;
      if (thread != null) {
         thread.interrupt();
      }
      if (active != local) {
         active.close();
      }
      local.close();
   }
}
