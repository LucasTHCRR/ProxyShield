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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FailoverStorageTest {

   @TempDir
   Path tempDir;

   /** A shared store that reports whatever availability the test wants. */
   private static ShieldStorage stub(boolean available) {
      return (ShieldStorage) Proxy.newProxyInstance(ShieldStorage.class.getClassLoader(),
            new Class<?>[] {ShieldStorage.class}, (proxy, method, args) -> switch (method.getName()) {
               case "name" -> "stub";
               case "available", "shared" -> available;
               case "find" -> Optional.empty();
               case "preload", "loadTrust" -> Map.of();
               case "purgeExpired" -> 0;
               default -> null;
            });
   }

   private static void await(java.util.function.BooleanSupplier condition) throws InterruptedException {
      long end = System.currentTimeMillis() + 5_000;
      while (!condition.getAsBoolean() && System.currentTimeMillis() < end) {
         Thread.sleep(20);
      }
   }

   @Test
   @DisplayName("It answers from the local store at once while the shared one is down")
   void startsOnTheLocalStore() {
      RecordingPlatform platform = new RecordingPlatform(tempDir);
      FailoverStorage storage = new FailoverStorage(platform, new FileStorage(platform),
            () -> stub(false), 60_000L);

      assertEquals("file", storage.name());
      assertFalse(storage.shared());
      storage.close();
   }

   @Test
   @DisplayName("It moves to the shared store once that answers, without a reload")
   void movesOverWhenTheSharedStoreRecovers() throws InterruptedException {
      RecordingPlatform platform = new RecordingPlatform(tempDir);
      AtomicInteger attempts = new AtomicInteger();
      FailoverStorage storage = new FailoverStorage(platform, new FileStorage(platform),
            () -> stub(attempts.incrementAndGet() >= 3), 20L);

      await(() -> storage.shared());

      assertTrue(storage.shared(), "the shared store should have taken over");
      assertEquals("stub", storage.name());
      assertTrue(attempts.get() >= 3);
      storage.close();
   }
}
