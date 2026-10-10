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

import de.lucasthcr.bridgesave.proxyshield.net.IpAddresses;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;

/**
 * Remembers which accounts connected from which address, for {@code /proxyshield alts}.
 * <p>
 * Kept in a plain tab separated file next to the config rather than in the verdict store: it is
 * a moderation aid, not something a network of proxies has to agree on, and an operator should be
 * able to read or prune it by hand. Entries older than the retention are dropped on save, so the
 * file cannot grow without bound on a busy server.
 */
public final class AltTracker {

   /** One account seen on one address. */
   public record Sighting(String address, UUID uuid, String name, long lastSeen) {
   }

   private final Path file;
   private final LongSupplier clock;
   private final Map<String, Map<UUID, Sighting>> byAddress = new ConcurrentHashMap<>();
   private final AtomicBoolean dirty = new AtomicBoolean();

   public AltTracker(Path file) {
      this(file, System::currentTimeMillis);
   }

   AltTracker(Path file, LongSupplier clock) {
      this.file = file;
      this.clock = clock;
   }

   /** Records a connection. Accounts without a UUID cannot be told apart and are skipped. */
   public void record(String ip, UUID uuid, String name) {
      String key = IpAddresses.cacheKey(ip);
      if (key == null || uuid == null) {
         return;
      }
      byAddress.computeIfAbsent(key, ignored -> new ConcurrentHashMap<>())
            .put(uuid, new Sighting(key, uuid, name == null ? "?" : name, clock.getAsLong()));
      dirty.set(true);
   }

   /** Every account seen on the address, most recent first. */
   public List<Sighting> accountsOn(String ip) {
      String key = IpAddresses.cacheKey(ip);
      if (key == null) {
         return List.of();
      }
      Map<UUID, Sighting> accounts = byAddress.get(key);
      if (accounts == null) {
         return List.of();
      }
      List<Sighting> out = new ArrayList<>(accounts.values());
      out.sort(Comparator.comparingLong(Sighting::lastSeen).reversed());
      return out;
   }

   /** Every address the named account was seen on. Case-insensitive. */
   public Set<String> addressesOf(String name) {
      String wanted = name.toLowerCase(Locale.ROOT);
      Set<String> out = new LinkedHashSet<>();
      for (Map.Entry<String, Map<UUID, Sighting>> entry : byAddress.entrySet()) {
         for (Sighting sighting : entry.getValue().values()) {
            if (sighting.name().toLowerCase(Locale.ROOT).equals(wanted)) {
               out.add(entry.getKey());
            }
         }
      }
      return out;
   }

   public synchronized void load() {
      byAddress.clear();
      if (!Files.isRegularFile(file)) {
         return;
      }
      try {
         for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            if (line.isBlank() || line.startsWith("#")) {
               continue;
            }
            String[] parts = line.split("\t");
            if (parts.length < 4) {
               continue;
            }
            try {
               UUID uuid = UUID.fromString(parts[1]);
               long seen = Long.parseLong(parts[3]);
               byAddress.computeIfAbsent(parts[0], ignored -> new ConcurrentHashMap<>())
                     .put(uuid, new Sighting(parts[0], uuid, parts[2], seen));
            } catch (IllegalArgumentException malformed) {
               // One damaged line must not cost the rest of the history.
            }
         }
      } catch (IOException unreadable) {
         // Starting with an empty history is better than refusing to start.
      }
   }

   /**
    * Writes the history if anything changed, dropping sightings older than the retention.
    *
    * @param retentionDays 0 keeps everything
    */
   public synchronized void save(int retentionDays) throws IOException {
      boolean pruned = prune(retentionDays);
      if (!dirty.getAndSet(false) && !pruned) {
         return;
      }
      Path parent = file.getParent();
      if (parent != null) {
         Files.createDirectories(parent);
      }
      List<String> lines = new ArrayList<>();
      lines.add("# address\tuuid\tname\tlast-seen-millis");
      for (Map<UUID, Sighting> accounts : byAddress.values()) {
         for (Sighting sighting : accounts.values()) {
            lines.add(sighting.address() + "\t" + sighting.uuid() + "\t" + sighting.name() + "\t"
                  + sighting.lastSeen());
         }
      }
      Path temp = file.resolveSibling(file.getFileName() + ".tmp");
      Files.write(temp, lines, StandardCharsets.UTF_8);
      try {
         Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING,
               StandardCopyOption.ATOMIC_MOVE);
      } catch (AtomicMoveNotSupportedException notOnThisFileSystem) {
         Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
      }
   }

   private boolean prune(int retentionDays) {
      if (retentionDays <= 0) {
         return false;
      }
      long cutoff = clock.getAsLong() - retentionDays * 86_400_000L;
      boolean removed = false;
      for (Map<UUID, Sighting> accounts : byAddress.values()) {
         removed |= accounts.values().removeIf(sighting -> sighting.lastSeen() < cutoff);
      }
      removed |= byAddress.values().removeIf(Map::isEmpty);
      return removed;
   }
}
