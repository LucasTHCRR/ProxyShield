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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The default store: two JSON files in the plugin folder.
 * <p>
 * Needs no setup, survives a restart, and is the right answer for a single server. It cannot be
 * shared, so a network running several proxies should point {@code storage.type} at a database or
 * Redis instead.
 */
public final class FileStorage implements ShieldStorage {

   private static final String VERDICTS = "lookup-cache.json";
   private static final String TRUST = "trusted-players.json";

   private final Platform platform;
   private final Path folder;
   private final Map<String, CachedVerdict> verdicts = new ConcurrentHashMap<>();
   private final AtomicBoolean dirty = new AtomicBoolean();

   public FileStorage(Platform platform) {
      this.platform = platform;
      this.folder = platform.dataFolder();
   }

   @Override
   public String name() {
      return "file";
   }

   @Override
   public boolean available() {
      return true;
   }

   @Override
   public boolean shared() {
      return false;
   }

   @Override
   public Map<String, CachedVerdict> preload() {
      Path file = folder.resolve(VERDICTS);
      if (!Files.isRegularFile(file)) {
         return Map.of();
      }

      Map<String, CachedVerdict> loaded = new LinkedHashMap<>();
      try {
         Object parsed = Json.parse(Files.readString(file, StandardCharsets.UTF_8));
         if (!(parsed instanceof List<?> entries)) {
            return Map.of();
         }
         for (Object element : entries) {
            String key = Json.stringAt(element, "ip");
            CachedVerdict verdict = VerdictCodec.decode(element);
            if (key != null && verdict != null) {
               loaded.put(key, verdict);
            }
         }
      } catch (IOException | RuntimeException unreadable) {
         platform.warn("Could not read " + VERDICTS + ", starting with an empty lookup cache: "
               + unreadable.getMessage());
         return Map.of();
      }

      verdicts.putAll(loaded);
      return loaded;
   }

   /** Always empty: everything this store holds was already handed over by {@link #preload()}. */
   @Override
   public Optional<CachedVerdict> find(String key) {
      return Optional.empty();
   }

   @Override
   public void put(String key, CachedVerdict verdict) {
      verdicts.put(key, verdict);
      dirty.set(true);
   }

   @Override
   public void invalidate(String key) {
      if (verdicts.remove(key) != null) {
         dirty.set(true);
      }
   }

   @Override
   public void clearVerdicts() {
      verdicts.clear();
      dirty.set(true);
   }

   @Override
   public int purgeExpired() {
      int before = verdicts.size();
      verdicts.values().removeIf(CachedVerdict::isExpired);
      int removed = before - verdicts.size();
      if (removed > 0) {
         dirty.set(true);
      }
      return removed;
   }

   @Override
   public Map<UUID, TrustRecord> loadTrust() {
      Path file = folder.resolve(TRUST);
      if (!Files.isRegularFile(file)) {
         return Map.of();
      }

      Map<UUID, TrustRecord> records = new LinkedHashMap<>();
      try {
         Object parsed = Json.parse(Files.readString(file, StandardCharsets.UTF_8));
         if (!(parsed instanceof List<?> entries)) {
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
               // Skip the entry rather than refuse to load the whole file.
            }
         }
      } catch (IOException | RuntimeException unreadable) {
         platform.warn("Could not read " + TRUST + ", starting with no trusted players: "
               + unreadable.getMessage());
      }
      return records;
   }

   @Override
   public void saveTrust(Map<UUID, TrustRecord> records) {
      Json.Writer writer = new Json.Writer().beginArray();
      for (Map.Entry<UUID, TrustRecord> entry : records.entrySet()) {
         writer.beginObject()
               .field("uuid", entry.getKey().toString())
               .field("firstSeen", entry.getValue().firstSeen())
               .field("lastSeen", entry.getValue().lastSeen())
               .field("logins", entry.getValue().cleanLogins())
               .endObject();
      }
      write(TRUST, writer.endArray().toString());
   }

   @Override
   public void flush() {
      if (!dirty.getAndSet(false)) {
         return;
      }

      Json.Writer writer = new Json.Writer().beginArray();
      List<Map.Entry<String, CachedVerdict>> snapshot = new ArrayList<>(verdicts.entrySet());
      for (Map.Entry<String, CachedVerdict> entry : snapshot) {
         if (entry.getValue().isExpired()) {
            continue;
         }
         writer.beginObject().field("ip", entry.getKey());
         VerdictCodec.writeFields(writer, entry.getValue());
         writer.endObject();
      }
      write(VERDICTS, writer.endArray().toString());
   }

   private void write(String fileName, String body) {
      try {
         Files.createDirectories(folder);
         Files.writeString(folder.resolve(fileName), body, StandardCharsets.UTF_8);
      } catch (IOException failure) {
         platform.warn("Could not write " + fileName + ": " + failure.getMessage());
      }
   }

   @Override
   public void close() {
      flush();
   }
}
