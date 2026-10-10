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

package de.lucasthcr.bridgesave.proxyshield.net;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;

/**
 * An IP list assembled from two sources: the static entries in config.yml and the entries added at
 * runtime through {@code /proxyshield whitelist add ...}, which are persisted to their own file so
 * they survive a restart without rewriting the user's config.
 * <p>
 * A runtime entry can carry who added it, why, and when it runs out. The details live in a
 * trailing comment on the entry's line, so the file stays readable and a list written by an older
 * build loads unchanged.
 */
public final class ManagedIpList {

   /** What is known about a runtime entry. {@code expiresAt} is 0 for a permanent one. */
   public record Details(String reason, String addedBy, long addedAt, long expiresAt) {

      static final Details NONE = new Details(null, null, 0L, 0L);

      public boolean permanent() {
         return expiresAt <= 0L;
      }

      boolean expired(long now) {
         return expiresAt > 0L && now >= expiresAt;
      }
   }

   private final Path storageFile;
   private final LongSupplier clock;
   private final Set<String> configEntries = new LinkedHashSet<>();
   private final Map<String, Details> runtimeEntries = new LinkedHashMap<>();

   private volatile IpRangeSet compiled = IpRangeSet.EMPTY;
   private volatile long nextExpiry = Long.MAX_VALUE;

   public ManagedIpList(Path storageFile) {
      this(storageFile, System::currentTimeMillis);
   }

   public ManagedIpList(Path storageFile, LongSupplier clock) {
      this.storageFile = storageFile;
      this.clock = clock;
   }

   /** Loads persisted runtime entries. Missing or unreadable files simply yield an empty list. */
   public synchronized void load() throws IOException {
      runtimeEntries.clear();
      if (Files.isRegularFile(storageFile)) {
         for (String line : Files.readAllLines(storageFile, StandardCharsets.UTF_8)) {
            String entry = IpAddresses.normalizeListEntry(line);
            if (entry != null && isAcceptable(entry)) {
               runtimeEntries.put(entry, parseDetails(line));
            }
         }
      }
      dropExpired(clock.getAsLong());
      recompile();
   }

   private synchronized void save() throws IOException {
      if (runtimeEntries.isEmpty() && !Files.exists(storageFile)) {
         return;
      }
      Path parent = storageFile.getParent();
      if (parent != null) {
         Files.createDirectories(parent);
      }

      List<String> lines = new ArrayList<>(runtimeEntries.size() + 3);
      lines.add("# Entries added with /proxyshield whitelist|blacklist add");
      lines.add("# One address, CIDR block or range per line.");
      for (Map.Entry<String, Details> entry : runtimeEntries.entrySet()) {
         lines.add(entry.getKey() + formatDetails(entry.getValue()));
      }
      Files.write(storageFile, lines, StandardCharsets.UTF_8);
   }

   private static String formatDetails(Details details) {
      if (details == null || details.equals(Details.NONE)) {
         return "";
      }
      StringBuilder out = new StringBuilder(" #");
      if (details.addedAt() > 0L) {
         out.append(" added=").append(details.addedAt());
      }
      if (details.expiresAt() > 0L) {
         out.append(" until=").append(details.expiresAt());
      }
      if (details.addedBy() != null) {
         out.append(" by=").append(details.addedBy().replace(' ', '_'));
      }
      if (details.reason() != null) {
         // Last on the line, so a reason with spaces needs no quoting.
         out.append(" reason=").append(details.reason().replace('\n', ' '));
      }
      return out.toString();
   }

   static Details parseDetails(String line) {
      int hash = line.indexOf('#');
      if (hash < 0) {
         return Details.NONE;
      }
      String comment = line.substring(hash + 1).trim();
      if (!comment.isEmpty() && comment.indexOf('=') < 0) {
         // A note written by hand into an older file: keep it as the reason rather than lose it
         // on the next save.
         return new Details(comment, null, 0L, 0L);
      }
      String reason = null;
      int reasonAt = comment.indexOf("reason=");
      if (reasonAt >= 0) {
         reason = comment.substring(reasonAt + "reason=".length()).trim();
         comment = comment.substring(0, reasonAt);
      }
      long added = 0L;
      long until = 0L;
      String by = null;
      for (String token : comment.trim().split("\\s+")) {
         int eq = token.indexOf('=');
         if (eq <= 0) {
            continue;
         }
         String key = token.substring(0, eq);
         String value = token.substring(eq + 1);
         switch (key) {
            case "added" -> added = parseLong(value);
            case "until" -> until = parseLong(value);
            case "by" -> by = value.isEmpty() ? null : value;
            default -> {
            }
         }
      }
      return new Details(reason == null || reason.isEmpty() ? null : reason, by, added, until);
   }

   private static long parseLong(String value) {
      try {
         return Long.parseLong(value);
      } catch (NumberFormatException ignored) {
         return 0L;
      }
   }

   /** Replaces the config half of the list, keeping runtime entries intact. */
   public synchronized void setConfigEntries(Collection<String> entries) {
      configEntries.clear();
      for (String raw : entries) {
         String entry = IpAddresses.normalizeListEntry(raw);
         if (entry != null && isAcceptable(entry)) {
            configEntries.add(entry);
         }
      }
      recompile();
   }

   /** Adds a permanent runtime entry without details. */
   public boolean add(String rawEntry) throws IOException {
      return add(rawEntry, null, null, 0L);
   }

   /**
    * Adds a runtime entry and persists it.
    *
    * @param durationMillis how long the entry lasts, 0 for permanent
    * @return {@code false} if the entry is malformed or already present
    */
   public synchronized boolean add(String rawEntry, String reason, String addedBy,
         long durationMillis) throws IOException {
      String entry = IpAddresses.normalizeListEntry(rawEntry);
      if (entry == null || !isAcceptable(entry) || contains(entry, false)) {
         return false;
      }
      long now = clock.getAsLong();
      runtimeEntries.put(entry, new Details(blankToNull(reason), blankToNull(addedBy), now,
            durationMillis > 0L ? now + durationMillis : 0L));
      recompile();
      save();
      return true;
   }

   private static String blankToNull(String value) {
      return value == null || value.isBlank() ? null : value.trim();
   }

   /**
    * Removes a runtime entry.
    *
    * @return {@code false} if no such runtime entry exists
    */
   public synchronized boolean remove(String rawEntry) throws IOException {
      String entry = IpAddresses.normalizeListEntry(rawEntry);
      if (entry == null || runtimeEntries.remove(entry) == null) {
         return false;
      }
      recompile();
      save();
      return true;
   }

   /**
    * Removes every runtime entry. Config entries are untouched.
    *
    * @return how many entries were removed
    */
   public synchronized int purge() throws IOException {
      int removed = runtimeEntries.size();
      if (removed > 0) {
         runtimeEntries.clear();
         recompile();
         save();
      }
      return removed;
   }

   /** The details of a runtime entry, or {@code null} if it is not one. */
   public synchronized Details details(String rawEntry) {
      String entry = IpAddresses.normalizeListEntry(rawEntry);
      return entry == null ? null : runtimeEntries.get(entry);
   }

   /** True when the address falls inside any configured or runtime range. */
   public boolean matches(String ip) {
      if (clock.getAsLong() >= nextExpiry) {
         expireNow();
      }
      return compiled.contains(ip);
   }

   /** Drops entries that ran out. Also run from the heartbeat so the file is rewritten. */
   public synchronized void expireNow() {
      if (dropExpired(clock.getAsLong())) {
         recompile();
         try {
            save();
         } catch (IOException ignored) {
            // The entry is gone from memory either way; the file catches up on the next save.
         }
      } else {
         recompile();
      }
   }

   private boolean dropExpired(long now) {
      return runtimeEntries.values().removeIf(details -> details.expired(now));
   }

   /** True when this exact entry string is present, optionally ignoring the config half. */
   public synchronized boolean contains(String entry, boolean includeConfig) {
      return runtimeEntries.containsKey(entry)
            || (includeConfig && configEntries.contains(entry));
   }

   public synchronized List<String> configEntries() {
      return List.copyOf(configEntries);
   }

   public synchronized List<String> runtimeEntries() {
      return List.copyOf(runtimeEntries.keySet());
   }

   public synchronized List<String> allEntries() {
      Set<String> all = new LinkedHashSet<>(configEntries);
      all.addAll(runtimeEntries.keySet());
      return List.copyOf(all);
   }

   public int rangeCount() {
      return compiled.rangeCount();
   }

   public boolean isEmpty() {
      return compiled.isEmpty();
   }

   /** Rejects anything {@link IpRangeSet} could not turn into a range. */
   public static boolean isAcceptable(String entry) {
      return IpRangeSet.builder().add(entry);
   }

   private void recompile() {
      IpRangeSet.Builder builder = IpRangeSet.builder();
      for (String entry : configEntries) {
         builder.add(entry);
      }
      long soonest = Long.MAX_VALUE;
      for (Map.Entry<String, Details> entry : runtimeEntries.entrySet()) {
         builder.add(entry.getKey());
         long expires = entry.getValue().expiresAt();
         if (expires > 0L && expires < soonest) {
            soonest = expires;
         }
      }
      compiled = builder.build();
      nextExpiry = soonest;
   }
}
