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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * An IP list assembled from two sources: the static entries in config.yml and the entries added at
 * runtime through {@code /proxyshield whitelist add ...}, which are persisted to their own file so
 * they survive a restart without rewriting the user's config.
 */
public final class ManagedIpList {

   private final Path storageFile;
   private final Set<String> configEntries = new LinkedHashSet<>();
   private final Set<String> runtimeEntries = new LinkedHashSet<>();

   private volatile IpRangeSet compiled = IpRangeSet.EMPTY;

   public ManagedIpList(Path storageFile) {
      this.storageFile = storageFile;
   }

   /** Loads persisted runtime entries. Missing or unreadable files simply yield an empty list. */
   public synchronized void load() throws IOException {
      runtimeEntries.clear();
      if (Files.isRegularFile(storageFile)) {
         for (String line : Files.readAllLines(storageFile, StandardCharsets.UTF_8)) {
            String entry = IpAddresses.normalizeListEntry(line);
            if (entry != null && isAcceptable(entry)) {
               runtimeEntries.add(entry);
            }
         }
      }
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
      lines.addAll(runtimeEntries);
      Files.write(storageFile, lines, StandardCharsets.UTF_8);
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

   /**
    * Adds a runtime entry and persists it.
    *
    * @return {@code false} if the entry is malformed or already present
    */
   public synchronized boolean add(String rawEntry) throws IOException {
      String entry = IpAddresses.normalizeListEntry(rawEntry);
      if (entry == null || !isAcceptable(entry) || contains(entry, false)) {
         return false;
      }
      runtimeEntries.add(entry);
      recompile();
      save();
      return true;
   }

   /**
    * Removes a runtime entry.
    *
    * @return {@code false} if no such runtime entry exists
    */
   public synchronized boolean remove(String rawEntry) throws IOException {
      String entry = IpAddresses.normalizeListEntry(rawEntry);
      if (entry == null || !runtimeEntries.remove(entry)) {
         return false;
      }
      recompile();
      save();
      return true;
   }

   /** True when the address falls inside any configured or runtime range. */
   public boolean matches(String ip) {
      return compiled.contains(ip);
   }

   /** True when this exact entry string is present, optionally ignoring the config half. */
   public synchronized boolean contains(String entry, boolean includeConfig) {
      return runtimeEntries.contains(entry) || (includeConfig && configEntries.contains(entry));
   }

   public synchronized List<String> configEntries() {
      return List.copyOf(configEntries);
   }

   public synchronized List<String> runtimeEntries() {
      return List.copyOf(runtimeEntries);
   }

   public synchronized List<String> allEntries() {
      Set<String> all = new LinkedHashSet<>(configEntries);
      all.addAll(runtimeEntries);
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
      for (String entry : runtimeEntries) {
         builder.add(entry);
      }
      compiled = builder.build();
   }
}
