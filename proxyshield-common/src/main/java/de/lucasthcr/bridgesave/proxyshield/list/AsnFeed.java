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

package de.lucasthcr.bridgesave.proxyshield.list;

import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import de.lucasthcr.bridgesave.proxyshield.util.Json;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Network numbers to block, downloaded from lists the operator names.
 * <p>
 * The ASN rule in config.yml is only as good as the operator's own knowledge. A maintained list
 * of VPN and hosting networks keeps it current without anybody editing the config. Two shapes are
 * read: a JSON array (of numbers, of strings like {@code "AS9009"}, or of objects carrying an
 * {@code asn} field) and plain text with one network per line, where anything after the number
 * is ignored so {@code AS9009 M247 Europe} works.
 * <p>
 * The last good download is kept on disk, so a feed that is briefly unreachable does not empty
 * the set, and protection is in place from the first login after a restart.
 */
public final class AsnFeed {

   private static final Pattern LINE = Pattern.compile("^\\s*(?:AS)?(\\d{1,10})\\b",
         Pattern.CASE_INSENSITIVE);
   private static final Pattern TOKEN = Pattern.compile("^(?:AS)?(\\d{1,10})$",
         Pattern.CASE_INSENSITIVE);
   private static final int MAX_BYTES = 8 * 1024 * 1024;

   private final Platform platform;
   private final Path cacheFile;
   private volatile Set<String> asns = Set.of();
   private volatile long lastAttempt;

   public AsnFeed(Platform platform) {
      this.platform = platform;
      this.cacheFile = platform.dataFolder().resolve("asn-cache.txt");
   }

   /** Whether the network, in {@code AS<digits>} form, is on any downloaded list. */
   public boolean contains(String asn) {
      return asn != null && asns.contains(asn);
   }

   /** Whether the last download attempt is older than the interval. */
   public boolean due(long intervalMillis) {
      return System.currentTimeMillis() - lastAttempt >= intervalMillis;
   }

   public int size() {
      return asns.size();
   }

   /** Restores the last good download. */
   public void loadFromDisk() {
      if (!Files.isRegularFile(cacheFile)) {
         return;
      }
      try {
         asns = Set.copyOf(parse(Files.readString(cacheFile, StandardCharsets.UTF_8)));
      } catch (IOException unreadable) {
         platform.warn("Could not read asn-cache.txt: " + unreadable.getMessage());
      }
   }

   /**
    * Downloads every source. Blocking; call from an async context. A source that fails keeps
    * nothing of its own, but the set is only replaced when at least one source answered.
    */
   public void refresh(List<String> sources, int timeoutSeconds) {
      lastAttempt = System.currentTimeMillis();
      if (sources.isEmpty()) {
         asns = Set.of();
         return;
      }
      Set<String> merged = new LinkedHashSet<>();
      int answered = 0;
      for (String source : sources) {
         try {
            merged.addAll(parse(download(source, timeoutSeconds * 1000)));
            answered++;
         } catch (IOException | RuntimeException failure) {
            platform.warn("ASN list " + source + " could not be downloaded: "
                  + failure.getMessage());
         }
      }
      if (answered == 0) {
         return;
      }
      asns = Set.copyOf(merged);
      try {
         Files.createDirectories(cacheFile.getParent());
         Files.write(cacheFile, new ArrayList<>(merged), StandardCharsets.UTF_8);
      } catch (IOException failure) {
         platform.warn("Could not write asn-cache.txt: " + failure.getMessage());
      }
   }

   private String download(String source, int timeoutMillis) throws IOException {
      if (!source.startsWith("https://")) {
         throw new IOException("only https sources are accepted");
      }
      HttpURLConnection connection =
            (HttpURLConnection) URI.create(source).toURL().openConnection();
      try {
         connection.setConnectTimeout(timeoutMillis);
         connection.setReadTimeout(timeoutMillis);
         connection.setRequestProperty("User-Agent", "ProxyShield/" + platform.version());
         int status = connection.getResponseCode();
         if (status != 200) {
            throw new IOException("HTTP " + status);
         }
         try (InputStream in = connection.getInputStream()) {
            return new String(in.readNBytes(MAX_BYTES), StandardCharsets.UTF_8);
         }
      } finally {
         connection.disconnect();
      }
   }

   /** Visible for testing. */
   static Set<String> parse(String body) {
      Set<String> out = new LinkedHashSet<>();
      String trimmed = body.stripLeading();
      if (trimmed.startsWith("[")) {
         Object root = Json.parse(trimmed);
         if (root instanceof List<?> elements) {
            for (Object element : elements) {
               Object value = element instanceof Map<?, ?> map ? map.get("asn") : element;
               String asn = normalize(value);
               if (asn != null) {
                  out.add(asn);
               }
            }
         }
         return out;
      }
      for (String line : body.split("\\R")) {
         if (line.isBlank() || line.stripLeading().startsWith("#")) {
            continue;
         }
         Matcher matcher = LINE.matcher(line);
         if (matcher.find()) {
            out.add("AS" + Long.parseLong(matcher.group(1)));
         }
      }
      return out;
   }

   private static String normalize(Object value) {
      if (value instanceof Number number) {
         return number.longValue() > 0L ? "AS" + number.longValue() : null;
      }
      if (value instanceof String text) {
         Matcher matcher = TOKEN.matcher(text.trim());
         return matcher.matches() ? "AS" + Long.parseLong(matcher.group(1)) : null;
      }
      return null;
   }
}
