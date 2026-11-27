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

import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.GZIPInputStream;

/**
 * Which kind of network an address sits in, answered from a file on disk with no request.
 * <p>
 * The feed is tab separated, one range per line: start, end, class, country, ASN, IP version.
 * Class {@code E} marks a network that serves many end users, {@code H} one that looks like
 * hosting, {@code N} one with no measured end users at all. Any other letter (the feed also has
 * {@code S} for small access networks) is known to be neither and only supplies country and ASN.
 * Both address families are held as sorted arrays and searched by bisection, so a lookup costs
 * microseconds.
 * <p>
 * The last good download stays on disk, so a feed that is briefly unreachable changes nothing and
 * protection is in place from the first login after a restart.
 */
public final class NetworkData {

   /** What the feed knows about one address. */
   public record Network(boolean endUser, boolean hosting, boolean noUsers, String country, long asn) {

      public String asnName() {
         return "AS" + asn;
      }
   }

   private static final int MAX_BYTES = 64 * 1024 * 1024;

   private static final class Table {
      final BigInteger[] starts;
      final BigInteger[] ends;
      final char[] kind;
      final String[] country;
      final long[] asn;

      Table(List<Object[]> rows) {
         int size = rows.size();
         starts = new BigInteger[size];
         ends = new BigInteger[size];
         kind = new char[size];
         country = new String[size];
         asn = new long[size];
         for (int i = 0; i < size; i++) {
            Object[] row = rows.get(i);
            starts[i] = (BigInteger) row[0];
            ends[i] = (BigInteger) row[1];
            kind[i] = (char) row[2];
            country[i] = (String) row[3];
            asn[i] = (long) row[4];
         }
      }

      Network find(BigInteger value) {
         int index = Arrays.binarySearch(starts, value);
         if (index < 0) {
            index = -index - 2;
         }
         if (index < 0 || ends[index].compareTo(value) < 0) {
            return null;
         }
         return new Network(kind[index] == 'E', kind[index] == 'H', kind[index] == 'N', country[index],
               asn[index]);
      }
   }

   private static final Table EMPTY = new Table(List.of());

   private final Platform platform;
   private final Path cacheFile;
   private final Path etagFile;

   private volatile Table v4 = EMPTY;
   private volatile Table v6 = EMPTY;
   private volatile long lastRefreshMillis;

   public NetworkData(Platform platform) {
      this.platform = platform;
      Path directory = platform.dataFolder().resolve("cache");
      this.cacheFile = directory.resolve("network-feed.tsv.gz");
      this.etagFile = directory.resolve("network-feed.etag");
   }

   /** The network an address is in, or {@code null} when the feed does not know it. */
   public Network classify(String ip) {
      byte[] address = IpAddresses.parseLiteral(ip);
      if (address == null) {
         return null;
      }
      BigInteger value = new BigInteger(1, address);
      return (address.length == 4 ? v4 : v6).find(value);
   }

   public boolean loaded() {
      return v4 != EMPTY || v6 != EMPTY;
   }

   public int rangeCount() {
      return v4.starts.length + v6.starts.length;
   }

   public long lastRefreshMillis() {
      return lastRefreshMillis;
   }

   /** Reads the copy on disk, if there is one. */
   public void loadFromDisk() {
      loadFromDisk(true);
   }

   public void loadFromDisk(boolean announce) {
      if (!Files.isRegularFile(cacheFile)) {
         return;
      }
      try (InputStream in = Files.newInputStream(cacheFile)) {
         parse(in);
         if (announce) {
            platform.info("Loaded " + rangeCount() + " network ranges from the cached feed.");
         }
      } catch (IOException | RuntimeException failed) {
         platform.warn("Could not read the cached network feed: " + failed.getMessage());
      }
   }

   /**
    * Downloads the feed when it changed and swaps it in. Blocking, so call it off the main
    * thread. Returns whether data is available afterwards.
    */
   public boolean refresh(String source, int timeoutSeconds) {
      if (source == null || source.isBlank()) {
         return loaded();
      }
      try {
         HttpURLConnection connection = (HttpURLConnection) URI.create(source).toURL().openConnection();
         connection.setConnectTimeout(timeoutSeconds * 1000);
         connection.setReadTimeout(timeoutSeconds * 1000);
         connection.setRequestProperty("User-Agent", "ProxyShield");
         if (Files.isRegularFile(cacheFile) && Files.isRegularFile(etagFile)) {
            connection.setRequestProperty("If-None-Match", Files.readString(etagFile).trim());
         }
         int status = connection.getResponseCode();
         if (status == HttpURLConnection.HTTP_NOT_MODIFIED && loaded()) {
            lastRefreshMillis = System.currentTimeMillis();
            return true;
         }
         if (status != HttpURLConnection.HTTP_OK) {
            platform.warn("The network feed answered " + status + ": " + source);
            return loaded();
         }
         Files.createDirectories(cacheFile.getParent());
         Path partial = cacheFile.resolveSibling(cacheFile.getFileName() + ".part");
         try (InputStream in = connection.getInputStream()) {
            Files.copy(in, partial, StandardCopyOption.REPLACE_EXISTING);
         }
         try (InputStream in = Files.newInputStream(partial)) {
            parse(in);
         }
         Files.move(partial, cacheFile, StandardCopyOption.REPLACE_EXISTING);
         String etag = connection.getHeaderField("ETag");
         if (etag != null) {
            Files.writeString(etagFile, etag);
         }
         lastRefreshMillis = System.currentTimeMillis();
         platform.info("Network feed ready: " + rangeCount() + " ranges.");
         return true;
      } catch (IOException | RuntimeException failed) {
         platform.warn("Could not load the network feed from " + source + ": " + failed.getMessage());
         return loaded();
      }
   }

   private void parse(InputStream raw) throws IOException {
      List<Object[]> four = new ArrayList<>();
      List<Object[]> six = new ArrayList<>();
      java.util.Map<String, String> countries = new java.util.HashMap<>();
      long bytes = 0;
      try (BufferedReader reader = new BufferedReader(
            new InputStreamReader(new GZIPInputStream(raw), StandardCharsets.UTF_8))) {
         String line;
         while ((line = reader.readLine()) != null) {
            bytes += line.length() + 1;
            if (bytes > MAX_BYTES) {
               throw new IOException("feed is larger than " + MAX_BYTES + " bytes");
            }
            if (line.isEmpty() || line.charAt(0) == '#') {
               continue;
            }
            // Ohne split und Regex, das spart beim Start viel Zeit
            int t0 = line.indexOf('\t');
            int t1 = t0 < 0 ? -1 : line.indexOf('\t', t0 + 1);
            int t2 = t1 < 0 ? -1 : line.indexOf('\t', t1 + 1);
            int t3 = t2 < 0 ? -1 : line.indexOf('\t', t2 + 1);
            int t4 = t3 < 0 ? -1 : line.indexOf('\t', t3 + 1);
            if (t4 < 0 || t2 == t1 + 1) {
               continue;
            }
            int t5 = line.indexOf('\t', t4 + 1);
            String family = line.substring(t4 + 1, t5 < 0 ? line.length() : t5);
            String countryCode = countries.computeIfAbsent(line.substring(t2 + 1, t3), k -> k);
            Object[] row = {number(line, 0, t0), number(line, t0 + 1, t1), line.charAt(t1 + 1),
                  countryCode, Long.parseLong(line, t3 + 1, t4, 10)};
            ("6".equals(family) ? six : four).add(row);
         }
      }
      Table fresh4 = sorted(four);
      Table fresh6 = sorted(six);
      v4 = fresh4;
      v6 = fresh6;
   }

   private static BigInteger number(String line, int from, int to) {
      if (to - from <= 18) {
         return BigInteger.valueOf(Long.parseLong(line, from, to, 10));
      }
      return new BigInteger(line.substring(from, to));
   }

   private static Table sorted(List<Object[]> rows) {
      boolean ordered = true;
      for (int i = 1; i < rows.size() && ordered; i++) {
         ordered = ((BigInteger) rows.get(i - 1)[0]).compareTo((BigInteger) rows.get(i)[0]) <= 0;
      }
      if (!ordered) rows.sort((a, b) -> ((BigInteger) a[0]).compareTo((BigInteger) b[0]));
      return new Table(rows);
   }
}
