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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

// Lokale Kopie von PaperStream Intel als MaxMind-DB, beantwortet Adressen ohne Anfrage nach aussen
public final class IntelDatabase {

   public record Hit(boolean vpn, boolean proxy, boolean tor, boolean hosting, String network,
                     String country, long asn, int score, List<String> reasons) {
      public boolean endUser() {
         return "end_user".equals(network);
      }

      public String asnName() {
         return asn > 0 ? "AS" + asn : null;
      }
   }

   private static final byte[] MARKER = marker();
   private static final int MAX_BYTES = 256 * 1024 * 1024;
   // Oeffentlicher Schluessel von intel.paperstream.dev, damit niemand Daten unterschieben kann
   static final String PUBLIC_KEY = "+VaJhOVqyD/USYygb/isK/EQVa8UJ/RmLHcmSMXWSO8=";
   private static final String SNAPSHOT = "intel-snapshot.mmdb.gz";

   private record Db(byte[] buf, int nodes, int recordSize, int ipv4Start, int data, long buildEpoch) {
   }

   private final Platform platform;
   private final Path cacheFile;
   private final Path stampFile;
   private volatile Db db;
   private volatile long lastRefreshMillis;

   public IntelDatabase(Platform platform) {
      this.platform = platform;
      Path directory = platform.dataFolder().resolve("cache");
      this.cacheFile = directory.resolve("intel.mmdb.gz");
      this.stampFile = directory.resolve("intel.mmdb.modified");
   }

   IntelDatabase(byte[] mmdb) throws IOException {
      this.platform = null;
      this.cacheFile = null;
      this.stampFile = null;
      this.db = open(mmdb);
   }

   public boolean loaded() {
      return db != null;
   }

   public int nodeCount() {
      Db current = db;
      return current == null ? 0 : current.nodes;
   }

   public long buildEpoch() {
      Db current = db;
      return current == null ? 0L : current.buildEpoch;
   }

   public boolean stale(int maxAgeHours) {
      long built = buildEpoch();
      return built == 0L || System.currentTimeMillis() / 1000L - built > maxAgeHours * 3600L;
   }

   private void markChecked() {
      lastRefreshMillis = System.currentTimeMillis();
      if (stampFile != null && Files.isRegularFile(stampFile)) {
         try {
            Files.setLastModifiedTime(stampFile, java.nio.file.attribute.FileTime.fromMillis(lastRefreshMillis));
         } catch (IOException ignored) {
            // nur fuer den naechsten Start
         }
      }
   }

   public long lastRefreshMillis() {
      return lastRefreshMillis;
   }

   public boolean due(long intervalMillis) {
      return lastRefreshMillis == 0L || System.currentTimeMillis() - lastRefreshMillis >= intervalMillis;
   }

   public Hit lookup(String ip) {
      Db current = db;
      byte[] address = IpAddresses.parseLiteral(ip);
      if (current == null || address == null) {
         return null;
      }
      int node = address.length == 4 ? current.ipv4Start : 0;
      int bits = address.length * 8;
      for (int i = 0; i < bits && node < current.nodes; i++) {
         int bit = (address[i >> 3] >> (7 - (i & 7))) & 1;
         node = record(current, node, bit);
      }
      if (Integer.compareUnsigned(node, current.nodes) <= 0) {
         return null;
      }
      try {
         Object value = new Decoder(current.buf, current.data)
               .decode(current.data + (node - current.nodes - 16));
         return value instanceof Map<?, ?> map ? toHit(map) : null;
      } catch (RuntimeException broken) {
         return null;
      }
   }

   private static Hit toHit(Map<?, ?> map) {
      List<String> reasons = new ArrayList<>();
      if (map.get("reasons") instanceof List<?> list) {
         for (Object reason : list) {
            reasons.add(String.valueOf(reason));
         }
      }
      return new Hit(bool(map.get("vpn")), bool(map.get("proxy")), bool(map.get("tor")),
            bool(map.get("hosting")), map.get("network") instanceof String s ? s : "unknown",
            map.get("country") instanceof String c ? c : null,
            map.get("asn") instanceof Number n ? n.longValue() : 0L,
            map.get("score") instanceof Number n ? n.intValue() : 0, List.copyOf(reasons));
   }

   private static boolean bool(Object value) {
      return value instanceof Boolean b && b;
   }

   public void loadFromDisk() {
      if (cacheFile == null) {
         return;
      }
      if (!Files.isRegularFile(cacheFile)) {
         loadSnapshot();
         return;
      }
      try {
         db = open(gunzip(Files.newInputStream(cacheFile)));
         // Letzte Pruefung ueberlebt den Neustart, sonst laedt jeder Start neu
         if (stampFile != null && Files.isRegularFile(stampFile)) {
            lastRefreshMillis = Files.getLastModifiedTime(stampFile).toMillis();
         }
         platform.info("Loaded the PaperStream Intel database from cache (" + db.nodes + " nodes).");
      } catch (IOException | RuntimeException failed) {
         platform.warn("Could not read the cached PaperStream Intel database: " + failed.getMessage());
      }
   }

   // Mitgelieferte Kopie aus der JAR, Schutz schon beim allerersten Start
   private void loadSnapshot() {
      try (InputStream in = IntelDatabase.class.getClassLoader().getResourceAsStream(SNAPSHOT)) {
         if (in == null) {
            return;
         }
         db = open(gunzip(in));
         platform.info("Loaded the PaperStream Intel snapshot shipped with the plugin (" + db.nodes + " nodes).");
      } catch (IOException | RuntimeException failed) {
         platform.warn("Could not read the shipped PaperStream Intel snapshot: " + failed.getMessage());
      }
   }

   static boolean verify(byte[] data, String signatureBase64) {
      try {
         byte[] raw = java.util.Base64.getDecoder().decode(PUBLIC_KEY);
         byte[] prefix = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
         byte[] encoded = new byte[prefix.length + raw.length];
         System.arraycopy(prefix, 0, encoded, 0, prefix.length);
         System.arraycopy(raw, 0, encoded, prefix.length, raw.length);
         java.security.PublicKey key = java.security.KeyFactory.getInstance("Ed25519")
               .generatePublic(new java.security.spec.X509EncodedKeySpec(encoded));
         java.security.Signature check = java.security.Signature.getInstance("Ed25519");
         check.initVerify(key);
         check.update(data);
         return check.verify(java.util.Base64.getDecoder().decode(signatureBase64.trim()));
      } catch (java.security.GeneralSecurityException | IllegalArgumentException broken) {
         return false;
      }
   }

   private static String fetchText(String url, int timeoutSeconds) throws IOException {
      HttpURLConnection connection = (HttpURLConnection) URI.create(url).toURL().openConnection();
      connection.setConnectTimeout(timeoutSeconds * 1000);
      connection.setReadTimeout(timeoutSeconds * 1000);
      connection.setInstanceFollowRedirects(false);
      connection.setRequestProperty("User-Agent", "ProxyShield");
      if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
         throw new IOException("signature answered " + connection.getResponseCode());
      }
      try (InputStream in = connection.getInputStream()) {
         return new String(in.readNBytes(4096), StandardCharsets.US_ASCII);
      }
   }

   public boolean refresh(String source, int timeoutSeconds) {
      return refresh(source, timeoutSeconds, true);
   }

   public boolean refresh(String source, int timeoutSeconds, boolean requireSignature) {
      if (source == null || source.isBlank()) {
         return loaded();
      }
      try {
         HttpURLConnection connection = (HttpURLConnection) URI.create(source).toURL().openConnection();
         connection.setConnectTimeout(timeoutSeconds * 1000);
         connection.setReadTimeout(Math.max(timeoutSeconds, 30) * 1000);
         connection.setInstanceFollowRedirects(false);
         connection.setRequestProperty("User-Agent", "ProxyShield");
         if (loaded() && Files.isRegularFile(cacheFile) && Files.isRegularFile(stampFile)) {
            connection.setRequestProperty("If-Modified-Since", Files.readString(stampFile).trim());
         }
         int status = connection.getResponseCode();
         if (status == HttpURLConnection.HTTP_NOT_MODIFIED && loaded()) {
            markChecked();
            return true;
         }
         if (status != HttpURLConnection.HTTP_OK) {
            platform.warn("PaperStream Intel database answered " + status + ".");
            lastRefreshMillis = System.currentTimeMillis();
            return loaded();
         }
         Files.createDirectories(cacheFile.getParent());
         Path partial = cacheFile.resolveSibling(cacheFile.getFileName() + ".part");
         try (InputStream in = connection.getInputStream()) {
            Files.copy(in, partial, StandardCopyOption.REPLACE_EXISTING);
         }
         if (requireSignature) {
            byte[] packed = Files.readAllBytes(partial);
            if (!verify(packed, fetchText(source + ".sig", timeoutSeconds))) {
               Files.deleteIfExists(partial);
               platform.warn("Ignored a PaperStream Intel database whose signature does not match.");
               lastRefreshMillis = System.currentTimeMillis();
               return loaded();
            }
         }
         Db fresh = open(gunzip(Files.newInputStream(partial)));
         Db current = db;
         // Schutz vor halb leeren Dateien: deutlich kleiner als bisher wird nicht uebernommen
         if (current != null && fresh.nodes < current.nodes / 2) {
            Files.deleteIfExists(partial);
            platform.warn("Ignored a PaperStream Intel database that is much smaller than the current one.");
            lastRefreshMillis = System.currentTimeMillis();
            return true;
         }
         Files.move(partial, cacheFile, StandardCopyOption.REPLACE_EXISTING);
         String modified = connection.getHeaderField("Last-Modified");
         if (modified != null) {
            Files.writeString(stampFile, modified);
         }
         db = fresh;
         markChecked();
         platform.info("PaperStream Intel database ready (" + fresh.nodes + " nodes).");
         return true;
      } catch (IOException | RuntimeException failed) {
         platform.warn("Could not load the PaperStream Intel database: " + failed.getMessage());
         lastRefreshMillis = System.currentTimeMillis();
         return loaded();
      }
   }

   private static byte[] gunzip(InputStream raw) throws IOException {
      try (InputStream in = new GZIPInputStream(raw, 1 << 16)) {
         ByteArrayOutputStream out = new ByteArrayOutputStream(1 << 22);
         byte[] chunk = new byte[1 << 16];
         int read;
         while ((read = in.read(chunk)) != -1) {
            out.write(chunk, 0, read);
            if (out.size() > MAX_BYTES) {
               throw new IOException("database larger than " + MAX_BYTES + " bytes");
            }
         }
         return out.toByteArray();
      }
   }

   static Db open(byte[] buf) throws IOException {
      int at = lastIndexOf(buf, MARKER);
      if (at < 0) {
         throw new IOException("not a MaxMind DB file");
      }
      Decoder decoder = new Decoder(buf, at + MARKER.length);
      if (!(decoder.decode(at + MARKER.length) instanceof Map<?, ?> meta)) {
         throw new IOException("metadata missing");
      }
      long nodes = number(meta.get("node_count"));
      int recordSize = (int) number(meta.get("record_size"));
      if (recordSize != 24 && recordSize != 28 && recordSize != 32) {
         throw new IOException("record size " + recordSize + " not supported");
      }
      long data = nodes * recordSize / 4 + 16;
      if (nodes <= 0 || data > buf.length) {
         throw new IOException("search tree larger than the file");
      }
      Db partial = new Db(buf, (int) nodes, recordSize, 0, (int) data, number(meta.get("build_epoch")));
      int ipv4Start = 0;
      if (number(meta.get("ip_version")) == 6) {
         for (int i = 0; i < 96 && ipv4Start < nodes; i++) {
            ipv4Start = record(partial, ipv4Start, 0);
         }
      }
      return new Db(buf, (int) nodes, recordSize, ipv4Start, (int) data, partial.buildEpoch);
   }

   private static byte[] marker() {
      byte[] text = "MaxMind.com".getBytes(StandardCharsets.US_ASCII);
      byte[] out = new byte[text.length + 3];
      out[0] = (byte) 0xAB;
      out[1] = (byte) 0xCD;
      out[2] = (byte) 0xEF;
      System.arraycopy(text, 0, out, 3, text.length);
      return out;
   }

   private static long number(Object value) {
      return value instanceof Number n ? n.longValue() : -1L;
   }

   private static int lastIndexOf(byte[] buf, byte[] needle) {
      int stop = Math.max(0, buf.length - 128 * 1024);
      outer:
      for (int i = buf.length - needle.length; i >= stop; i--) {
         for (int j = 0; j < needle.length; j++) {
            if (buf[i + j] != needle[j]) {
               continue outer;
            }
         }
         return i;
      }
      return -1;
   }

   private static int record(Db db, int node, int bit) {
      byte[] b = db.buf;
      switch (db.recordSize) {
         case 32 -> {
            int at = node * 8 + bit * 4;
            return (b[at] & 0xFF) << 24 | (b[at + 1] & 0xFF) << 16 | (b[at + 2] & 0xFF) << 8 | (b[at + 3] & 0xFF);
         }
         case 24 -> {
            int at = node * 6 + bit * 3;
            return (b[at] & 0xFF) << 16 | (b[at + 1] & 0xFF) << 8 | (b[at + 2] & 0xFF);
         }
         default -> {
            int at = node * 7;
            if (bit == 0) {
               return (b[at + 3] & 0xF0) << 20 | (b[at] & 0xFF) << 16 | (b[at + 1] & 0xFF) << 8 | (b[at + 2] & 0xFF);
            }
            return (b[at + 3] & 0x0F) << 24 | (b[at + 4] & 0xFF) << 16 | (b[at + 5] & 0xFF) << 8 | (b[at + 6] & 0xFF);
         }
      }
   }

   private static final class Decoder {
      private final byte[] buf;
      private final int base;
      private int pos;

      Decoder(byte[] buf, int base) {
         this.buf = buf;
         this.base = base;
      }

      Object decode(int offset) {
         pos = offset;
         return next(0);
      }

      private long be(int n) {
         long value = 0;
         for (int i = 0; i < n; i++) {
            value = value << 8 | (buf[pos++] & 0xFF);
         }
         return value;
      }

      private Object next(int depth) {
         if (depth > 32) {
            throw new IllegalStateException("data nested too deep");
         }
         int ctrl = buf[pos++] & 0xFF;
         int type = ctrl >>> 5;
         if (type == 1) {
            int ss = (ctrl >>> 3) & 3;
            long vvv = ctrl & 7;
            long pointer = switch (ss) {
               case 0 -> vvv << 8 | be(1);
               case 1 -> (vvv << 16 | be(2)) + 2048;
               case 2 -> (vvv << 24 | be(3)) + 526_336;
               default -> be(4);
            };
            int back = pos;
            pos = (int) (base + pointer);
            Object value = next(depth + 1);
            pos = back;
            return value;
         }
         if (type == 0) {
            type = 7 + (buf[pos++] & 0xFF);
         }
         int size = ctrl & 0x1F;
         if (size == 29) {
            size = 29 + (int) be(1);
         } else if (size == 30) {
            size = 285 + (int) be(2);
         } else if (size == 31) {
            size = 65_821 + (int) be(3);
         }
         switch (type) {
            case 2 -> {
               String text = new String(buf, pos, size, StandardCharsets.UTF_8);
               pos += size;
               return text;
            }
            case 3 -> {
               return Double.longBitsToDouble(be(8));
            }
            case 5, 6, 8, 9, 10 -> {
               return be(Math.min(size, 8));
            }
            case 14 -> {
               return size != 0;
            }
            case 7 -> {
               Map<String, Object> map = new LinkedHashMap<>();
               for (int i = 0; i < size; i++) {
                  String key = String.valueOf(next(depth + 1));
                  map.put(key, next(depth + 1));
               }
               return map;
            }
            case 11 -> {
               List<Object> list = new ArrayList<>(size);
               for (int i = 0; i < size; i++) {
                  list.add(next(depth + 1));
               }
               return list;
            }
            default -> throw new IllegalStateException("unsupported data type " + type);
         }
      }
   }
}
