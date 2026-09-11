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

import de.lucasthcr.bridgesave.proxyshield.net.IpRangeSet;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.GZIPInputStream;

/**
 * Downloads the configured VPN/proxy IP feeds and compiles them into one searchable
 * {@link IpRangeSet}.
 * <p>
 * Feeds are usually hosted on raw.githubusercontent.com, which rate limits per client address and
 * answers {@code 429} once a host has asked too often. A Minecraft server typically runs several
 * plugins that poll GitHub, so hitting that limit at startup is normal rather than exceptional.
 * Three things keep it from costing protection: requests are spaced out and retried with the
 * server's own {@code Retry-After} delay, a stored {@code ETag} turns an unchanged feed into a
 * cheap {@code 304}, and every successful download is mirrored to disk so a restart during an
 * outage still comes up protected.
 */
public final class ListManager {

   private static final String USER_AGENT = "ProxyShield/2.2 (+https://modrinth.com)";

   /**
    * How hard to try, and how long to wait between attempts.
    *
    * @param maxAttempts          attempts per source before giving up on it
    * @param baseBackoffMillis    fallback wait when the server rate limits without saying how long
    * @param maxBackoffMillis     ceiling for one retry, however large Retry-After is
    * @param betweenSourcesMillis gap between sources, so feeds on one host are spread out
    */
   public record RetryPolicy(int maxAttempts, long baseBackoffMillis, long maxBackoffMillis,
         long betweenSourcesMillis) {

      public static final RetryPolicy DEFAULT = new RetryPolicy(3, 3_000L, 30_000L, 750L);
   }

   private final RetryPolicy retryPolicy;
   private final Platform platform;
   private final Path cacheDirectory;
   private final AtomicBoolean refreshing = new AtomicBoolean();

   private volatile IpRangeSet ranges = IpRangeSet.EMPTY;
   private volatile long lastRefreshMillis;
   private volatile String lastError;
   private volatile int lastSourceCount;
   private volatile int lastFailedSourceCount;

   public ListManager(Platform platform) {
      this(platform, RetryPolicy.DEFAULT);
   }

   public ListManager(Platform platform, RetryPolicy retryPolicy) {
      this.platform = platform;
      this.retryPolicy = retryPolicy;
      this.cacheDirectory = platform.dataFolder().resolve("cache");
   }

   public boolean matches(String ip) {
      return ranges.contains(ip);
   }

   public IpRangeSet ranges() {
      return ranges;
   }

   public long lastRefreshMillis() {
      return lastRefreshMillis;
   }

   public String lastError() {
      return lastError;
   }

   public int sourceCount() {
      return lastSourceCount;
   }

   public int failedSourceCount() {
      return lastFailedSourceCount;
   }

   public boolean isRefreshing() {
      return refreshing.get();
   }

   /** Loads whatever is already cached on disk, so startup is protected before the first download. */
   public void loadFromDisk(List<String> sources) {
      if (sources.isEmpty()) {
         return;
      }

      IpRangeSet.Builder builder = IpRangeSet.builder();
      int restored = 0;
      for (String source : sources) {
         Path file = cacheFileFor(source);
         if (!Files.isRegularFile(file)) {
            continue;
         }
         try {
            readInto(file, builder);
            restored++;
         } catch (IOException unreadable) {
            platform.warn("Could not read cached list " + file.getFileName() + ": "
                  + unreadable.getMessage());
         }
      }

      if (restored > 0) {
         ranges = builder.build();
         platform.info("Restored " + ranges.rangeCount() + " ranges from " + restored
               + " cached list(s) while waiting for a fresh download.");
      }
   }

   /**
    * Re-downloads every source and swaps in the result.
    * <p>
    * Concurrent calls are ignored; the caller gets {@code false}. Must not be run on the main
    * thread.
    */
   public boolean refresh(List<String> sources, int timeoutSeconds, boolean writeDiskCache) {
      if (!refreshing.compareAndSet(false, true)) {
         return false;
      }

      try {
         if (sources.isEmpty()) {
            ranges = IpRangeSet.EMPTY;
            lastSourceCount = 0;
            lastFailedSourceCount = 0;
            lastError = null;
            lastRefreshMillis = System.currentTimeMillis();
            return true;
         }

         IpRangeSet.Builder builder = IpRangeSet.builder();
         List<String> failures = new ArrayList<>();
         int succeeded = 0;
         boolean rateLimited = false;

         for (int i = 0; i < sources.size(); i++) {
            if (i > 0) {
               pause(retryPolicy.betweenSourcesMillis());
            }

            String source = sources.get(i);
            try {
               Fetched result = fetch(source, timeoutSeconds, writeDiskCache, builder);
               succeeded++;
               platform.info("Loaded " + result.entries() + " entries from " + source
                     + (result.fromCache() ? " (unchanged, used the cached copy)" : ""));
            } catch (RateLimitedException limited) {
               rateLimited = true;
               failures.add(source + " (rate limited)");
               platform.warn("Rate limited by " + hostOf(source)
                     + " after " + retryPolicy.maxAttempts() + " attempts: " + source);
            } catch (Exception failed) {
               failures.add(source + " (" + failed.getClass().getSimpleName() + ": "
                     + failed.getMessage() + ")");
               platform.warn("Failed to load list " + source + ": " + failed.getMessage());
            }
         }

         lastSourceCount = sources.size();
         lastFailedSourceCount = failures.size();
         lastError = failures.isEmpty() ? null : String.join("; ", failures);

         if (succeeded == 0) {
            reportTotalFailure(rateLimited);
            return false;
         }

         IpRangeSet built = builder.build();
         ranges = built;
         lastRefreshMillis = System.currentTimeMillis();
         platform.info("VPN lists ready: " + built.entryCount() + " entries compiled into "
               + built.rangeCount() + " ranges covering " + built.addressCount() + " addresses.");
         return true;
      } finally {
         refreshing.set(false);
      }
   }

   /** Says plainly whether the server currently has list protection, and what to do about it. */
   private void reportTotalFailure(boolean rateLimited) {
      if (ranges.rangeCount() > 0) {
         platform.warn("No list source could be downloaded, keeping the previous "
               + ranges.rangeCount() + " ranges.");
      } else {
         platform.warn("No list source could be downloaded and nothing is cached yet, so list "
               + "based detection is currently INACTIVE. The provider lookup under 'api' still "
               + "works. The next attempt runs automatically, or use /proxyshield refresh.");
      }

      if (rateLimited) {
         platform.warn("A 429 from the feed host usually means this address asked too often, "
               + "often because several plugins poll GitHub at startup. It normally clears within "
               + "a few minutes and the cached copy is reused once one download succeeds.");
      }
   }

   /** Downloads one source, retrying on a rate limit or a transient server error. */
   private Fetched fetch(String source, int timeoutSeconds, boolean writeDiskCache,
         IpRangeSet.Builder builder) throws IOException, RateLimitedException {
      IOException lastFailure = null;

      for (int attempt = 1; attempt <= retryPolicy.maxAttempts(); attempt++) {
         HttpURLConnection http = null;
         try {
            URLConnection connection = open(source, timeoutSeconds, writeDiskCache);
            if (connection instanceof HttpURLConnection typed) {
               http = typed;
               int status = typed.getResponseCode();

               if (status == HttpURLConnection.HTTP_NOT_MODIFIED) {
                  Path cached = cacheFileFor(source);
                  if (Files.isRegularFile(cached)) {
                     return new Fetched(readInto(cached, builder), true);
                  }
                  // The server says unchanged but our copy is gone; ask again without the ETag.
                  deleteQuietly(etagFileFor(source));
                  throw new IOException("cached copy missing after HTTP 304");
               }

               if (isRetryable(status)) {
                  if (attempt == retryPolicy.maxAttempts()) {
                     throw new RateLimitedException();
                  }
                  long wait = retryAfterMillis(typed, attempt);
                  platform.info("Feed host answered HTTP " + status + " for " + source
                        + ", retrying in " + (wait / 1000) + "s (attempt " + attempt + "/"
                        + retryPolicy.maxAttempts() + ")");
                  typed.disconnect();
                  http = null;
                  pause(wait);
                  continue;
               }

               if (status < 200 || status >= 300) {
                  throw new IOException("HTTP " + status);
               }
            }

            return new Fetched(readBody(source, connection, writeDiskCache, builder), false);
         } catch (IOException failure) {
            lastFailure = failure;
            if (attempt == retryPolicy.maxAttempts()) {
               throw failure;
            }
            pause(retryPolicy.baseBackoffMillis() * attempt);
         } finally {
            if (http != null) {
               http.disconnect();
            }
         }
      }

      throw lastFailure == null ? new IOException("no attempt succeeded") : lastFailure;
   }

   private URLConnection open(String source, int timeoutSeconds, boolean useEtag)
         throws IOException {
      URL url = URI.create(source).toURL();
      URLConnection connection = url.openConnection();
      connection.setConnectTimeout(timeoutSeconds * 1000);
      connection.setReadTimeout(timeoutSeconds * 1000);
      connection.setRequestProperty("User-Agent", USER_AGENT);
      connection.setRequestProperty("Accept-Encoding", "gzip");

      if (connection instanceof HttpURLConnection http) {
         http.setInstanceFollowRedirects(true);
      }

      // A conditional request turns an unchanged feed into a small 304, which is much less
      // likely to run into a rate limit than re-downloading several megabytes.
      if (useEtag && Files.isRegularFile(cacheFileFor(source))) {
         String etag = readEtag(source);
         if (etag != null) {
            connection.setRequestProperty("If-None-Match", etag);
         }
      }
      return connection;
   }

   private static boolean isRetryable(int status) {
      return status == 429 || status == 500 || status == 502 || status == 503 || status == 504;
   }

   private long retryAfterMillis(HttpURLConnection connection, int attempt) {
      String header = connection.getHeaderField("Retry-After");
      if (header != null && !header.isBlank()) {
         try {
            return Math.min(retryPolicy.maxBackoffMillis(),
                  Long.parseLong(header.trim()) * 1000L + 250L);
         } catch (NumberFormatException notSeconds) {
            // Retry-After may also be an HTTP date; the exponential fallback is good enough.
         }
      }
      return Math.min(retryPolicy.maxBackoffMillis(), retryPolicy.baseBackoffMillis() * attempt);
   }

   /** Streams the response into the builder and, when asked, into the on-disk mirror. */
   private int readBody(String source, URLConnection connection, boolean writeDiskCache,
         IpRangeSet.Builder builder) throws IOException {
      Path target = writeDiskCache ? cacheFileFor(source) : null;
      Path temp = null;
      if (target != null) {
         Files.createDirectories(cacheDirectory);
         temp = Files.createTempFile(cacheDirectory, "list-", ".tmp");
      }

      int accepted = 0;
      try (InputStream raw = connection.getInputStream();
            InputStream decoded = "gzip".equalsIgnoreCase(connection.getContentEncoding())
                  ? new GZIPInputStream(raw)
                  : raw;
            BufferedReader reader = new BufferedReader(
                  new InputStreamReader(decoded, StandardCharsets.UTF_8))) {

         List<String> buffer = temp == null ? null : new ArrayList<>();
         String line;
         while ((line = reader.readLine()) != null) {
            if (builder.add(line)) {
               accepted++;
               if (buffer != null) {
                  buffer.add(line.trim());
               }
            }
         }

         if (temp != null) {
            Files.write(temp, buffer, StandardCharsets.UTF_8);
         }
      } catch (IOException | RuntimeException failure) {
         deleteQuietly(temp);
         throw failure;
      }

      if (temp != null) {
         Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
         storeEtag(source, connection.getHeaderField("ETag"));
      }
      return accepted;
   }

   private int readInto(Path file, IpRangeSet.Builder builder) throws IOException {
      int accepted = 0;
      try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
         String line;
         while ((line = reader.readLine()) != null) {
            if (builder.add(line)) {
               accepted++;
            }
         }
      }
      return accepted;
   }

   private String readEtag(String source) {
      Path file = etagFileFor(source);
      if (!Files.isRegularFile(file)) {
         return null;
      }
      try {
         String etag = Files.readString(file, StandardCharsets.UTF_8).trim();
         return etag.isEmpty() ? null : etag;
      } catch (IOException unreadable) {
         return null;
      }
   }

   private void storeEtag(String source, String etag) {
      Path file = etagFileFor(source);
      try {
         if (etag == null || etag.isBlank()) {
            Files.deleteIfExists(file);
            return;
         }
         Files.writeString(file, etag.trim(), StandardCharsets.UTF_8);
      } catch (IOException failure) {
         // Losing the ETag only costs a full download next time, so this is not worth reporting.
      }
   }

   private void pause(long millis) {
      if (millis <= 0) {
         return;
      }
      try {
         Thread.sleep(millis);
      } catch (InterruptedException interrupted) {
         Thread.currentThread().interrupt();
      }
   }

   private void deleteQuietly(Path path) {
      if (path == null) {
         return;
      }
      try {
         Files.deleteIfExists(path);
      } catch (IOException ignored) {
         // nothing useful to do about a leftover temp file
      }
   }

   private static String hostOf(String source) {
      try {
         return URI.create(source).getHost();
      } catch (RuntimeException malformed) {
         return "the feed host";
      }
   }

   /** Stable, filesystem safe name derived from the source URL. */
   private Path cacheFileFor(String source) {
      return cacheDirectory.resolve(baseNameFor(source) + ".list");
   }

   private Path etagFileFor(String source) {
      return cacheDirectory.resolve(baseNameFor(source) + ".etag");
   }

   private static String baseNameFor(String source) {
      StringBuilder name = new StringBuilder();
      for (int i = 0; i < source.length() && name.length() < 60; i++) {
         char c = source.charAt(i);
         name.append(Character.isLetterOrDigit(c) ? c : '_');
      }
      return name + "-" + Integer.toHexString(source.hashCode());
   }

   private record Fetched(int entries, boolean fromCache) {
   }

   /** The host kept answering 429 or 5xx, so the source was given up on for this round. */
   private static final class RateLimitedException extends Exception {
   }
}
