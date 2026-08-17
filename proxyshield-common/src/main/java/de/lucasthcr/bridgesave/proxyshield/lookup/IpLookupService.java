package de.lucasthcr.bridgesave.proxyshield.lookup;

import de.lucasthcr.bridgesave.proxyshield.cache.ExpiringCache;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.platform.Platform;
import de.lucasthcr.bridgesave.proxyshield.util.Json;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Queries the configured IP intelligence provider, with caching and rate limiting.
 * <p>
 * The default provider is ip-api.com, whose free tier allows 45 requests per minute and answers
 * with a flat JSON object. v1 ignored the rate limit entirely and decided "is this a proxy" by
 * testing whether the raw first line of the response contained the substring {@code "true"}, which
 * also matched a country named e.g. {@code "Truelandia"} and broke as soon as the response spanned
 * more than one line.
 */
public final class IpLookupService implements LookupProvider {

   private static final String USER_AGENT = "ProxyShield/2.0";

   private final Platform platform;
   private final ExpiringCache<String, LookupResult> cache;
   private final int requestsPerMinute;
   private final String urlTemplate;
   private final int timeoutMillis;

   private final AtomicLong windowStart = new AtomicLong(System.currentTimeMillis());
   private final AtomicLong windowCount = new AtomicLong();

   private final AtomicLong lookups = new AtomicLong();
   private final AtomicLong rateLimited = new AtomicLong();
   private final AtomicLong failures = new AtomicLong();

   public IpLookupService(Platform platform, ShieldConfig config) {
      this.platform = platform;
      this.urlTemplate = config.apiUrl();
      this.timeoutMillis = config.apiTimeoutSeconds() * 1000;
      this.requestsPerMinute = config.apiRateLimitPerMinute();
      this.cache = new ExpiringCache<>(config.apiMaxCacheEntries(),
            config.apiCacheMinutes() * 60_000L);
   }

   /** Cached result for this address, if one is still valid. */
   public Optional<LookupResult> cached(String ip) {
      return cache.get(ip);
   }

   /**
    * Returns the cached result or performs a blocking HTTP lookup.
    * <p>
    * Must never be called from the main thread. Failures come back as an unresolved
    * {@link LookupResult} rather than an exception, so the caller can apply the fail-open or
    * fail-closed policy.
    */
   @Override
   public LookupResult lookup(String ip) {
      Optional<LookupResult> hit = cache.get(ip);
      if (hit.isPresent()) {
         return hit.get();
      }

      if (!tryConsumeToken()) {
         rateLimited.incrementAndGet();
         // Deliberately not cached: this says nothing about the address itself.
         return LookupResult.failed("rate limit reached (" + requestsPerMinute + "/min)");
      }

      LookupResult result = query(ip);
      lookups.incrementAndGet();
      if (result.resolved()) {
         cache.put(ip, result);
      } else {
         failures.incrementAndGet();
      }
      return result;
   }

   private LookupResult query(String ip) {
      String endpoint = urlTemplate.replace("{ip}", ip);
      HttpURLConnection connection = null;
      try {
         URL url = URI.create(endpoint).toURL();
         connection = (HttpURLConnection) url.openConnection();
         connection.setConnectTimeout(timeoutMillis);
         connection.setReadTimeout(timeoutMillis);
         connection.setRequestProperty("User-Agent", USER_AGENT);
         connection.setRequestProperty("Accept", "application/json");

         int status = connection.getResponseCode();
         if (status == 429) {
            return LookupResult.failed("provider rate limited us (HTTP 429)");
         }
         if (status < 200 || status >= 300) {
            return LookupResult.failed("HTTP " + status);
         }

         String body = readBody(connection);
         return parse(body);
      } catch (IOException | RuntimeException failure) {
         return LookupResult.failed(failure.getClass().getSimpleName() + ": "
               + failure.getMessage());
      } finally {
         if (connection != null) {
            connection.disconnect();
         }
      }
   }

   private String readBody(HttpURLConnection connection) throws IOException {
      StringBuilder body = new StringBuilder();
      try (InputStream stream = connection.getInputStream();
            BufferedReader reader = new BufferedReader(
                  new InputStreamReader(stream, StandardCharsets.UTF_8))) {
         char[] chunk = new char[1024];
         int read;
         // Cap the response so a misconfigured endpoint cannot exhaust memory.
         while ((read = reader.read(chunk)) > 0 && body.length() < 64 * 1024) {
            body.append(chunk, 0, read);
         }
      }
      return body.toString();
   }

   private LookupResult parse(String body) {
      Map<String, Object> json;
      try {
         json = Json.parseObject(body);
      } catch (Json.JsonException malformed) {
         return LookupResult.failed("malformed response: " + malformed.getMessage());
      }

      if (json.isEmpty()) {
         return LookupResult.failed("empty response");
      }

      // ip-api.com reports failures in-band with HTTP 200.
      String status = Json.stringOf(json, "status");
      if (status != null && !"success".equalsIgnoreCase(status)) {
         String message = Json.stringOf(json, "message");
         return LookupResult.failed(message == null ? status : status + ": " + message);
      }

      boolean proxy = Json.boolOf(json, "proxy");
      boolean hosting = Json.boolOf(json, "hosting");
      // Common alternative field names across providers.
      if (!proxy) {
         proxy = Json.boolOf(json, "vpn") || Json.boolOf(json, "tor") || Json.boolOf(json, "block");
      }
      if (!hosting) {
         hosting = Json.boolOf(json, "datacenter");
      }

      String code = Json.stringOf(json, "countryCode");
      if (code == null) {
         code = Json.stringOf(json, "country_code");
      }

      return LookupResult.of(proxy, hosting, code, Json.stringOf(json, "country"),
            Json.stringOf(json, "isp"));
   }

   /** Fixed-window limiter. Coarse, but exactly matches how the provider counts. */
   private boolean tryConsumeToken() {
      long now = System.currentTimeMillis();
      long start = windowStart.get();
      if (now - start >= 60_000L && windowStart.compareAndSet(start, now)) {
         windowCount.set(0);
      }
      return windowCount.incrementAndGet() <= requestsPerMinute;
   }

   public void invalidate(String ip) {
      cache.invalidate(ip);
   }

   public void clearCache() {
      cache.clear();
   }

   public int purgeExpired() {
      return cache.purgeExpired();
   }

   public int cacheSize() {
      return cache.size();
   }

   public long cacheHits() {
      return cache.hits();
   }

   public long lookups() {
      return lookups.get();
   }

   public long rateLimitedCount() {
      return rateLimited.get();
   }

   public long failureCount() {
      return failures.get();
   }

   /** Warns once at startup if the endpoint is plain HTTP. */
   public void warnIfInsecure() {
      if (urlTemplate.startsWith("http://")) {
         platform.warn("The lookup endpoint uses plain HTTP, so results can be tampered with in "
               + "transit. ip-api.com only offers HTTPS on paid plans; switch api.url to an HTTPS "
               + "provider if that matters to you.");
      }
   }
}
