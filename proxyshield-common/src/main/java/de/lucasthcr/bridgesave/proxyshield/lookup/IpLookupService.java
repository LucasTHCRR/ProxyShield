package de.lucasthcr.bridgesave.proxyshield.lookup;

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
import java.util.concurrent.atomic.AtomicLong;

/**
 * Queries one IP intelligence endpoint, with its own rate limiter.
 * <p>
 * Caching lives in {@link FailoverLookupService}, which owns the chain of these. Responses are
 * parsed as JSON: v1 decided "is this a proxy" by testing whether the raw first line contained the
 * substring {@code "true"}, which an ISP or country name could satisfy on its own and which broke
 * outright once a response spanned more than one line.
 */
public final class IpLookupService implements LookupProvider {

   private static final String USER_AGENT = "ProxyShield/2.1";

   private final Platform platform;
   private final String urlTemplate;
   private final int timeoutMillis;
   private final int requestsPerMinute;

   private final AtomicLong windowStart = new AtomicLong(System.currentTimeMillis());
   private final AtomicLong windowCount = new AtomicLong();
   private final AtomicLong rateLimited = new AtomicLong();

   public IpLookupService(Platform platform, ShieldConfig config, String urlTemplate) {
      this.platform = platform;
      this.urlTemplate = urlTemplate;
      this.timeoutMillis = config.apiTimeoutSeconds() * 1000;
      this.requestsPerMinute = config.apiRateLimitPerMinute();
   }

   /** Host portion of the endpoint, for log lines and {@code /proxyshield info}. */
   public String host() {
      try {
         String host = URI.create(urlTemplate.replace("{ip}", "0.0.0.0")).getHost();
         return host == null ? urlTemplate : host;
      } catch (RuntimeException malformed) {
         return urlTemplate;
      }
   }

   /**
    * Performs a blocking HTTP lookup.
    * <p>
    * Must never be called from the main thread. Failures come back as an unresolved
    * {@link LookupResult} rather than an exception, so the caller can fail over or apply the
    * fail-open policy.
    */
   @Override
   public LookupResult lookup(String ip) {
      if (!tryConsumeToken()) {
         rateLimited.incrementAndGet();
         return LookupResult.failed("rate limit reached (" + requestsPerMinute + "/min)");
      }
      return query(ip);
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

         return parse(readBody(connection), ip);
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

   /** Understands the shapes the common free providers return. */
   @SuppressWarnings("unchecked")
   LookupResult parse(String body, String ip) {
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
      if (status != null && !"success".equalsIgnoreCase(status) && !"ok".equalsIgnoreCase(status)) {
         String message = Json.stringOf(json, "message");
         return LookupResult.failed(message == null ? status : status + ": " + message);
      }

      // proxycheck.io nests the data under the queried address instead of returning it flat.
      Object nested = json.get(ip);
      if (nested instanceof Map<?, ?> perAddress) {
         json = (Map<String, Object>) perAddress;
      }

      boolean proxy = Json.boolOf(json, "proxy")
            || Json.boolOf(json, "vpn")
            || Json.boolOf(json, "tor")
            || Json.boolOf(json, "block");
      boolean hosting = Json.boolOf(json, "hosting") || Json.boolOf(json, "datacenter");

      String code = Json.stringOf(json, "countryCode");
      if (code == null) {
         code = Json.stringOf(json, "country_code");
      }
      if (code == null) {
         code = Json.stringOf(json, "isocode");
      }

      String isp = Json.stringOf(json, "isp");
      if (isp == null) {
         isp = Json.stringOf(json, "provider");
      }
      if (isp == null) {
         isp = Json.stringOf(json, "organisation");
      }

      return LookupResult.of(proxy, hosting, code, Json.stringOf(json, "country"), isp);
   }

   /** Fixed-window limiter. Coarse, but exactly matches how the providers count. */
   private boolean tryConsumeToken() {
      long now = System.currentTimeMillis();
      long start = windowStart.get();
      if (now - start >= 60_000L && windowStart.compareAndSet(start, now)) {
         windowCount.set(0);
      }
      return windowCount.incrementAndGet() <= requestsPerMinute;
   }

   public long rateLimitedCount() {
      return rateLimited.get();
   }

   /** Warns at startup if this endpoint is plain HTTP. */
   public void warnIfInsecure() {
      if (urlTemplate.startsWith("http://")) {
         platform.warn("Lookup endpoint " + host() + " uses plain HTTP, so results can be tampered "
               + "with in transit. ip-api.com only offers HTTPS on paid plans; add an HTTPS "
               + "provider under api.providers if that matters to you.");
      }
   }
}
