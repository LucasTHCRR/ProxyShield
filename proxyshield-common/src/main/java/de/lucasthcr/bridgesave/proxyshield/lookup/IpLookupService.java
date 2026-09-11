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
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Queries one IP intelligence endpoint described by a {@link ProviderDefinition}.
 * <p>
 * Caching and combination live in {@link FailoverLookupService}, which owns the set of these.
 * Everything provider-specific - where the flags sit in the response, whether the key goes in the
 * URL or a header, whether the body is JSON at all - comes from the definition, so adding a service
 * is a catalog entry rather than a parser branch.
 */
public final class IpLookupService implements LookupProvider {

   private static final String USER_AGENT = "ProxyShield/2.2";

   /** Consecutive failures before the endpoint is skipped for a while. */
   private static final int BREAKER_THRESHOLD = 5;

   /** How long a tripped endpoint stays skipped. */
   private static final long BREAKER_COOLDOWN_MILLIS = 120_000L;

   /** Redirects to follow before giving up, enough for a http-to-https hop and a path move. */
   private static final int MAX_REDIRECTS = 3;

   private final Platform platform;
   private final ProviderDefinition definition;
   private final int timeoutMillis;
   private final TokenBucket limiter;

   private final AtomicLong rateLimited = new AtomicLong();
   private final AtomicLong queries = new AtomicLong();
   private final AtomicLong failures = new AtomicLong();
   private final AtomicLong consecutiveFailures = new AtomicLong();
   private final AtomicLong breakerOpenUntil = new AtomicLong();
   private final AtomicLong totalLatencyMillis = new AtomicLong();

   public IpLookupService(Platform platform, ShieldConfig config, ProviderDefinition definition) {
      this.platform = platform;
      this.definition = definition;
      this.timeoutMillis = config.apiTimeoutSeconds() * 1000;
      this.limiter = new TokenBucket(definition.rateLimitPerMinute());
   }

   /** Convenience for a bare URL template, kept so an existing config keeps working. */
   public IpLookupService(Platform platform, ShieldConfig config, String urlTemplate) {
      this(platform, config, ProviderDefinition.generic(urlTemplate)
            .withRateLimit(config.apiRateLimitPerMinute()));
   }

   public ProviderDefinition definition() {
      return definition;
   }

   public String id() {
      return definition.id();
   }

   /** Host portion of the endpoint, for log lines and {@code /proxyshield info}. */
   public String host() {
      return definition.host();
   }

   public double weight() {
      return definition.weight();
   }

   /**
    * Performs a blocking HTTP lookup.
    * <p>
    * Must never be called from the main thread. Failures come back as an unresolved
    * {@link LookupResult} rather than an exception, so the caller can fail over, out-vote it or
    * apply the fail-open policy.
    */
   @Override
   public LookupResult lookup(String ip) {
      if (breakerOpen()) {
         return LookupResult.failed("skipped, endpoint is in cooldown after repeated failures");
      }
      if (!limiter.tryConsume()) {
         rateLimited.incrementAndGet();
         return LookupResult.failed("rate limit reached ("
               + definition.rateLimitPerMinute() + "/min)");
      }

      long started = System.currentTimeMillis();
      LookupResult result = query(ip);
      totalLatencyMillis.addAndGet(System.currentTimeMillis() - started);
      queries.incrementAndGet();

      if (result.resolved()) {
         consecutiveFailures.set(0);
      } else {
         failures.incrementAndGet();
         tripBreakerIfNeeded();
      }
      return result;
   }

   private LookupResult query(String ip) {
      return query(definition.url(ip), ip, 0);
   }

   /**
    * Performs one request, following a redirect by hand where the JDK will not.
    * <p>
    * {@code HttpURLConnection} follows 301 and 302 on its own but ignores 307 and 308 entirely, and
    * it never follows a redirect that changes protocol. A service that moved to HTTPS, or answers
    * {@code 308 Permanent Redirect}, therefore looked like a hard failure and got its provider
    * dropped into the circuit breaker for no reason.
    */
   private LookupResult query(String endpoint, String ip, int hop) {
      HttpURLConnection connection = null;
      try {
         URL url = URI.create(endpoint).toURL();
         connection = (HttpURLConnection) url.openConnection();
         connection.setConnectTimeout(timeoutMillis);
         connection.setReadTimeout(timeoutMillis);
         connection.setRequestProperty("User-Agent", USER_AGENT);
         connection.setRequestProperty("Accept", "application/json");
         if (definition.keyStyle() == ProviderDefinition.KeyStyle.HEADER
               && definition.key() != null) {
            connection.setRequestProperty(definition.keyHeader(), definition.key());
         }

         int status = connection.getResponseCode();
         if (status >= 300 && status < 400) {
            String location = connection.getHeaderField("Location");
            if (location == null || location.isBlank()) {
               return LookupResult.failed("HTTP " + status + " without a Location header");
            }
            if (hop >= MAX_REDIRECTS) {
               return LookupResult.failed("too many redirects");
            }
            return query(URI.create(endpoint).resolve(location).toString(), ip, hop + 1);
         }
         if (status == 429) {
            return LookupResult.failed("provider rate limited us (HTTP 429)");
         }
         if (status == 401 || status == 403) {
            return LookupResult.failed("HTTP " + status + ", check the API key");
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

   /** Reads a response according to the definition. Visible for testing. */
   LookupResult parse(String body, String ip) {
      if (body == null || body.isBlank()) {
         return LookupResult.failed("empty response");
      }
      if (definition.format() == ProviderDefinition.Format.PLAIN) {
         return parsePlain(body);
      }
      return parseJson(body, ip);
   }

   private LookupResult parsePlain(String body) {
      String token = body.trim().toLowerCase(Locale.ROOT);
      // Some of these endpoints answer with a bare word wrapped in HTML or trailing whitespace.
      if (token.length() > 64) {
         token = token.substring(0, 64);
      }
      if (token.startsWith("e") && token.length() == 1) {
         return LookupResult.failed("provider reported an error");
      }

      boolean flagged = definition.trueValues().contains(token);
      if (!flagged && !isKnownNegative(token)) {
         return LookupResult.failed("unrecognised response: " + token);
      }
      return LookupResult.of(flagged, false, false, null, null, null, null, null,
            flagged ? definition.weight() : 0.0,
            flagged ? List.of(definition.id()) : List.of());
   }

   private static boolean isKnownNegative(String token) {
      return token.equals("n") || token.equals("false") || token.equals("no")
            || token.equals("0") || token.equals("clean");
   }

   @SuppressWarnings("unchecked")
   private LookupResult parseJson(String body, String ip) {
      Object root;
      try {
         root = Json.parse(body);
      } catch (Json.JsonException malformed) {
         return LookupResult.failed("malformed response: " + malformed.getMessage());
      }

      if (!(root instanceof Map<?, ?> map) || map.isEmpty()) {
         return LookupResult.failed("empty response");
      }

      // ip-api.com and friends report failures in-band with HTTP 200.
      String status = Json.stringAt(root, "status");
      if (status != null && !"success".equalsIgnoreCase(status) && !"ok".equalsIgnoreCase(status)
            && !"true".equalsIgnoreCase(status)) {
         String message = Json.stringAt(root, "message");
         return LookupResult.failed(message == null ? status : status + ": " + message);
      }
      for (String errorPath : definition.errorPaths()) {
         Object error = Json.path(root, errorPath);
         if (error instanceof String text && !text.isBlank()) {
            return LookupResult.failed(text);
         }
         if (error instanceof Boolean flag && flag) {
            return LookupResult.failed("provider reported an error at " + errorPath);
         }
      }

      // proxycheck.io and services modelled on it nest the data under the queried address
      // instead of returning it flat. Descending into it whenever it is there costs nothing and
      // means an unlisted service of that shape works without being told about the layout.
      Object node = root;
      Object nested = ((Map<String, Object>) map).get(ip);
      if (nested instanceof Map<?, ?>) {
         node = nested;
      }

      boolean proxy = anyTrue(node, definition.proxyPaths());
      boolean hosting = anyTrue(node, definition.hostingPaths());
      boolean tor = anyTrue(node, definition.torPaths());

      Double score = definition.scorePath() == null
            ? null
            : Json.numberAt(node, definition.scorePath());
      if (score != null && score >= definition.scoreThreshold()
            && score <= definition.scoreCeiling()) {
         proxy = true;
      }

      // A provider that answered but exposed none of its documented fields told us nothing; that
      // is a failure, not a clean result, otherwise a changed API silently disables detection.
      if (!proxy && !hosting && !tor && score == null && !describes(node)) {
         return LookupResult.failed("response carried none of the expected fields");
      }

      return LookupResult.of(proxy, hosting, tor,
            firstString(node, definition.countryPaths()),
            firstString(node, definition.countryNamePaths()),
            firstString(node, definition.ispPaths()),
            firstString(node, definition.asnPaths()),
            firstString(node, definition.connectionTypePaths()),
            proxy ? definition.weight() : 0.0,
            proxy || hosting ? List.of(definition.id()) : List.of());
   }

   /** Whether any documented field was present at all, flag or not. */
   private boolean describes(Object node) {
      for (List<String> paths : List.of(definition.proxyPaths(), definition.hostingPaths(),
            definition.torPaths(), definition.countryPaths(), definition.ispPaths(),
            definition.asnPaths(), definition.connectionTypePaths())) {
         for (String path : paths) {
            if (Json.path(node, path) != null) {
               return true;
            }
         }
      }
      return false;
   }

   private static boolean anyTrue(Object node, List<String> paths) {
      for (String path : paths) {
         if (Json.boolAt(node, path)) {
            return true;
         }
      }
      return false;
   }

   private static String firstString(Object node, List<String> paths) {
      for (String path : paths) {
         String value = Json.stringAt(node, path);
         if (value != null && !value.isBlank() && !"null".equalsIgnoreCase(value)) {
            return value;
         }
      }
      return null;
   }

   private boolean breakerOpen() {
      long until = breakerOpenUntil.get();
      if (until == 0L) {
         return false;
      }
      if (System.currentTimeMillis() >= until) {
         // Cooldown elapsed: let one request through and see whether the endpoint recovered.
         breakerOpenUntil.compareAndSet(until, 0L);
         consecutiveFailures.set(0);
         return false;
      }
      return true;
   }

   private void tripBreakerIfNeeded() {
      if (consecutiveFailures.incrementAndGet() < BREAKER_THRESHOLD) {
         return;
      }
      if (breakerOpenUntil.getAndSet(System.currentTimeMillis() + BREAKER_COOLDOWN_MILLIS) == 0L) {
         platform.warn("Lookup provider " + definition.id() + " (" + host() + ") failed "
               + BREAKER_THRESHOLD + " times in a row and is skipped for "
               + (BREAKER_COOLDOWN_MILLIS / 1000L) + "s. Logins are not delayed by it meanwhile.");
      }
   }

   /** Whether the endpoint is currently being skipped, for {@code /proxyshield info}. */
   public boolean tripped() {
      long until = breakerOpenUntil.get();
      return until != 0L && System.currentTimeMillis() < until;
   }

   public long rateLimitedCount() {
      return rateLimited.get();
   }

   public long queryCount() {
      return queries.get();
   }

   public long failureCount() {
      return failures.get();
   }

   /** Mean round trip in milliseconds, or 0 before the first query. */
   public long averageLatencyMillis() {
      long count = queries.get();
      return count == 0L ? 0L : totalLatencyMillis.get() / count;
   }

   /** Warns at startup if this endpoint is plain HTTP. */
   public void warnIfInsecure() {
      if (definition.urlTemplate().startsWith("http://")) {
         platform.warn("Lookup endpoint " + host() + " uses plain HTTP, so results can be tampered "
               + "with in transit. ip-api.com only offers HTTPS on paid plans; enable an HTTPS "
               + "provider under api.providers if that matters to you.");
      }
   }

   /**
    * Refills at the configured rate, so a burst of logins can use budget an idle minute left
    * unspent instead of being cut off at a window boundary.
    * <p>
    * The fixed window it replaces reset its counter and incremented it from separate atomics,
    * which let concurrent logins slip past the limit or lose requests to a reset landing between
    * the two operations.
    */
   static final class TokenBucket {

      private final int capacity;
      private final double tokensPerMilli;
      private final Object lock = new Object();

      private double tokens;
      private long lastRefill = System.currentTimeMillis();

      TokenBucket(int perMinute) {
         this.capacity = Math.max(1, perMinute);
         this.tokensPerMilli = this.capacity / 60_000.0;
         this.tokens = this.capacity;
      }

      boolean tryConsume() {
         synchronized (lock) {
            long now = System.currentTimeMillis();
            tokens = Math.min(capacity, tokens + (now - lastRefill) * tokensPerMilli);
            lastRefill = now;
            if (tokens < 1.0) {
               return false;
            }
            tokens -= 1.0;
            return true;
         }
      }
   }
}
