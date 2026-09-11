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

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Describes one IP intelligence endpoint as data: where to send the request, and where in the
 * answer the interesting flags live.
 * <p>
 * v2.1 had a single generic parser that guessed at field names, which meant a provider nesting its
 * verdict under {@code security.vpn} or reporting a probability as the string {@code "0.99"} was
 * silently read as "clean" - a false negative, the one failure mode an anti-VPN must not have. A
 * definition removes the guessing: every supported service states its own paths, and an operator
 * can describe an unlisted one in config.yml without touching code.
 */
public final class ProviderDefinition {

   /** How the body is shaped. */
   public enum Format {
      /** A JSON document, read through dotted paths. */
      JSON,
      /** A bare token such as {@code Y} or {@code true}, matched against {@link #trueValues()}. */
      PLAIN
   }

   /** Where the API key goes, for services that need one. */
   public enum KeyStyle {
      /** Substituted into the URL template's {@code {key}} placeholder. */
      URL,
      /** Sent as a request header, e.g. {@code X-Key} for iphub.info. */
      HEADER
   }

   private final String id;
   private final String urlTemplate;
   private final Format format;
   private final KeyStyle keyStyle;
   private final String keyHeader;
   private final boolean keyRequired;
   private final double weight;
   private final int rateLimitPerMinute;

   private final List<String> proxyPaths;
   private final List<String> hostingPaths;
   private final List<String> torPaths;
   private final List<String> countryPaths;
   private final List<String> countryNamePaths;
   private final List<String> ispPaths;
   private final List<String> asnPaths;
   private final List<String> connectionTypePaths;
   private final List<String> errorPaths;

   private final String scorePath;
   private final double scoreThreshold;
   private final double scoreCeiling;
   private final Set<String> trueValues;
   private final boolean nestedByIp;

   private final String key;
   private final String contact;

   private ProviderDefinition(Builder builder) {
      this.id = builder.id;
      this.urlTemplate = builder.urlTemplate;
      this.format = builder.format;
      this.keyStyle = builder.keyStyle;
      this.keyHeader = builder.keyHeader;
      this.keyRequired = builder.keyRequired;
      this.weight = builder.weight;
      this.rateLimitPerMinute = builder.rateLimitPerMinute;
      this.proxyPaths = List.copyOf(builder.proxyPaths);
      this.hostingPaths = List.copyOf(builder.hostingPaths);
      this.torPaths = List.copyOf(builder.torPaths);
      this.countryPaths = List.copyOf(builder.countryPaths);
      this.countryNamePaths = List.copyOf(builder.countryNamePaths);
      this.ispPaths = List.copyOf(builder.ispPaths);
      this.asnPaths = List.copyOf(builder.asnPaths);
      this.connectionTypePaths = List.copyOf(builder.connectionTypePaths);
      this.errorPaths = List.copyOf(builder.errorPaths);
      this.scorePath = builder.scorePath;
      this.scoreThreshold = builder.scoreThreshold;
      this.scoreCeiling = builder.scoreCeiling;
      this.trueValues = Set.copyOf(builder.trueValues);
      this.nestedByIp = builder.nestedByIp;
      this.key = builder.key;
      this.contact = builder.contact;
   }

   public static Builder builder(String id, String urlTemplate) {
      return new Builder(id, urlTemplate);
   }

   /**
    * A definition for an endpoint the catalog does not know, kept compatible with the v2.1
    * behaviour so an existing {@code api.providers} URL list keeps working after an update.
    */
   public static ProviderDefinition generic(String urlTemplate) {
      return builder(hostOf(urlTemplate), urlTemplate)
            .proxy("proxy", "vpn", "tor", "block", "isProxy", "is_proxy", "is_vpn",
                  "security.vpn", "security.proxy", "security.tor", "privacy.is_proxy",
                  "privacy.is_vpn", "privacy.is_tor", "risk.is_vpn", "risk.is_proxy",
                  "open_proxy", "data_center")
            .hosting("hosting", "datacenter", "data_center", "is_datacenter",
                  "risk.is_datacenter", "asn.hosting")
            .country("countryCode", "country_code", "isocode", "location.country_code")
            .countryName("country", "location.country")
            .isp("isp", "provider", "organisation", "organization", "asn.organisation")
            .asn("asn", "as", "asn.asn", "connection.asn")
            .build();
   }

   /** Fills in {@code {ip}} and, where the key belongs in the URL, {@code {key}}. */
   public String url(String ip) {
      String resolved = urlTemplate.replace("{ip}", ip);
      if (keyStyle == KeyStyle.URL) {
         resolved = resolved.replace("{key}", key == null ? "" : key);
      }
      if (contact != null) {
         resolved = resolved.replace("{contact}", contact);
      }
      return resolved;
   }

   /** A copy of this definition carrying the operator's credentials. */
   public ProviderDefinition withCredentials(String key, String contact) {
      return toBuilder().key(key).contact(contact).build();
   }

   /** A copy of this definition with the operator's weight applied. */
   public ProviderDefinition withWeight(double weight) {
      return toBuilder().weight(weight).build();
   }

   public ProviderDefinition withRateLimit(int rateLimitPerMinute) {
      return toBuilder().rateLimit(rateLimitPerMinute).build();
   }

   /**
    * Whether this provider can actually be queried.
    * <p>
    * A key-only service without a key answers {@code 401} for every login, so it is dropped at
    * start-up with one warning instead of failing once per connection.
    */
   public boolean usable() {
      if (!keyRequired) {
         return true;
      }
      return key != null && !key.isBlank();
   }

   /** Host portion of the endpoint, for log lines and {@code /proxyshield info}. */
   public String host() {
      return hostOf(urlTemplate);
   }

   private static String hostOf(String template) {
      try {
         String probe = template.replace("{ip}", "0.0.0.0").replace("{key}", "k")
               .replace("{contact}", "a@b.c");
         String host = java.net.URI.create(probe).getHost();
         return host == null ? template : host;
      } catch (RuntimeException malformed) {
         return template;
      }
   }

   public String id() {
      return id;
   }

   public String urlTemplate() {
      return urlTemplate;
   }

   public Format format() {
      return format;
   }

   public KeyStyle keyStyle() {
      return keyStyle;
   }

   public String keyHeader() {
      return keyHeader;
   }

   public boolean keyRequired() {
      return keyRequired;
   }

   public String key() {
      return key;
   }

   public double weight() {
      return weight;
   }

   public int rateLimitPerMinute() {
      return rateLimitPerMinute;
   }

   public List<String> proxyPaths() {
      return proxyPaths;
   }

   public List<String> hostingPaths() {
      return hostingPaths;
   }

   public List<String> torPaths() {
      return torPaths;
   }

   public List<String> countryPaths() {
      return countryPaths;
   }

   public List<String> countryNamePaths() {
      return countryNamePaths;
   }

   public List<String> ispPaths() {
      return ispPaths;
   }

   public List<String> asnPaths() {
      return asnPaths;
   }

   public List<String> connectionTypePaths() {
      return connectionTypePaths;
   }

   public List<String> errorPaths() {
      return errorPaths;
   }

   public String scorePath() {
      return scorePath;
   }

   public double scoreThreshold() {
      return scoreThreshold;
   }

   /**
    * Upper bound of the range that counts as a detection.
    * <p>
    * iphub.info answers 0 residential, 1 non-residential and 2 "unclear". Treating anything at or
    * above 1 as a hit turns its shrug into a kick, so the range has to be closed at the top.
    */
   public double scoreCeiling() {
      return scoreCeiling;
   }

   public Set<String> trueValues() {
      return trueValues;
   }

   public boolean nestedByIp() {
      return nestedByIp;
   }

   public Builder toBuilder() {
      Builder builder = new Builder(id, urlTemplate);
      builder.format = format;
      builder.keyStyle = keyStyle;
      builder.keyHeader = keyHeader;
      builder.keyRequired = keyRequired;
      builder.weight = weight;
      builder.rateLimitPerMinute = rateLimitPerMinute;
      builder.proxyPaths = List.copyOf(proxyPaths);
      builder.hostingPaths = List.copyOf(hostingPaths);
      builder.torPaths = List.copyOf(torPaths);
      builder.countryPaths = List.copyOf(countryPaths);
      builder.countryNamePaths = List.copyOf(countryNamePaths);
      builder.ispPaths = List.copyOf(ispPaths);
      builder.asnPaths = List.copyOf(asnPaths);
      builder.connectionTypePaths = List.copyOf(connectionTypePaths);
      builder.errorPaths = List.copyOf(errorPaths);
      builder.scorePath = scorePath;
      builder.scoreThreshold = scoreThreshold;
      builder.scoreCeiling = scoreCeiling;
      builder.trueValues = Set.copyOf(trueValues);
      builder.nestedByIp = nestedByIp;
      builder.key = key;
      builder.contact = contact;
      return builder;
   }

   @Override
   public String toString() {
      return id + " (" + host() + ")";
   }

   /** Fluent builder; every list defaults to empty, so a definition states only what it needs. */
   public static final class Builder {

      private final String id;
      private final String urlTemplate;

      private Format format = Format.JSON;
      private KeyStyle keyStyle = KeyStyle.URL;
      private String keyHeader;
      private boolean keyRequired;
      private double weight = 1.0;
      private int rateLimitPerMinute = 45;

      private List<String> proxyPaths = List.of();
      private List<String> hostingPaths = List.of();
      private List<String> torPaths = List.of();
      private List<String> countryPaths = List.of();
      private List<String> countryNamePaths = List.of();
      private List<String> ispPaths = List.of();
      private List<String> asnPaths = List.of();
      private List<String> connectionTypePaths = List.of();
      private List<String> errorPaths = List.of();

      private String scorePath;
      private double scoreThreshold = 1.0;
      private double scoreCeiling = Double.MAX_VALUE;
      private Set<String> trueValues = Set.of("y", "true", "yes", "1");
      private boolean nestedByIp;

      private String key;
      private String contact;

      private Builder(String id, String urlTemplate) {
         this.id = id.toLowerCase(Locale.ROOT);
         this.urlTemplate = urlTemplate;
      }

      public Builder plain(String... trueValues) {
         this.format = Format.PLAIN;
         if (trueValues.length > 0) {
            this.trueValues = Set.of(lowerCase(trueValues));
         }
         return this;
      }

      public Builder headerKey(String header) {
         this.keyStyle = KeyStyle.HEADER;
         this.keyHeader = header;
         this.keyRequired = true;
         return this;
      }

      public Builder urlKey() {
         this.keyStyle = KeyStyle.URL;
         this.keyRequired = true;
         return this;
      }

      /** A key that improves the limits but is not needed to get an answer. */
      public Builder optionalKey() {
         this.keyStyle = KeyStyle.URL;
         this.keyRequired = false;
         return this;
      }

      public Builder weight(double weight) {
         this.weight = weight;
         return this;
      }

      public Builder rateLimit(int perMinute) {
         this.rateLimitPerMinute = perMinute;
         return this;
      }

      public Builder proxy(String... paths) {
         this.proxyPaths = List.of(paths);
         return this;
      }

      public Builder hosting(String... paths) {
         this.hostingPaths = List.of(paths);
         return this;
      }

      public Builder tor(String... paths) {
         this.torPaths = List.of(paths);
         return this;
      }

      public Builder country(String... paths) {
         this.countryPaths = List.of(paths);
         return this;
      }

      public Builder countryName(String... paths) {
         this.countryNamePaths = List.of(paths);
         return this;
      }

      public Builder isp(String... paths) {
         this.ispPaths = List.of(paths);
         return this;
      }

      public Builder asn(String... paths) {
         this.asnPaths = List.of(paths);
         return this;
      }

      public Builder connectionType(String... paths) {
         this.connectionTypePaths = List.of(paths);
         return this;
      }

      /** Paths that, when truthy or non-empty, mean the provider reported an in-band error. */
      public Builder errors(String... paths) {
         this.errorPaths = List.of(paths);
         return this;
      }

      /** A numeric risk score, treated as a proxy flag once it reaches {@code threshold}. */
      public Builder score(String path, double threshold) {
         this.scorePath = path;
         this.scoreThreshold = threshold;
         return this;
      }

      /** A numeric verdict that only counts inside a closed range, e.g. iphub's block=1. */
      public Builder score(String path, double threshold, double ceiling) {
         this.scorePath = path;
         this.scoreThreshold = threshold;
         this.scoreCeiling = ceiling;
         return this;
      }

      /** proxycheck.io wraps its answer in an object keyed by the address that was queried. */
      public Builder nestedByIp() {
         this.nestedByIp = true;
         return this;
      }

      public Builder key(String key) {
         this.key = key == null || key.isBlank() ? null : key.trim();
         return this;
      }

      public Builder contact(String contact) {
         this.contact = contact == null || contact.isBlank() ? null : contact.trim();
         return this;
      }

      public ProviderDefinition build() {
         return new ProviderDefinition(this);
      }

      private static String[] lowerCase(String[] values) {
         String[] out = new String[values.length];
         for (int i = 0; i < values.length; i++) {
            out[i] = values[i].toLowerCase(Locale.ROOT);
         }
         return out;
      }
   }
}
