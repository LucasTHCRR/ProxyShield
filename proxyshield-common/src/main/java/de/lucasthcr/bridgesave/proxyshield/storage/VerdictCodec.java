package de.lucasthcr.bridgesave.proxyshield.storage;

import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import de.lucasthcr.bridgesave.proxyshield.util.Json;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Turns a verdict into JSON and back.
 * <p>
 * Shared by the file store and Redis so both write the same shape: a cache file written by a
 * single server stays readable after that server is put behind a shared Redis, and vice versa.
 */
final class VerdictCodec {

   private VerdictCodec() {
   }

   /** Writes the verdict's fields into an open object. */
   static void writeFields(Json.Writer writer, ShieldStorage.CachedVerdict verdict) {
      LookupResult result = verdict.result();
      writer.field("expires", verdict.expiresAt())
            .field("proxy", result.proxy())
            .field("hosting", result.hosting())
            .field("tor", result.tor());

      if (result.countryCode() != null) {
         writer.field("country", result.countryCode());
      }
      if (result.countryName() != null) {
         writer.field("countryName", result.countryName());
      }
      if (result.isp() != null) {
         writer.field("isp", result.isp());
      }
      if (result.asn() != null) {
         writer.field("asn", result.asn());
      }
      if (result.connectionType() != null) {
         writer.field("type", result.connectionType());
      }

      // Stored in hundredths so the value survives as an integer everywhere.
      writer.name("confidence").value(Math.round(result.confidence() * 100.0));
      writer.name("sources").beginArray();
      for (String source : result.sources()) {
         writer.value(source);
      }
      writer.endArray();
   }

   static String encode(ShieldStorage.CachedVerdict verdict) {
      Json.Writer writer = new Json.Writer().beginObject();
      writeFields(writer, verdict);
      return writer.endObject().toString();
   }

   /** Reads a verdict from a parsed JSON object, or {@code null} if it is unusable or expired. */
   static ShieldStorage.CachedVerdict decode(Object node) {
      if (!(node instanceof Map<?, ?>)) {
         return null;
      }

      Double expires = Json.numberAt(node, "expires");
      if (expires == null || expires <= System.currentTimeMillis()) {
         return null;
      }

      List<String> sources = new ArrayList<>();
      if (Json.path(node, "sources") instanceof List<?> raw) {
         for (Object source : raw) {
            sources.add(String.valueOf(source));
         }
      }

      Double confidence = Json.numberAt(node, "confidence");
      LookupResult result = LookupResult.of(
            Json.boolAt(node, "proxy"),
            Json.boolAt(node, "hosting"),
            Json.boolAt(node, "tor"),
            Json.stringAt(node, "country"),
            Json.stringAt(node, "countryName"),
            Json.stringAt(node, "isp"),
            Json.stringAt(node, "asn"),
            Json.stringAt(node, "type"),
            confidence == null ? 0.0 : confidence / 100.0,
            sources);
      return new ShieldStorage.CachedVerdict(result, expires.longValue());
   }

   static ShieldStorage.CachedVerdict decode(String json) {
      if (json == null || json.isBlank()) {
         return null;
      }
      try {
         return decode(Json.parse(json));
      } catch (Json.JsonException malformed) {
         return null;
      }
   }
}
