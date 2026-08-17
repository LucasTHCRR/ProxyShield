package de.lucasthcr.bridgesave.proxyshield.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small dependency free JSON reader and writer.
 * <p>
 * The plugin only ever reads flat lookup responses and writes one webhook payload, so pulling in a
 * full JSON library on three different platforms is not worth the classpath risk. What does matter
 * is correct escaping on the way out: v1 concatenated player names and config strings straight into
 * the webhook body, so a name or a kick message containing a quote produced malformed JSON, and a
 * crafted one could inject arbitrary fields into the embed.
 */
public final class Json {

   private Json() {
   }

   // ---------------------------------------------------------------- writing

   /** Escapes a string for use as a JSON string body, without the surrounding quotes. */
   public static String escape(String raw) {
      if (raw == null) {
         return "";
      }

      StringBuilder out = new StringBuilder(raw.length() + 16);
      for (int i = 0; i < raw.length(); i++) {
         char c = raw.charAt(i);
         switch (c) {
            case '"' -> out.append("\\\"");
            case '\\' -> out.append("\\\\");
            case '\n' -> out.append("\\n");
            case '\r' -> out.append("\\r");
            case '\t' -> out.append("\\t");
            case '\b' -> out.append("\\b");
            case '\f' -> out.append("\\f");
            default -> {
               if (c < 0x20) {
                  out.append(String.format("\\u%04x", (int) c));
               } else {
                  out.append(c);
               }
            }
         }
      }
      return out.toString();
   }

   /** Builds JSON objects and arrays with correct escaping. */
   public static final class Writer {

      private final StringBuilder out = new StringBuilder();
      private boolean needsComma;

      public Writer beginObject() {
         separate();
         out.append('{');
         needsComma = false;
         return this;
      }

      public Writer endObject() {
         out.append('}');
         needsComma = true;
         return this;
      }

      public Writer beginArray() {
         separate();
         out.append('[');
         needsComma = false;
         return this;
      }

      public Writer endArray() {
         out.append(']');
         needsComma = true;
         return this;
      }

      public Writer name(String name) {
         separate();
         out.append('"').append(escape(name)).append("\":");
         needsComma = false;
         return this;
      }

      public Writer value(String value) {
         separate();
         out.append('"').append(escape(value)).append('"');
         needsComma = true;
         return this;
      }

      public Writer value(long value) {
         separate();
         out.append(value);
         needsComma = true;
         return this;
      }

      public Writer value(boolean value) {
         separate();
         out.append(value);
         needsComma = true;
         return this;
      }

      public Writer field(String name, String value) {
         return name(name).value(value);
      }

      public Writer field(String name, long value) {
         return name(name).value(value);
      }

      public Writer field(String name, boolean value) {
         return name(name).value(value);
      }

      private void separate() {
         if (needsComma) {
            out.append(',');
         }
      }

      @Override
      public String toString() {
         return out.toString();
      }
   }

   // ---------------------------------------------------------------- reading

   /**
    * Parses a JSON document into {@link Map}, {@link List}, {@link String}, {@link Double},
    * {@link Boolean} or {@code null}.
    *
    * @throws JsonException if the input is not valid JSON
    */
   public static Object parse(String input) {
      Parser parser = new Parser(input);
      parser.skipWhitespace();
      Object value = parser.readValue();
      parser.skipWhitespace();
      if (!parser.atEnd()) {
         throw new JsonException("Trailing data at position " + parser.position);
      }
      return value;
   }

   /** Parses a document that is expected to be an object, returning an empty map on anything else. */
   @SuppressWarnings("unchecked")
   public static Map<String, Object> parseObject(String input) {
      Object value = parse(input);
      return value instanceof Map ? (Map<String, Object>) value : new LinkedHashMap<>();
   }

   public static String stringOf(Map<String, Object> object, String key) {
      Object value = object.get(key);
      return value == null ? null : String.valueOf(value);
   }

   /**
    * Reads a flag, accepting the spellings the various providers use.
    * <p>
    * ip-api.com sends a real JSON boolean, proxycheck.io sends {@code "yes"} / {@code "no"}, and
    * some send {@code 1} / {@code 0}.
    */
   public static boolean boolOf(Map<String, Object> object, String key) {
      Object value = object.get(key);
      if (value instanceof Boolean flag) {
         return flag;
      }
      if (value instanceof Number number) {
         return number.intValue() != 0;
      }
      if (value instanceof String text) {
         String normalized = text.trim().toLowerCase(java.util.Locale.ROOT);
         return normalized.equals("true") || normalized.equals("yes") || normalized.equals("1");
      }
      return false;
   }

   public static final class JsonException extends RuntimeException {
      public JsonException(String message) {
         super(message);
      }
   }

   private static final class Parser {

      private final String input;
      private int position;

      Parser(String input) {
         this.input = input == null ? "" : input;
      }

      boolean atEnd() {
         return position >= input.length();
      }

      void skipWhitespace() {
         while (position < input.length() && Character.isWhitespace(input.charAt(position))) {
            position++;
         }
      }

      Object readValue() {
         if (atEnd()) {
            throw new JsonException("Unexpected end of input");
         }
         char c = input.charAt(position);
         return switch (c) {
            case '{' -> readObject();
            case '[' -> readArray();
            case '"' -> readString();
            case 't', 'f' -> readBoolean();
            case 'n' -> readNull();
            default -> readNumber();
         };
      }

      Map<String, Object> readObject() {
         expect('{');
         Map<String, Object> object = new LinkedHashMap<>();
         skipWhitespace();
         if (peek() == '}') {
            position++;
            return object;
         }

         while (true) {
            skipWhitespace();
            String key = readString();
            skipWhitespace();
            expect(':');
            skipWhitespace();
            object.put(key, readValue());
            skipWhitespace();
            char c = next();
            if (c == '}') {
               return object;
            }
            if (c != ',') {
               throw new JsonException("Expected ',' or '}' at position " + (position - 1));
            }
         }
      }

      List<Object> readArray() {
         expect('[');
         List<Object> array = new ArrayList<>();
         skipWhitespace();
         if (peek() == ']') {
            position++;
            return array;
         }

         while (true) {
            skipWhitespace();
            array.add(readValue());
            skipWhitespace();
            char c = next();
            if (c == ']') {
               return array;
            }
            if (c != ',') {
               throw new JsonException("Expected ',' or ']' at position " + (position - 1));
            }
         }
      }

      String readString() {
         expect('"');
         StringBuilder out = new StringBuilder();
         while (true) {
            char c = next();
            if (c == '"') {
               return out.toString();
            }
            if (c != '\\') {
               out.append(c);
               continue;
            }

            char escaped = next();
            switch (escaped) {
               case '"' -> out.append('"');
               case '\\' -> out.append('\\');
               case '/' -> out.append('/');
               case 'b' -> out.append('\b');
               case 'f' -> out.append('\f');
               case 'n' -> out.append('\n');
               case 'r' -> out.append('\r');
               case 't' -> out.append('\t');
               case 'u' -> {
                  if (position + 4 > input.length()) {
                     throw new JsonException("Truncated unicode escape");
                  }
                  out.append((char) Integer.parseInt(input.substring(position, position + 4), 16));
                  position += 4;
               }
               default -> throw new JsonException("Invalid escape '\\" + escaped + "'");
            }
         }
      }

      Boolean readBoolean() {
         if (input.startsWith("true", position)) {
            position += 4;
            return Boolean.TRUE;
         }
         if (input.startsWith("false", position)) {
            position += 5;
            return Boolean.FALSE;
         }
         throw new JsonException("Invalid literal at position " + position);
      }

      Object readNull() {
         if (input.startsWith("null", position)) {
            position += 4;
            return null;
         }
         throw new JsonException("Invalid literal at position " + position);
      }

      Double readNumber() {
         int start = position;
         while (position < input.length() && "+-.eE0123456789".indexOf(input.charAt(position)) >= 0) {
            position++;
         }
         if (start == position) {
            throw new JsonException("Invalid value at position " + start);
         }
         try {
            return Double.valueOf(input.substring(start, position));
         } catch (NumberFormatException malformed) {
            throw new JsonException("Invalid number at position " + start);
         }
      }

      char peek() {
         if (atEnd()) {
            throw new JsonException("Unexpected end of input");
         }
         return input.charAt(position);
      }

      char next() {
         if (atEnd()) {
            throw new JsonException("Unexpected end of input");
         }
         return input.charAt(position++);
      }

      void expect(char expected) {
         char actual = next();
         if (actual != expected) {
            throw new JsonException("Expected '" + expected + "' but found '" + actual
                  + "' at position " + (position - 1));
         }
      }
   }
}
