package de.lucasthcr.bridgesave.proxyshield.message;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * Guards the bundled message files against drift.
 * <p>
 * These checks exist because both failure modes have already happened during development: a key
 * used by the code was missing from the defaults, and four keys were named {@code yes}/{@code no}/
 * {@code on}/{@code off}, which YAML 1.1 parses as booleans rather than strings.
 */
class MessagesTest {

   private static final Pattern PLACEHOLDER = Pattern.compile("\\{([a-z0-9_-]+)}");

   @SuppressWarnings("unchecked")
   private static Map<Object, Object> loadBundled(String locale) throws Exception {
      String resource = "messages_" + locale + ".yml";
      try (InputStream in = MessagesTest.class.getClassLoader().getResourceAsStream(resource)) {
         assertNotNull(in, resource + " must be bundled in the jar");
         Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
         Object loaded = yaml.load(new InputStreamReader(in, StandardCharsets.UTF_8));
         assertTrue(loaded instanceof Map, resource + " must parse as a mapping");
         return (Map<Object, Object>) loaded;
      }
   }

   @ParameterizedTest
   @ValueSource(strings = {"en", "de"})
   @DisplayName("Bundled file defines every key the plugin looks up")
   void definesEveryKnownKey(String locale) throws Exception {
      Map<Object, Object> file = loadBundled(locale);

      Set<String> missing = new TreeSet<>();
      for (String key : Messages.knownKeys()) {
         if (!file.containsKey(key)) {
            missing.add(key);
         }
      }

      assertTrue(missing.isEmpty(), "messages_" + locale + ".yml is missing keys: " + missing);
   }

   @ParameterizedTest
   @ValueSource(strings = {"en", "de"})
   @DisplayName("Bundled file has no keys the plugin never reads")
   void hasNoStrayKeys(String locale) throws Exception {
      Map<Object, Object> file = loadBundled(locale);
      Set<String> known = new LinkedHashSet<>(Messages.knownKeys());

      Set<String> stray = new TreeSet<>();
      for (Object key : file.keySet()) {
         if (!known.contains(String.valueOf(key))) {
            stray.add(String.valueOf(key));
         }
      }

      assertTrue(stray.isEmpty(), "messages_" + locale + ".yml has unused keys: " + stray);
   }

   /**
    * YAML 1.1 turns bare {@code yes}, {@code no}, {@code on}, {@code off}, {@code true} and
    * {@code false} into booleans. A key or value of that shape would never reach the code as a
    * string, so the message would silently break.
    */
   @ParameterizedTest
   @ValueSource(strings = {"en", "de"})
   @DisplayName("No key or value is swallowed by YAML boolean coercion")
   void everythingStaysAString(String locale) throws Exception {
      Map<Object, Object> file = loadBundled(locale);

      List<String> problems = new ArrayList<>();
      for (Map.Entry<Object, Object> entry : file.entrySet()) {
         if (!(entry.getKey() instanceof String)) {
            problems.add("key " + entry.getKey() + " parsed as "
                  + entry.getKey().getClass().getSimpleName());
         }
         if (!(entry.getValue() instanceof String)) {
            problems.add("value of " + entry.getKey() + " parsed as "
                  + (entry.getValue() == null ? "null" : entry.getValue().getClass().getSimpleName()));
         }
      }

      assertTrue(problems.isEmpty(), "messages_" + locale + ".yml: " + problems);
   }

   @Test
   @DisplayName("Translations keep the placeholders the English text uses")
   void translationsKeepPlaceholders() throws Exception {
      Map<Object, Object> german = loadBundled("de");

      List<String> problems = new ArrayList<>();
      for (String key : Messages.knownKeys()) {
         Set<String> expected = placeholdersIn(Messages.defaultValue(key));
         Set<String> actual = placeholdersIn(String.valueOf(german.get(key)));

         Set<String> dropped = new TreeSet<>(expected);
         dropped.removeAll(actual);
         if (!dropped.isEmpty()) {
            problems.add(key + " drops " + dropped);
         }

         Set<String> invented = new TreeSet<>(actual);
         invented.removeAll(expected);
         if (!invented.isEmpty()) {
            problems.add(key + " invents " + invented);
         }
      }

      assertTrue(problems.isEmpty(), "messages_de.yml placeholder mismatch: " + problems);
   }

   private static Set<String> placeholdersIn(String template) {
      Set<String> found = new LinkedHashSet<>();
      if (template == null) {
         return found;
      }
      Matcher matcher = PLACEHOLDER.matcher(template);
      while (matcher.find()) {
         // {prefix} is injected everywhere and is not part of a message's own contract.
         if (!matcher.group(1).equals("prefix")) {
            found.add(matcher.group(1));
         }
      }
      return found;
   }

   @Test
   void unknownKeyIsVisibleRatherThanSilent() {
      String result = Messages.builtIn().get("no-such-key");

      assertTrue(result.contains("no-such-key"), "should name the missing key: " + result);
   }

   @Test
   void fillsPlaceholdersAndPrefix() {
      String result = Messages.builtIn().get("player-not-found", Map.of("input", "Steve"));

      assertTrue(result.contains("Steve"));
      assertTrue(result.contains("ProxyShield"), "prefix should be substituted");
   }

   @Test
   void kickMessageExistsAndCarriesTheReason() {
      String result = Messages.builtIn().get("kick-message", Map.of("reason", "proxy/VPN"));

      assertTrue(result.contains("proxy/VPN"));
      assertTrue(result.contains("\n"), "\\n should become a real line break");
   }

   @Test
   void bundledLocalesAreDeclared() {
      assertEquals(List.of("en", "de"), Messages.BUNDLED_LOCALES);
   }
}
