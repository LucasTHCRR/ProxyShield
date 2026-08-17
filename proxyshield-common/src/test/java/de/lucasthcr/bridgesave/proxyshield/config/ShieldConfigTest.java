package de.lucasthcr.bridgesave.proxyshield.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.lucasthcr.bridgesave.proxyshield.net.IpRangeSet;
import de.lucasthcr.bridgesave.proxyshield.testing.MapConfigNode;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Parses the config.yml that actually ships in the jar.
 * <p>
 * This is the check that catches a key being renamed in one place but not the other: if a option
 * moves in the YAML without the reader following, the assertion for its value fails.
 */
class ShieldConfigTest {

   private static ShieldConfig shipped;

   @BeforeAll
   static void loadShippedConfig(@TempDir Path tempDir) throws Exception {
      Path file = tempDir.resolve("config.yml");
      try (InputStream in = ShieldConfigTest.class.getClassLoader()
            .getResourceAsStream("config.yml")) {
         assertNotNull(in, "config.yml must be bundled in the jar");
         Files.writeString(file, new String(in.readAllBytes(), StandardCharsets.UTF_8));
      }
      shipped = ShieldConfig.from(YamlConfigNode.load(file));
   }

   @Test
   @DisplayName("Shipped defaults are safe to run as-is")
   void defaultsAreSensible() {
      assertEquals("en", shipped.language());
      assertEquals("proxyshield.bypass", shipped.bypassPermission());
      assertFalse(shipped.failClosed(), "default must fail open, not lock players out");
      assertFalse(shipped.dryRun());
      assertTrue(shipped.blockProxy());
      assertTrue(shipped.blockHosting());
      assertTrue(shipped.useLists());
      assertTrue(shipped.useApi());
      assertFalse(shipped.recheckOnline());
   }

   @Test
   void countryFilterIsOffByDefault() {
      assertFalse(shipped.countryEnabled());
      assertEquals(ShieldConfig.CountryMode.BLACKLIST, shipped.countryMode());
      assertFalse(shipped.blockUnknownCountry());
   }

   @Test
   @DisplayName("Default whitelist covers loopback and every private range")
   void defaultWhitelistCoversPrivateRanges() {
      IpRangeSet whitelist = IpRangeSet.of(shipped.whitelistIps());

      assertTrue(whitelist.contains("127.0.0.1"));
      assertTrue(whitelist.contains("10.1.2.3"));
      assertTrue(whitelist.contains("172.16.5.5"));
      assertTrue(whitelist.contains("192.168.1.20"));
      assertFalse(whitelist.contains("8.8.8.8"));
   }

   @Test
   void listSourcesAreAllHttps() {
      List<String> sources = shipped.activeListSources();

      assertFalse(sources.isEmpty(), "at least one feed must be configured");
      for (String source : sources) {
         assertTrue(source.startsWith("https://"), source + " should use HTTPS");
      }
   }

   @Test
   void apiTemplateCarriesTheIpPlaceholder() {
      assertTrue(shipped.apiUrl().contains("{ip}"),
            "without {ip} every lookup would query the same address");
      assertEquals(45, shipped.apiRateLimitPerMinute(), "must match the free tier limit");
   }

   @Test
   void notificationDefaults() {
      assertFalse(shipped.silent());
      assertTrue(shipped.consoleAlerts());
      assertTrue(shipped.logToFile());
      assertEquals("proxyshield.notify", shipped.notifyPermission());
   }

   @Test
   void discordIsOffAndNotUsableWithoutAUrl() {
      assertFalse(shipped.discordEnabled());
      assertFalse(shipped.discordUsable());
      assertEquals(0xFF0000, shipped.discordColor());
   }

   @Test
   @DisplayName("Out of range numbers are clamped rather than trusted")
   void clampsHostileValues() {
      ShieldConfig config = ShieldConfig.from(new MapConfigNode(Map.of(
            "lists.update-interval-hours", 0,
            "lists.timeout-seconds", 99999,
            "api.timeout-seconds", 0,
            "api.max-cache-entries", 1,
            "api.rate-limit-per-minute", 0,
            "api.cache-minutes", -5)));

      assertEquals(1L, config.listUpdateIntervalHours());
      assertEquals(300, config.listTimeoutSeconds());
      assertEquals(1, config.apiTimeoutSeconds());
      assertEquals(100, config.apiMaxCacheEntries());
      assertEquals(1, config.apiRateLimitPerMinute());
      assertEquals(1L, config.apiCacheMinutes());
   }

   @Test
   void countryCodesAreUpperCasedAndPlayersLowerCased() {
      ShieldConfig config = ShieldConfig.from(new MapConfigNode(Map.of(
            "country.codes", List.of("de", " at ", "Ch"),
            "whitelist.players", List.of("Steve", " ALEX "))));

      assertTrue(config.countryCodes().containsAll(List.of("DE", "AT", "CH")));
      assertTrue(config.whitelistPlayers().containsAll(List.of("steve", "alex")));
   }

   @Test
   void discordNeedsAnHttpsWebhook() {
      ShieldConfig plainHttp = ShieldConfig.from(new MapConfigNode(Map.of(
            "discord.enabled", true,
            "discord.webhook-url", "http://example.com/hook")));

      assertFalse(plainHttp.discordUsable(), "plain HTTP webhooks must be rejected");
   }

   @Test
   void countryModeParsingIsCaseInsensitiveAndDefaultsToBlacklist() {
      assertEquals(ShieldConfig.CountryMode.WHITELIST,
            ShieldConfig.from(new MapConfigNode(Map.of("country.mode", "WhiteList")))
                  .countryMode());
      assertEquals(ShieldConfig.CountryMode.BLACKLIST,
            ShieldConfig.from(new MapConfigNode(Map.of("country.mode", "nonsense")))
                  .countryMode());
   }
}
