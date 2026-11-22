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

package de.lucasthcr.bridgesave.proxyshield.check;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.list.ListManager;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupProvider;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import de.lucasthcr.bridgesave.proxyshield.net.ManagedIpList;
import de.lucasthcr.bridgesave.proxyshield.net.NetworkData;
import de.lucasthcr.bridgesave.proxyshield.testing.MapConfigNode;
import de.lucasthcr.bridgesave.proxyshield.testing.RecordingPlatform;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NetworkDataTest {

   private static final String END_USER = "203.0.113.50";
   private static final String HOSTING = "198.51.100.50";

   @TempDir
   Path tempDir;

   private NetworkData feed() throws IOException {
      RecordingPlatform platform = new RecordingPlatform(tempDir);
      Path cache = platform.dataFolder().resolve("cache");
      Files.createDirectories(cache);
      String lines = "# test feed\n"
            + "3405803776\t3405804031\tE\tDE\t3320\t4\n"
            + "3325256704\t3325256959\tH\tUS\t24940\t4\n"
            + "151587072\t151587087\tN\tBG\t201899\t4\n"
            + "151587088\t151587103\tS\tNL\t9009\t4\n"
            + "42540766411282592856903984951653826560\t42540766411283801782723599580828532735\tE\tDE\t3320\t6\n";
      try (OutputStream out = new GZIPOutputStream(Files.newOutputStream(cache.resolve("network-feed.tsv.gz")))) {
         out.write(lines.getBytes(StandardCharsets.UTF_8));
      }
      NetworkData data = new NetworkData(platform);
      data.loadFromDisk();
      return data;
   }

   private CheckEngine engine(NetworkData data, LookupProvider provider, boolean fastAdmit)
         throws IOException {
      return engine(data, provider, fastAdmit ? "always" : "never");
   }

   private CheckEngine engine(NetworkData data, LookupProvider provider, String mode)
         throws IOException {
      Map<String, Object> values = new LinkedHashMap<>();
      values.put("detection.use-lists", false);
      values.put("detection.block-bogon", false);
      values.put("detection.network-data.fast-admit", mode);
      values.put("detection.network-data.fast-admit-burst", 3);
      ShieldConfig config = ShieldConfig.from(new MapConfigNode(values));
      RecordingPlatform platform = new RecordingPlatform(tempDir);
      ListManager lists = new ListManager(platform);
      ManagedIpList whitelist = new ManagedIpList(tempDir.resolve("w.txt"));
      ManagedIpList blacklist = new ManagedIpList(tempDir.resolve("b.txt"));
      whitelist.load();
      blacklist.load();
      return new CheckEngine(config, lists, provider, whitelist, blacklist).withNetworkData(data);
   }

   @Test
   @DisplayName("The feed tells end-user and hosting networks apart and knows nothing else")
   void classifies() throws IOException {
      NetworkData data = feed();

      assertTrue(data.classify(END_USER).endUser());
      assertEquals(3320, data.classify(END_USER).asn());
      assertTrue(data.classify(HOSTING).hosting());
      assertNull(data.classify("8.8.8.8"));
      assertNotNull(data.classify("2001:db8::1"));
   }

   @Test
   @DisplayName("Fast admit lets an end-user network in without asking a provider")
   void fastAdmitSkipsTheLookup() throws IOException {
      AtomicInteger asked = new AtomicInteger();
      CheckEngine engine = engine(feed(), ip -> {
         asked.incrementAndGet();
         return LookupResult.of(false, false, "DE", "Germany", "ISP");
      }, true);

      CheckVerdict verdict = engine.check("Steve", null, END_USER, permission -> false);

      assertFalse(verdict.blocked());
      assertEquals(0, asked.get());
   }

   @Test
   @DisplayName("Auto mode asks providers until a wave of joins starts")
   void autoModeSwitchesOnInAWave() throws IOException {
      AtomicInteger asked = new AtomicInteger();
      CheckEngine engine = engine(feed(), ip -> {
         asked.incrementAndGet();
         return LookupResult.of(false, false, "DE", "Germany", "ISP");
      }, "auto");

      engine.check("A", null, END_USER, permission -> false);
      engine.check("B", null, END_USER, permission -> false);
      assertEquals(2, asked.get());

      engine.check("C", null, END_USER, permission -> false);
      engine.check("D", null, END_USER, permission -> false);
      assertEquals(2, asked.get(), "from the third join in the window on, no lookups for end-user networks");
   }

   @Test
   @DisplayName("Without fast admit the provider is asked as before")
   void providersAreAskedByDefault() throws IOException {
      AtomicInteger asked = new AtomicInteger();
      CheckEngine engine = engine(feed(), ip -> {
         asked.incrementAndGet();
         return LookupResult.of(false, false, "DE", "Germany", "ISP");
      }, false);

      engine.check("Steve", null, END_USER, permission -> false);

      assertEquals(1, asked.get());
   }

   @Test
   @DisplayName("A hosting network is refused when no provider could answer")
   void hostingFallback() throws IOException {
      CheckEngine engine = engine(feed(), ip -> LookupResult.failed("quota"), false);

      CheckVerdict verdict = engine.check("Steve", null, HOSTING, permission -> false);

      assertTrue(verdict.blocked());
      assertEquals(CheckVerdict.Reason.HOSTING, verdict.reason());
   }

   @Test
   @DisplayName("A network without any end users is no proof of hosting, so it stays open when no provider could answer")
   void noUsersFallback() throws IOException {
      NetworkData data = feed();
      CheckEngine engine = engine(data, ip -> LookupResult.failed("quota"), false);

      assertTrue(data.classify("9.9.9.5").noUsers());
      assertFalse(data.classify("9.9.9.20").noUsers());
      assertFalse(data.classify("9.9.9.20").endUser());
      assertFalse(data.classify("9.9.9.20").hosting());
      assertEquals("NL", data.classify("9.9.9.20").country());

      assertFalse(engine.check("Steve", null, "9.9.9.5", permission -> false).blocked());
      assertFalse(engine.check("Steve", null, "9.9.9.20", permission -> false).blocked());
   }

   @Test
   @DisplayName("An end-user network is still let in when no provider could answer")
   void endUserStaysOpen() throws IOException {
      CheckEngine engine = engine(feed(), ip -> LookupResult.failed("quota"), false);

      assertFalse(engine.check("Steve", null, END_USER, permission -> false).blocked());
   }
}
