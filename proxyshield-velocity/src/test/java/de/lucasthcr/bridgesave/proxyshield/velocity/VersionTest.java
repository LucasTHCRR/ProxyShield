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

package de.lucasthcr.bridgesave.proxyshield.velocity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class VersionTest {

   private static final Pattern PARENT_VERSION =
         Pattern.compile("<artifactId>proxyshield-parent</artifactId>\\s*<version>([^<]+)</version>");

   @Test
   @DisplayName("The version Velocity shows is the version of the build")
   void matchesPom() throws IOException {
      String pom = Files.readString(Path.of("..", "pom.xml"), StandardCharsets.UTF_8);
      Matcher matcher = PARENT_VERSION.matcher(pom);

      assertTrue(matcher.find(), "no version found in the parent pom");
      assertEquals(matcher.group(1), VelocityMain.VERSION);
   }
}
