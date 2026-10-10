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

package de.lucasthcr.bridgesave.proxyshield.notify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.lucasthcr.bridgesave.proxyshield.check.CheckVerdict;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import de.lucasthcr.bridgesave.proxyshield.testing.MapConfigNode;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Telegram and VK alert text and the switches that turn them on. */
class ChatNotifierTest {

   private static final CheckVerdict VERDICT = CheckVerdict.deny(CheckVerdict.Reason.PROXY,
         "stub", LookupResult.of(true, false, "NL", "Netherlands", "Example BV"));

   @Test
   void placeholdersAndLineBreaksAreFilledIn() {
      String text = ChatNotifier.render("{action}: {player} ({ip})\\n{country} {isp}", "Steve",
            "8.8.4.4", VERDICT, true, true);
      assertEquals("blocked: Steve (8.8.4.4)\nNL Example BV", text);
   }

   @Test
   void theAddressCanBeHidden() {
      String text = ChatNotifier.render("{ip}", "Steve", "8.8.4.4", VERDICT, false, false);
      assertEquals("hidden", text);
   }

   @Test
   void aServiceNeedsItsCredentialsBeforeItCounts() {
      Map<String, Object> values = new LinkedHashMap<>();
      values.put("telegram.enabled", true);
      values.put("vk.enabled", true);
      ShieldConfig incomplete = ShieldConfig.from(new MapConfigNode(values));
      assertFalse(incomplete.telegramUsable());
      assertFalse(incomplete.vkUsable());

      values.put("telegram.bot-token", "123:abc");
      values.put("telegram.chat-id", "-1001234");
      values.put("vk.access-token", "token");
      values.put("vk.peer-id", 2000000001L);
      ShieldConfig complete = ShieldConfig.from(new MapConfigNode(values));
      assertTrue(complete.telegramUsable());
      assertTrue(complete.vkUsable());
   }
}
