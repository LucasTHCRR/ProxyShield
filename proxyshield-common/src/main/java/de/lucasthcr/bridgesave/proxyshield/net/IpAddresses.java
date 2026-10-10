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

package de.lucasthcr.bridgesave.proxyshield.net;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/** Parsing helpers for IPv4 and IPv6 literals. */
public final class IpAddresses {

   private static final Pattern V4_SHAPE = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");
   private static final Pattern V6_SHAPE = Pattern.compile("[0-9A-Fa-f:.]+");

   private IpAddresses() {
   }

   /**
    * Parses an IP literal into its raw 4 or 16 byte form, or returns {@code null} if the input is
    * not a literal address.
    * <p>
    * The shape of the input is validated before handing it to {@link InetAddress}, so a hostname
    * can never slip through and trigger a DNS lookup on the calling thread.
    */
   public static byte[] parseLiteral(String input) {
      if (input == null) {
         return null;
      }

      String text = input.trim();
      if (text.isEmpty()) {
         return null;
      }

      int zone = text.indexOf('%');
      if (zone >= 0) {
         text = text.substring(0, zone);
      }
      if (text.length() > 1 && text.charAt(0) == '[' && text.charAt(text.length() - 1) == ']') {
         text = text.substring(1, text.length() - 1);
      }
      if (text.isEmpty()) {
         return null;
      }

      boolean looksV6 = text.indexOf(':') >= 0;
      if (looksV6 ? !V6_SHAPE.matcher(text).matches() : !V4_SHAPE.matcher(text).matches()) {
         return null;
      }

      try {
         return InetAddress.getByName(text).getAddress();
      } catch (UnknownHostException notALiteral) {
         return null;
      }
   }

   public static boolean isValid(String input) {
      return parseLiteral(input) != null;
   }

   /**
    * True for loopback, link-local, site-local and unique-local addresses.
    * <p>
    * These never have meaningful proxy data, so checking them only wastes lookup quota and would
    * lock out LAN players whenever the provider answers with an error.
    */
   public static boolean isLocal(String input) {
      byte[] address = parseLiteral(input);
      return address != null && isLocal(address);
   }

   public static boolean isLocal(byte[] address) {
      try {
         // getByAddress never performs a name lookup, it only wraps the raw bytes.
         InetAddress parsed = InetAddress.getByAddress(address);
         if (parsed.isLoopbackAddress() || parsed.isLinkLocalAddress()
               || parsed.isSiteLocalAddress() || parsed.isAnyLocalAddress()) {
            return true;
         }
         // IPv6 unique local addresses (fc00::/7) are not covered by isSiteLocalAddress.
         return address.length == 16 && (address[0] & 0xFE) == 0xFC;
      } catch (UnknownHostException impossibleForRawBytes) {
         return false;
      }
   }

   /**
    * Whether the address sits in a range that is never routed on the public internet and is not
    * one of the private ranges {@link #isLocal(byte[])} already lets through.
    * <p>
    * A real player cannot arrive from documentation, benchmark, multicast or reserved space, so a
    * connection claiming one of these came through a forwarding layer that was lied to. Carrier
    * grade NAT (100.64.0.0/10) is deliberately absent: overlay networks such as Tailscale hand
    * those out to legitimate machines inside a network.
    */
   public static boolean isBogon(String input) {
      byte[] address = parseLiteral(input);
      return address != null && isBogon(address);
   }

   public static boolean isBogon(byte[] address) {
      if (address.length == 4) {
         int a = address[0] & 0xFF;
         int b = address[1] & 0xFF;
         int c = address[2] & 0xFF;
         return a == 0
               || (a == 192 && b == 0 && (c == 0 || c == 2))
               || (a == 198 && (b == 18 || b == 19))
               || (a == 198 && b == 51 && c == 100)
               || (a == 203 && b == 0 && c == 113)
               || a >= 224;
      }
      if (address.length == 16) {
         int a = address[0] & 0xFF;
         int b = address[1] & 0xFF;
         int c = address[2] & 0xFF;
         int d = address[3] & 0xFF;
         if (a == 0xFF) {
            return true; // multicast
         }
         if (a == 0x20 && b == 0x01 && c == 0x0D && d == 0xB8) {
            return true; // 2001:db8::/32, documentation
         }
         // 100::/64, discard-only
         if (a != 0x01 || b != 0) {
            return false;
         }
         for (int i = 2; i < 8; i++) {
            if (address[i] != 0) {
               return false;
            }
         }
         return true;
      }
      return false;
   }

   /**
    * The key an address is cached and rate-limited under.
    * <p>
    * IPv6 clients routinely get a whole /64 and rotate the host part, so caching the full address
    * means a VPN answers a fresh lookup for every reconnect and the cache never hits. Folding v6
    * down to its /64 is how the rest of the industry treats a "single" v6 client. IPv4 is returned
    * unchanged.
    */
   public static String cacheKey(String input) {
      byte[] address = parseLiteral(input);
      if (address == null) {
         return input;
      }
      if (address.length != 16) {
         return input.trim();
      }
      return prefixOf(address, 8) + "::/64";
   }

   /**
    * The neighbourhood an address belongs to, used by the join-rate heuristics: /24 for IPv4 and
    * /48 for IPv6, which is roughly one customer allocation on either side.
    */
   public static String subnetKey(String input) {
      byte[] address = parseLiteral(input);
      if (address == null) {
         return input;
      }
      if (address.length == 4) {
         return (address[0] & 0xFF) + "." + (address[1] & 0xFF) + "." + (address[2] & 0xFF)
               + ".0/24";
      }
      return prefixOf(address, 6) + "::/48";
   }

   private static String prefixOf(byte[] address, int bytes) {
      StringBuilder out = new StringBuilder();
      for (int i = 0; i < bytes; i += 2) {
         if (i > 0) {
            out.append(':');
         }
         out.append(Integer.toHexString(((address[i] & 0xFF) << 8) | (address[i + 1] & 0xFF)));
      }
      return out.toString();
   }

   /** Converts a 4 byte address into the unsigned value held in the low 32 bits of a long. */
   public static long toLong(byte[] v4) {
      return ((long) (v4[0] & 0xFF) << 24)
            | ((long) (v4[1] & 0xFF) << 16)
            | ((long) (v4[2] & 0xFF) << 8)
            | (v4[3] & 0xFF);
   }

   public static BigInteger toBigInteger(byte[] address) {
      return new BigInteger(1, address);
   }

   /**
    * Strips everything the public VPN lists tend to append to an entry: inline comments and
    * trailing free text such as {@code "1.2.3.0/24 # SomeProvider"}.
    */
   public static String normalizeListEntry(String line) {
      String text = line.trim();
      if (text.isEmpty() || text.charAt(0) == '#' || text.startsWith("//") || text.charAt(0) == ';') {
         return null;
      }

      int comment = text.indexOf('#');
      if (comment >= 0) {
         text = text.substring(0, comment).trim();
      }

      int space = indexOfWhitespace(text);
      if (space >= 0) {
         text = text.substring(0, space).trim();
      }

      // Some feeds ship entries as "1.2.3.0/24," inside a comma separated list.
      while (text.endsWith(",") || text.endsWith(";")) {
         text = text.substring(0, text.length() - 1).trim();
      }

      return text.isEmpty() ? null : text;
   }

   private static int indexOfWhitespace(String text) {
      for (int i = 0; i < text.length(); i++) {
         if (Character.isWhitespace(text.charAt(i))) {
            return i;
         }
      }
      return -1;
   }
}
