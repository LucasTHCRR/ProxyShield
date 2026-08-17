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
