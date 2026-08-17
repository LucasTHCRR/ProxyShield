package de.lucasthcr.bridgesave.proxyshield.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class IpAddressesTest {

   @ParameterizedTest
   @ValueSource(strings = {"1.2.3.4", "0.0.0.0", "255.255.255.255", "::1", "2001:db8::1",
         "[2001:db8::1]", "fe80::1%eth0"})
   void acceptsLiterals(String input) {
      assertTrue(IpAddresses.isValid(input), input);
   }

   @ParameterizedTest
   @ValueSource(strings = {"example.com", "", "   ", "1.2.3", "1.2.3.4.5", "999.1.1.1",
         "not an ip", "1.2.3.4/24"})
   void rejectsNonLiterals(String input) {
      assertFalse(IpAddresses.isValid(input), input);
   }

   @Test
   void rejectsNull() {
      assertNull(IpAddresses.parseLiteral(null));
   }

   /**
    * A hostname must never reach {@code InetAddress.getByName}, otherwise a login could block on a
    * DNS lookup. Shape validation happens first, so this returns immediately.
    */
   @Test
   void neverResolvesHostnames() {
      assertTimeoutPreemptively(Duration.ofMillis(500), () -> {
         assertFalse(IpAddresses.isValid("this-host-does-not-exist.invalid"));
         assertFalse(IpAddresses.isValid("localhost"));
      });
   }

   @ParameterizedTest
   @ValueSource(strings = {"127.0.0.1", "127.1.2.3", "10.1.2.3", "192.168.1.50", "172.16.0.1",
         "169.254.1.1", "0.0.0.0", "::1", "fd00::1", "fe80::1"})
   void detectsLocalAddresses(String input) {
      assertTrue(IpAddresses.isLocal(input), input);
   }

   @ParameterizedTest
   @ValueSource(strings = {"8.8.8.8", "1.1.1.1", "203.0.113.7", "2001:db8::1"})
   void publicAddressesAreNotLocal(String input) {
      assertFalse(IpAddresses.isLocal(input), input);
   }

   @Test
   void convertsIpv4ToUnsignedLong() {
      assertEquals(0L, IpAddresses.toLong(IpAddresses.parseLiteral("0.0.0.0")));
      assertEquals(16909060L, IpAddresses.toLong(IpAddresses.parseLiteral("1.2.3.4")));
      assertEquals(4294967295L, IpAddresses.toLong(IpAddresses.parseLiteral("255.255.255.255")));
   }

   @Test
   void stripsListEntryNoise() {
      assertEquals("1.2.3.0/24", IpAddresses.normalizeListEntry("1.2.3.0/24 SomeProvider"));
      assertEquals("1.2.3.0/24", IpAddresses.normalizeListEntry("  1.2.3.0/24  # comment"));
      assertEquals("1.2.3.0/24", IpAddresses.normalizeListEntry("1.2.3.0/24,"));
      assertNull(IpAddresses.normalizeListEntry("# whole line comment"));
      assertNull(IpAddresses.normalizeListEntry("// whole line comment"));
      assertNull(IpAddresses.normalizeListEntry("   "));
   }
}
