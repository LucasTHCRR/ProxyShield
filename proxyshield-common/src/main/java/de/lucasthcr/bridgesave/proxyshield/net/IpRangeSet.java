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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * An immutable set of IP ranges with O(log n) lookups.
 * <p>
 * Entries are accepted as single addresses ({@code 1.2.3.4}), CIDR blocks ({@code 1.2.3.0/24}) or
 * explicit spans ({@code 1.2.3.4-1.2.3.9}), for both IPv4 and IPv6. Everything is normalised to
 * start/end pairs which are then sorted and merged, so overlapping feeds do not blow up memory and
 * a lookup is a single binary search.
 * <p>
 * Note that v1 of this plugin threw the prefix length away ({@code entry.split("/")[0]}) and then
 * compared for string equality, which meant a {@code /24} block only ever matched its own network
 * address and the list check was effectively dead.
 */
public final class IpRangeSet {

   private static final BigInteger V6_MAX = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);

   public static final IpRangeSet EMPTY = new IpRangeSet(new long[0], new long[0],
         new BigInteger[0], new BigInteger[0], 0);

   private final long[] v4Start;
   private final long[] v4End;
   private final BigInteger[] v6Start;
   private final BigInteger[] v6End;
   private final int acceptedEntries;

   private IpRangeSet(long[] v4Start, long[] v4End, BigInteger[] v6Start, BigInteger[] v6End,
         int acceptedEntries) {
      this.v4Start = v4Start;
      this.v4End = v4End;
      this.v6Start = v6Start;
      this.v6End = v6End;
      this.acceptedEntries = acceptedEntries;
   }

   public static Builder builder() {
      return new Builder();
   }

   /** Convenience factory for the small config driven lists. */
   public static IpRangeSet of(Iterable<String> entries) {
      Builder builder = builder();
      for (String entry : entries) {
         builder.add(entry);
      }
      return builder.build();
   }

   public boolean contains(String ip) {
      byte[] address = IpAddresses.parseLiteral(ip);
      return address != null && contains(address);
   }

   public boolean contains(byte[] address) {
      if (address.length == 4) {
         return containsV4(IpAddresses.toLong(address));
      }
      return containsV6(IpAddresses.toBigInteger(address));
   }

   private boolean containsV4(long value) {
      int index = floorIndex(v4Start, value);
      return index >= 0 && Long.compareUnsigned(value, v4End[index]) <= 0;
   }

   private boolean containsV6(BigInteger value) {
      int index = floorIndex(v6Start, value);
      return index >= 0 && value.compareTo(v6End[index]) <= 0;
   }

   /** Index of the last range whose start is <= value, or -1. */
   private static int floorIndex(long[] starts, long value) {
      int low = 0;
      int high = starts.length - 1;
      int found = -1;
      while (low <= high) {
         int mid = (low + high) >>> 1;
         if (Long.compareUnsigned(starts[mid], value) <= 0) {
            found = mid;
            low = mid + 1;
         } else {
            high = mid - 1;
         }
      }
      return found;
   }

   private static int floorIndex(BigInteger[] starts, BigInteger value) {
      int low = 0;
      int high = starts.length - 1;
      int found = -1;
      while (low <= high) {
         int mid = (low + high) >>> 1;
         if (starts[mid].compareTo(value) <= 0) {
            found = mid;
            low = mid + 1;
         } else {
            high = mid - 1;
         }
      }
      return found;
   }

   /** Number of source entries that parsed successfully. */
   public int entryCount() {
      return acceptedEntries;
   }

   /** Number of ranges left after merging, which is what lookups actually search. */
   public int rangeCount() {
      return v4Start.length + v6Start.length;
   }

   public boolean isEmpty() {
      return rangeCount() == 0;
   }

   /**
    * Number of IPv4 addresses covered.
    * <p>
    * Exact, and it cannot overflow: the ranges are merged and disjoint, so the total is at most
    * 2^32.
    * <p>
    * There is deliberately no combined figure. A single IPv6 /64 already holds 2^64 addresses, so
    * any total including IPv6 exceeds what a {@code long} can express and has to be reported as a
    * saturated value, which then never changes no matter what the feeds contain. A number that
    * does not move with its input is worse than no number, so IPv6 is reported by range instead.
    */
   public long ipv4AddressCount() {
      long total = 0;
      for (int i = 0; i < v4Start.length; i++) {
         total += v4End[i] - v4Start[i] + 1;
      }
      return total;
   }

   /** Merged IPv4 ranges. */
   public int ipv4RangeCount() {
      return v4Start.length;
   }

   /** Merged IPv6 ranges. These are counted rather than measured, see {@link #ipv4AddressCount()}. */
   public int ipv6RangeCount() {
      return v6Start.length;
   }

   /** Collects entries and produces the immutable, merged set. */
   public static final class Builder {

      private final List<long[]> v4 = new ArrayList<>();
      private final List<BigInteger[]> v6 = new ArrayList<>();
      private int accepted;
      private int rejected;

      /** Takes over everything another builder collected. */
      public void addAll(Builder other) {
         v4.addAll(other.v4);
         v6.addAll(other.v6);
         accepted += other.accepted;
         rejected += other.rejected;
      }

      /** Adds a raw list line. Returns {@code true} if it produced a usable range. */
      public boolean add(String rawEntry) {
         String entry = IpAddresses.normalizeListEntry(rawEntry);
         if (entry == null) {
            return false;
         }

         boolean ok = entry.indexOf('/') >= 0 ? addCidr(entry) : addPlainOrSpan(entry);
         if (ok) {
            accepted++;
         } else {
            rejected++;
         }
         return ok;
      }

      private boolean addCidr(String entry) {
         int slash = entry.indexOf('/');
         byte[] address = IpAddresses.parseLiteral(entry.substring(0, slash));
         if (address == null) {
            return false;
         }

         int prefix;
         try {
            prefix = Integer.parseInt(entry.substring(slash + 1).trim());
         } catch (NumberFormatException notANumber) {
            return false;
         }

         int bits = address.length * 8;
         if (prefix < 0 || prefix > bits) {
            return false;
         }

         if (address.length == 4) {
            long base = IpAddresses.toLong(address);
            long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
            long start = base & mask;
            long end = start | (~mask & 0xFFFFFFFFL);
            v4.add(new long[]{start, end});
         } else {
            int hostBits = 128 - prefix;
            BigInteger base = IpAddresses.toBigInteger(address);
            BigInteger start = base.shiftRight(hostBits).shiftLeft(hostBits);
            BigInteger end = start.add(BigInteger.ONE.shiftLeft(hostBits)).subtract(BigInteger.ONE);
            v6.add(new BigInteger[]{start, end.min(V6_MAX)});
         }
         return true;
      }

      private boolean addPlainOrSpan(String entry) {
         int dash = entry.indexOf('-');
         if (dash <= 0) {
            return addSingle(entry);
         }

         byte[] from = IpAddresses.parseLiteral(entry.substring(0, dash));
         byte[] to = IpAddresses.parseLiteral(entry.substring(dash + 1));
         if (from == null || to == null || from.length != to.length) {
            // A dash inside an IPv6 literal is not legal, so this really is a malformed entry.
            return addSingle(entry);
         }

         if (from.length == 4) {
            long start = IpAddresses.toLong(from);
            long end = IpAddresses.toLong(to);
            if (Long.compareUnsigned(start, end) > 0) {
               long swap = start;
               start = end;
               end = swap;
            }
            v4.add(new long[]{start, end});
         } else {
            BigInteger start = IpAddresses.toBigInteger(from);
            BigInteger end = IpAddresses.toBigInteger(to);
            if (start.compareTo(end) > 0) {
               BigInteger swap = start;
               start = end;
               end = swap;
            }
            v6.add(new BigInteger[]{start, end});
         }
         return true;
      }

      private boolean addSingle(String entry) {
         byte[] address = IpAddresses.parseLiteral(entry);
         if (address == null) {
            return false;
         }
         if (address.length == 4) {
            long value = IpAddresses.toLong(address);
            v4.add(new long[]{value, value});
         } else {
            BigInteger value = IpAddresses.toBigInteger(address);
            v6.add(new BigInteger[]{value, value});
         }
         return true;
      }

      public int accepted() {
         return accepted;
      }

      public int rejected() {
         return rejected;
      }

      public IpRangeSet build() {
         v4.sort((a, b) -> Long.compareUnsigned(a[0], b[0]));
         v6.sort(Comparator.comparing(a -> a[0]));

         List<long[]> mergedV4 = new ArrayList<>(v4.size());
         for (long[] range : v4) {
            if (!mergedV4.isEmpty()) {
               long[] last = mergedV4.get(mergedV4.size() - 1);
               // Merge when overlapping or directly adjacent. The +1 cannot wrap because
               // 255.255.255.255 as the end means every following start is <= it anyway.
               if (Long.compareUnsigned(range[0], last[1]) <= 0
                     || (last[1] != 0xFFFFFFFFL && range[0] == last[1] + 1)) {
                  if (Long.compareUnsigned(range[1], last[1]) > 0) {
                     last[1] = range[1];
                  }
                  continue;
               }
            }
            mergedV4.add(new long[]{range[0], range[1]});
         }

         List<BigInteger[]> mergedV6 = new ArrayList<>(v6.size());
         for (BigInteger[] range : v6) {
            if (!mergedV6.isEmpty()) {
               BigInteger[] last = mergedV6.get(mergedV6.size() - 1);
               if (range[0].compareTo(last[1]) <= 0
                     || range[0].equals(last[1].add(BigInteger.ONE))) {
                  if (range[1].compareTo(last[1]) > 0) {
                     last[1] = range[1];
                  }
                  continue;
               }
            }
            mergedV6.add(new BigInteger[]{range[0], range[1]});
         }

         long[] starts4 = new long[mergedV4.size()];
         long[] ends4 = new long[mergedV4.size()];
         for (int i = 0; i < mergedV4.size(); i++) {
            starts4[i] = mergedV4.get(i)[0];
            ends4[i] = mergedV4.get(i)[1];
         }

         BigInteger[] starts6 = new BigInteger[mergedV6.size()];
         BigInteger[] ends6 = new BigInteger[mergedV6.size()];
         for (int i = 0; i < mergedV6.size(); i++) {
            starts6[i] = mergedV6.get(i)[0];
            ends6[i] = mergedV6.get(i)[1];
         }

         return new IpRangeSet(starts4, ends4, starts6, ends6, accepted);
      }
   }
}
