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

package de.lucasthcr.bridgesave.proxyshield.stats;

import de.lucasthcr.bridgesave.proxyshield.check.CheckVerdict;
import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/** Running counters for {@code /proxyshield stats}. */
public final class Statistics {

   private final long startedAt = System.currentTimeMillis();
   private final AtomicLong checked = new AtomicLong();
   private final AtomicLong blocked = new AtomicLong();
   private final AtomicLong wouldHaveBlocked = new AtomicLong();
   private final AtomicLong uncheckedAdmitted = new AtomicLong();
   private final AtomicLong intelDecided = new AtomicLong();
   private final AtomicLong uncheckedAtLastLog = new AtomicLong();
   private final Map<CheckVerdict.Reason, AtomicLong> byReason =
         new EnumMap<>(CheckVerdict.Reason.class);
   private final AtomicLong blockedAtLastReport = new AtomicLong();
   private final AtomicLong lookupsAtLastReport = new AtomicLong();

   public Statistics() {
      for (CheckVerdict.Reason reason : CheckVerdict.Reason.values()) {
         byReason.put(reason, new AtomicLong());
      }
   }

   public void record(CheckVerdict verdict, boolean enforced) {
      checked.incrementAndGet();
      byReason.get(verdict.reason()).incrementAndGet();
      de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult lookup = verdict.lookup();
      // Durchgelassen, obwohl kein Dienst und keine Liste geantwortet hat
      if (!verdict.blocked() && verdict.reason() == CheckVerdict.Reason.ALLOWED && lookup != null
            && lookup != de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult.UNKNOWN && !lookup.resolved()) {
         uncheckedAdmitted.incrementAndGet();
      }
      if (verdict.blocked() && lookup != null && lookup.sources().contains("paperstream-intel")) {
         intelDecided.incrementAndGet();
      }
      if (verdict.blocked()) {
         if (enforced) {
            blocked.incrementAndGet();
         } else {
            wouldHaveBlocked.incrementAndGet();
         }
      }
   }

   public long uncheckedAdmitted() {
      return uncheckedAdmitted.get();
   }

   public long intelDecided() {
      return intelDecided.get();
   }

   // Neue ungepruefte Logins seit dem letzten Aufruf
   public long drainUncheckedSinceLog() {
      long now = uncheckedAdmitted.get();
      return now - uncheckedAtLastLog.getAndSet(now);
   }

   public long checked() {
      return checked.get();
   }

   public long blocked() {
      return blocked.get();
   }

   /** Detections that were reported but not enforced because dry-run is on. */
   public long wouldHaveBlocked() {
      return wouldHaveBlocked.get();
   }

   public long count(CheckVerdict.Reason reason) {
      return byReason.get(reason).get();
   }

   /**
    * Blocks since the last call, for the metrics line chart.
    * <p>
    * bStats plots what it is given, so a running total would draw an ever-rising line that says
    * nothing about how much the plugin is actually doing right now.
    */
   public int drainBlockedSinceReport() {
      long total = blocked.get() + wouldHaveBlocked.get();
      long previous = blockedAtLastReport.getAndSet(total);
      return (int) Math.max(0L, total - previous);
   }

   /** Lookups since the last call, given the lookup service's running total. */
   public int drainLookupsSinceReport(long totalLookups) {
      long previous = lookupsAtLastReport.getAndSet(totalLookups);
      return (int) Math.max(0L, totalLookups - previous);
   }

   public long uptimeMillis() {
      return System.currentTimeMillis() - startedAt;
   }

   public String uptimeFormatted() {
      long seconds = uptimeMillis() / 1000L;
      long days = seconds / 86400L;
      long hours = (seconds % 86400L) / 3600L;
      long minutes = (seconds % 3600L) / 60L;

      if (days > 0) {
         return days + "d " + hours + "h " + minutes + "m";
      }
      if (hours > 0) {
         return hours + "h " + minutes + "m";
      }
      return minutes + "m " + (seconds % 60L) + "s";
   }

   public void reset() {
      checked.set(0);
      blockedAtLastReport.set(0);
      lookupsAtLastReport.set(0);
      blocked.set(0);
      wouldHaveBlocked.set(0);
      byReason.values().forEach(counter -> counter.set(0));
   }
}
