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
   private final Map<CheckVerdict.Reason, AtomicLong> byReason =
         new EnumMap<>(CheckVerdict.Reason.class);

   public Statistics() {
      for (CheckVerdict.Reason reason : CheckVerdict.Reason.values()) {
         byReason.put(reason, new AtomicLong());
      }
   }

   public void record(CheckVerdict verdict, boolean enforced) {
      checked.incrementAndGet();
      byReason.get(verdict.reason()).incrementAndGet();
      if (verdict.blocked()) {
         if (enforced) {
            blocked.incrementAndGet();
         } else {
            wouldHaveBlocked.incrementAndGet();
         }
      }
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
      blocked.set(0);
      wouldHaveBlocked.set(0);
      byReason.values().forEach(counter -> counter.set(0));
   }
}
