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

package de.lucasthcr.bridgesave.proxyshield.metrics;

import de.lucasthcr.bridgesave.proxyshield.ProxyShieldCore;
import de.lucasthcr.bridgesave.proxyshield.config.ShieldConfig;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The values reported to bStats, in one place.
 * <p>
 * Every platform module registers the same charts from here, so the graphs for the Bukkit, Bungee,
 * Velocity and Sponge builds are comparable instead of each showing whatever that module's author
 * happened to add. Nothing here identifies a server or a player: it is configuration shape and
 * counters, which is what makes it answerable whether a setting is worth keeping.
 */
public final class MetricsData {

   /** The bStats id of the Bukkit project, used by the Paper, Folia and Spigot builds. */
   public static final int BUKKIT_PLUGIN_ID = 33736;

   private MetricsData() {
   }

   /** Chart id to current value, for the simple pie charts. */
   public static Map<String, String> pies(ProxyShieldCore core) {
      ShieldConfig config = core.config();
      Map<String, String> charts = new LinkedHashMap<>();

      charts.put("lookup_mode", config.lookupMode().name().toLowerCase(java.util.Locale.ROOT));
      charts.put("storage_type", core.storage().name());
      charts.put("enforcement", config.dryRun() ? "dry-run" : "enforcing");
      charts.put("provider_count", bucket(core.lookups().providerCount()));
      charts.put("required_score", String.format(java.util.Locale.ROOT, "%.1f",
            config.requiredScore()));
      charts.put("language", config.language());
      charts.put("country_filter", config.countryEnabled()
            ? config.countryMode().name().toLowerCase(java.util.Locale.ROOT)
            : "off");
      charts.put("asn_rules", onOff(config.asnEnabled()
            && !(config.blockedAsns().isEmpty() && config.allowedAsns().isEmpty())));
      charts.put("reverse_dns", onOff(config.rdnsEnabled()));
      charts.put("heuristics", onOff(config.heuristicsEnabled()));
      charts.put("trust", onOff(config.trustEnabled()));
      charts.put("shared_storage", onOff(core.storage().shared()));

      return charts;
   }

   /**
    * Blocks since the last report, for a line chart.
    * <p>
    * Each counter is drained by its own call rather than through a map of all of them: a map would
    * be rebuilt per chart callback, and every rebuild would reset the counters the caller did not
    * read, so one of the two lines would silently flatline.
    */
   public static int blockedSinceLastReport(ProxyShieldCore core) {
      return core.statistics().drainBlockedSinceReport();
   }

   /** Provider lookups since the last report, for a line chart. */
   public static int lookupsSinceLastReport(ProxyShieldCore core) {
      return core.statistics().drainLookupsSinceReport(core.lookups().lookups());
   }

   /** Groups the provider count, so the chart stays readable. */
   private static String bucket(int providers) {
      if (providers <= 1) {
         return String.valueOf(providers);
      }
      if (providers <= 3) {
         return "2-3";
      }
      if (providers <= 6) {
         return "4-6";
      }
      return "7+";
   }

   private static String onOff(boolean value) {
      return value ? "enabled" : "disabled";
   }
}
