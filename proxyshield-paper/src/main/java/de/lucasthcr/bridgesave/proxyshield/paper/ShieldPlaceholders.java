package de.lucasthcr.bridgesave.proxyshield.paper;

import de.lucasthcr.bridgesave.proxyshield.ProxyShieldCore;
import de.lucasthcr.bridgesave.proxyshield.check.CheckVerdict;
import de.lucasthcr.bridgesave.proxyshield.lookup.LookupResult;
import java.util.Locale;
import java.util.Optional;
import me.clip.placeholderapi.expansion.PlaceholderExpansion;
import org.bukkit.OfflinePlayer;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;
import org.jetbrains.annotations.NotNull;

/**
 * Exposes ProxyShield's state to PlaceholderAPI.
 * <p>
 * Every placeholder here reads the cache; none of them performs a lookup. Placeholders are resolved
 * on the main thread, often several times a second inside a scoreboard, so a blocking HTTP request
 * behind one would freeze the server rather than fill in a number.
 * <p>
 * Nothing outside {@code PaperMain#hookPlaceholders} may name this class: loading it resolves
 * {@link PlaceholderExpansion}, which does not exist without PlaceholderAPI installed. The caller
 * checks for the plugin first and never reaches this class otherwise.
 */
public final class ShieldPlaceholders extends PlaceholderExpansion {

   private final JavaPlugin plugin;
   private final ProxyShieldCore core;

   private ShieldPlaceholders(JavaPlugin plugin, ProxyShieldCore core) {
      this.plugin = plugin;
      this.core = core;
   }

   /**
    * Registers the expansion. Only called once PlaceholderAPI is known to be installed.
    *
    * @return a callback that unregisters it again, or {@code null} if it would not register
    */
   static Runnable register(JavaPlugin plugin, ProxyShieldCore core) {
      ShieldPlaceholders expansion = new ShieldPlaceholders(plugin, core);
      if (!expansion.register()) {
         plugin.getLogger().warning("PlaceholderAPI refused the ProxyShield expansion.");
         return null;
      }
      plugin.getLogger().info("Registered the PlaceholderAPI expansion (%proxyshield_...%).");
      return expansion::unregister;
   }

   @Override
   public @NotNull String getIdentifier() {
      return "proxyshield";
   }

   @Override
   public @NotNull String getAuthor() {
      return "LucasTHCR";
   }

   @Override
   public @NotNull String getVersion() {
      return plugin.getDescription().getVersion();
   }

   /** The expansion lives inside the plugin, so PlaceholderAPI must not unload it on its own. */
   @Override
   public boolean persist() {
      return true;
   }

   @Override
   public String onRequest(OfflinePlayer player, @NotNull String params) {
      String key = params.toLowerCase(Locale.ROOT);

      // ---- server wide
      switch (key) {
         case "checked" -> {
            return String.valueOf(core.statistics().checked());
         }
         case "blocked" -> {
            return String.valueOf(core.statistics().blocked());
         }
         case "blocked_proxy" -> {
            return String.valueOf(core.statistics().count(CheckVerdict.Reason.PROXY));
         }
         case "blocked_hosting" -> {
            return String.valueOf(core.statistics().count(CheckVerdict.Reason.HOSTING));
         }
         case "blocked_country" -> {
            return String.valueOf(core.statistics().count(CheckVerdict.Reason.COUNTRY));
         }
         case "uptime" -> {
            return core.statistics().uptimeFormatted();
         }
         case "mode" -> {
            return core.config().lookupMode().name().toLowerCase(Locale.ROOT);
         }
         case "providers" -> {
            return String.valueOf(core.lookups().providerCount());
         }
         case "storage" -> {
            return core.storage().name();
         }
         case "cache_size" -> {
            return String.valueOf(core.lookups().cacheSize());
         }
         case "dry_run" -> {
            return bool(core.config().dryRun());
         }
         case "trusted_players" -> {
            return String.valueOf(core.trust().size());
         }
         case "list_ranges" -> {
            return String.valueOf(core.lists().ranges().rangeCount());
         }
         default -> {
            // Falls through to the per-player placeholders below.
         }
      }

      if (player == null) {
         return "";
      }

      // ---- about the player's own address
      if (key.equals("trusted")) {
         return bool(core.trust().trusted(player.getUniqueId(), core.config().trustMinLogins(),
               core.config().trustMinDays()));
      }

      Optional<LookupResult> cached = addressOf(player).flatMap(core.lookups()::cached);
      if (cached.isEmpty()) {
         return switch (key) {
            case "country", "isp", "asn", "type", "score", "is_proxy", "is_hosting", "sources" ->
                  "unknown";
            default -> null;
         };
      }

      LookupResult result = cached.get();
      return switch (key) {
         case "country" -> result.countryOrUnknown();
         case "country_name" -> result.countryName() == null ? "unknown" : result.countryName();
         case "isp" -> result.ispOrUnknown();
         case "asn" -> result.asnOrUnknown();
         case "type" -> result.connectionType() == null ? "unknown" : result.connectionType();
         case "score" -> String.format(Locale.ROOT, "%.1f", result.confidence());
         case "is_proxy" -> bool(result.proxy() || result.tor());
         case "is_hosting" -> bool(result.hosting());
         case "sources" -> result.sourceSummary();
         default -> null;
      };
   }

   private Optional<String> addressOf(OfflinePlayer player) {
      Player online = player.getPlayer();
      if (online == null || online.getAddress() == null
            || online.getAddress().getAddress() == null) {
         return Optional.empty();
      }
      return Optional.of(online.getAddress().getAddress().getHostAddress());
   }

   private String bool(boolean value) {
      return value ? "yes" : "no";
   }
}
