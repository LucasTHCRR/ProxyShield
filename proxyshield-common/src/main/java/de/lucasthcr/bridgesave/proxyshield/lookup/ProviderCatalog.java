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

package de.lucasthcr.bridgesave.proxyshield.lookup;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Every IP intelligence service ProxyShield knows how to read, keyed by the short id an operator
 * writes in config.yml.
 * <p>
 * Each entry states its own field paths, so a service is enabled with one line rather than a URL
 * and a hope that the generic parser guesses right. Services needing a key are listed too and stay
 * inert until one is configured, which keeps the config a menu of everything available instead of
 * a list of what happened to be free on the day it was written.
 * <p>
 * Weights are the default trust for the consensus engine: services that resolve a dedicated
 * fraud/VPN dataset carry more than ones that only expose a hosting flag.
 */
public final class ProviderCatalog {

   private static final Map<String, ProviderDefinition> BUILT_IN = build();

   private ProviderCatalog() {
   }

   /** The definition for {@code id}, or {@code null} when the catalog has no such service. */
   public static ProviderDefinition byId(String id) {
      return id == null ? null : BUILT_IN.get(id.trim().toLowerCase(Locale.ROOT));
   }

   public static boolean contains(String id) {
      return byId(id) != null;
   }

   public static Collection<ProviderDefinition> all() {
      return BUILT_IN.values();
   }

   public static Collection<String> ids() {
      return BUILT_IN.keySet();
   }

   private static Map<String, ProviderDefinition> build() {
      Map<String, ProviderDefinition> catalog = new LinkedHashMap<>();

      // ---------------------------------------------------------------- no key needed

      // ip-api.com serves HTTPS on paid plans only, hence the plain http.
      put(catalog, ProviderDefinition.builder("ip-api",
                  "http://ip-api.com/json/{ip}"
                        + "?fields=status,message,proxy,hosting,countryCode,country,isp,as")
            .proxy("proxy")
            .hosting("hosting")
            .country("countryCode")
            .countryName("country")
            .isp("isp")
            .asn("as")
            .errors("message")
            .rateLimit(45)
            .weight(1.0)
            .build());

      // Answers a single character: Y listed, N clean, E error.
      put(catalog, ProviderDefinition.builder("blackbox",
                  "https://blackbox.ipinfo.app/api/v1/{ip}")
            .plain("y")
            .weight(1.0)
            .rateLimit(120)
            .build());

      put(catalog, ProviderDefinition.builder("iprisk", "https://api.iprisk.info/v1/{ip}")
            .proxy("vpn", "open_proxy")
            .hosting("data_center")
            .country("country")
            .asn("asn")
            .weight(1.0)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("ipquery",
                  "https://api.ipquery.io/{ip}?format=json")
            .proxy("risk.is_vpn", "risk.is_proxy", "risk.is_tor")
            .hosting("risk.is_datacenter")
            .tor("risk.is_tor")
            .country("location.country_code")
            .countryName("location.country")
            .isp("isp.isp")
            .asn("isp.asn")
            .weight(1.0)
            .rateLimit(60)
            .build());

      // Without a key ipapi.is answers on its anonymous tier, which is eleven flat keys and none
      // of the risk fields: no is_vpn, no is_datacenter, and company and asn are plain strings
      // rather than objects. The flat paths are listed after the documented ones so a keyed
      // install is unaffected and an unkeyed one still contributes the country, the ISP and the
      // network instead of failing outright. It cannot contribute a VPN verdict either way, which
      // is what warnIfVerdictless reports at start-up.
      put(catalog, ProviderDefinition.builder("ipapi-is", "https://api.ipapi.is/?q={ip}&key={key}")
            .optionalKey()
            .proxy("is_proxy", "is_vpn", "is_tor", "is_abuser")
            .hosting("is_datacenter")
            .tor("is_tor")
            .country("location.country_code")
            .countryName("location.country", "country")
            .isp("asn.org", "company")
            .asn("asn.asn", "asn")
            .connectionType("company.type")
            .weight(1.5)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("iplocate",
                  "https://iplocate.io/api/lookup/{ip}?apikey={key}")
            .optionalKey()
            .proxy("privacy.is_proxy", "privacy.is_vpn", "privacy.is_tor")
            .hosting("privacy.is_hosting")
            .tor("privacy.is_tor")
            .country("country_code")
            .countryName("country")
            .isp("asn.name")
            .asn("asn.asn")
            .connectionType("asn.type")
            .weight(1.5)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("freeipapi", "https://freeipapi.com/api/json/{ip}")
            .proxy("isProxy")
            .country("countryCode")
            .countryName("countryName")
            .weight(1.0)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("funkemunky", "https://funkemunky.cc/vpn?ip={ip}")
            .optionalKey()
            .proxy("proxy", "vpn")
            .hosting("data_center")
            .country("countryCode", "country_code")
            .isp("isp")
            .weight(1.0)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("negativity", "https://api.negativity.fr/ip/{ip}")
            .proxy("proxy", "vpn")
            .hosting("hosting")
            .country("countryCode", "country_code")
            .weight(1.0)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("fastasfuck",
                  "https://api.fastasfuck.net/vpn/check/{ip}")
            .proxy("isVPN")
            .weight(1.0)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("zombiebot",
                  "https://antivpn.zombiebot.pl/check/{ip}")
            .proxy("vpn")
            .weight(1.0)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("rayzs",
                  "https://www.rayzs.de/provpn/api/proxy.php/?a={ip}")
            .plain("true", "1", "yes")
            .weight(1.0)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("marvinmc", "https://marvinmc.dev/proxy?ip={ip}")
            .plain("true", "1", "yes")
            .weight(1.0)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("ip-check",
                  "https://ip-check.net/api/proxy-detect.php?ip={ip}")
            .plain("true", "1", "yes")
            .weight(1.0)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("zowi", "https://api.zowi.gay/{ip}?key={key}")
            .optionalKey()
            .proxy("security.vpn.detected", "security.proxy",
                  "security.residential_proxy.detected")
            .hosting("security.hosting")
            .country("location.country_code")
            .weight(1.5)
            .rateLimit(60)
            .build());

      // ---------------------------------------------------------------- key needed

      // Works without a key at a much lower daily limit, so the key stays optional.
      put(catalog, ProviderDefinition.builder("proxycheck",
                  "https://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1&key={key}")
            .optionalKey()
            .nestedByIp()
            .proxy("proxy")
            .country("isocode")
            .countryName("country")
            .isp("provider", "organisation")
            .asn("asn")
            .connectionType("type")
            .score("risk", 66)
            .errors("error")
            .weight(2.0)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("ipqualityscore",
                  "https://www.ipqualityscore.com/api/json/ip/{key}/{ip}"
                        + "?strictness=1&allow_public_access_points=true")
            .urlKey()
            .proxy("proxy", "vpn", "tor", "active_vpn", "active_tor")
            .hosting("is_crawler")
            .tor("tor", "active_tor")
            .country("country_code")
            .isp("ISP")
            .asn("ASN")
            .connectionType("connection_type")
            .score("fraud_score", 85)
            .errors("message")
            .weight(2.5)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("vpnapi", "https://vpnapi.io/api/{ip}?key={key}")
            .urlKey()
            .proxy("security.vpn", "security.proxy", "security.tor", "security.relay")
            .tor("security.tor")
            .country("location.country_code")
            .countryName("location.country")
            .weight(2.0)
            .rateLimit(60)
            .build());

      // block: 0 residential, 1 non-residential (block), 2 unclear. Only 1 is a real detection,
      // which is why this reads the number instead of treating any non-zero as a hit.
      put(catalog, ProviderDefinition.builder("iphub", "https://v2.api.iphub.info/ip/{ip}")
            .headerKey("X-Key")
            .country("countryCode")
            .isp("isp")
            .asn("asn")
            .score("block", 1, 1)
            .weight(2.0)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("iphunter",
                  "https://www.iphunter.info:8082/v1/ip/{ip}")
            .headerKey("X-Key")
            .proxy("data.block")
            .country("data.country_code")
            .isp("data.isp")
            .asn("data.asn")
            .weight(2.0)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("ip2location",
                  "https://api.ip2location.io/?key={key}&ip={ip}")
            .urlKey()
            .proxy("is_proxy", "proxy.is_vpn", "proxy.is_tor")
            .hosting("proxy.is_data_center")
            .tor("proxy.is_tor")
            .country("country_code")
            .countryName("country_name")
            .isp("as")
            .asn("asn")
            .connectionType("usage_type")
            .weight(2.0)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("vpnblocker",
                  "https://api.vpnblocker.net/v2/json/{ip}/{key}")
            .urlKey()
            .proxy("host-ip")
            .hosting("host-ip")
            .country("country-code")
            .asn("asn")
            .weight(1.5)
            .rateLimit(60)
            .build());

      // "key" here is the contact e-mail address getipintel requires; result is a probability.
      put(catalog, ProviderDefinition.builder("getipintel",
                  "https://check.getipintel.net/check.php?ip={ip}&contact={key}&format=json")
            .urlKey()
            .score("result", 0.95)
            .errors("message")
            .weight(2.0)
            .rateLimit(15)
            .build());

      put(catalog, ProviderDefinition.builder("antivpn-io",
                  "https://api.antivpn.io/v2/check?ip={ip}&key={key}")
            .urlKey()
            .proxy("proxy", "vpn", "tor")
            .hosting("hosting")
            .tor("tor")
            .country("country")
            .score("risk_score", 70)
            .weight(2.0)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("2ip", "https://api.2ip.io/{ip}?token={key}")
            .urlKey()
            .hosting("asn.hosting")
            .proxy("asn.proxy")
            .country("location.country_code")
            .asn("asn.number")
            .weight(1.5)
            .rateLimit(60)
            .build());

      put(catalog, ProviderDefinition.builder("abuseipdb",
                  "https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90")
            .headerKey("Key")
            .proxy("data.isTor")
            .tor("data.isTor")
            .country("data.countryCode")
            .isp("data.isp")
            .connectionType("data.usageType")
            .score("data.abuseConfidenceScore", 75)
            .weight(1.5)
            .rateLimit(60)
            .build());

      return Map.copyOf(catalog);
   }

   private static void put(Map<String, ProviderDefinition> catalog, ProviderDefinition provider) {
      catalog.put(provider.id(), provider);
   }
}
