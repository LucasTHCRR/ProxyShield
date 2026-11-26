<div align="center">

[![Discord](https://img.shields.io/badge/Discord-dc.gg%2Fpaperstream-5865F2?style=flat-square&logo=discord&logoColor=white)](https://dc.gg/paperstream)
[![Release](https://img.shields.io/modrinth/v/proxyshield?style=flat-square&label=release&color=00AF5C)](https://modrinth.com/plugin/proxyshield/versions)
[![Downloads](https://img.shields.io/modrinth/dt/proxyshield?style=flat-square&label=downloads&color=00AF5C)](https://modrinth.com/plugin/proxyshield)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square)](https://www.gnu.org/licenses/gpl-3.0.txt)

[![Built with Java 21](https://raw.githubusercontent.com/intergrav/devins-badges/v3/assets/cozy/built-with/java21_vector.svg)](https://adoptium.net/)
[![Available for Paper](https://raw.githubusercontent.com/intergrav/devins-badges/v3/assets/cozy/supported/paper_vector.svg)](https://papermc.io/)
[![Available for Purpur](https://raw.githubusercontent.com/intergrav/devins-badges/v3/assets/cozy/supported/purpur_vector.svg)](https://purpurmc.org/)
[![Available for Spigot](https://raw.githubusercontent.com/intergrav/devins-badges/v3/assets/cozy/supported/spigot_vector.svg)](https://www.spigotmc.org/)
[![Available for Bukkit](https://raw.githubusercontent.com/intergrav/devins-badges/v3/assets/cozy/supported/bukkit_vector.svg)](https://dev.bukkit.org/)
[![Available for Folia](https://codeberg.org/LucasTHCR/ProxyShield/raw/branch/master/assets/badges/folia_vector.svg)](https://papermc.io/software/folia)
[![Available for Sponge](https://raw.githubusercontent.com/intergrav/devins-badges/v3/assets/cozy/supported/sponge_vector.svg)](https://spongepowered.org/)
[![Available for BungeeCord](https://raw.githubusercontent.com/intergrav/devins-badges/v3/assets/cozy/supported/bungeecord_vector.svg)](https://www.spigotmc.org/wiki/bungeecord/)
[![Available for Waterfall](https://raw.githubusercontent.com/intergrav/devins-badges/v3/assets/cozy/supported/waterfall_vector.svg)](https://papermc.io/software/waterfall)
[![Available for Velocity](https://raw.githubusercontent.com/intergrav/devins-badges/v3/assets/cozy/supported/velocity_vector.svg)](https://papermc.io/software/velocity)

[![Watch us on YouTube](https://raw.githubusercontent.com/intergrav/devins-badges/v3/assets/cozy/social/youtube-plural_vector.svg)](https://www.youtube.com/watch?v=p5o02yoP04Q)
[![Chat with us on Discord](https://raw.githubusercontent.com/intergrav/devins-badges/v3/assets/cozy/social/discord-plural_vector.svg)](https://dc.gg/paperstream)
[![Available on Codeberg](https://raw.githubusercontent.com/intergrav/devins-badges/v3/assets/cozy/available/codeberg_vector.svg)](https://codeberg.org/LucasTHCR/ProxyShield)

</div>

# ProxyShield

Anti-VPN and anti-proxy protection for Minecraft servers. Country filtering, Discord webhook alerts,
a silent mode and a dry-run mode. One shared detection core that behaves identically everywhere.

Since 3.1 it comes with its own free detection service, [PaperStream Intel](https://paperstream.dev/api),
which is switched on out of the box: no key, no account, and a daily built network feed that keeps
working when the free services run out of quota.

## Download

There is one file for every platform: `ProxyShield-Universal-<version>.jar`.

| Runs on | Put it in |
|---|---|
| Paper, Purpur and Spigot 1.21+, Folia | `plugins/` |
| BungeeCord / Waterfall | `plugins/` |
| Velocity 3.3+ | `plugins/` |
| Sponge (SpongeAPI 17) | `mods/` |

The jar carries all four entry points and all four plugin descriptors at once. Every server reads
the descriptor it knows and ignores the rest, so the same file works on a single server and on a
whole network. Versions before 3.0.2 were also published as one jar per platform. Those files are
still listed under the older releases.

Spigot is supported by the same jar. Paper and Folia offer `AsyncScheduler`, a per-entity scheduler
and Adventure components; Spigot has none of the three. The jar picks an implementation at start-up,
and the Paper-only types live in a class that is never loaded on a server without them.

Install **one** jar, on the machine that accepts the connection. On a network that is the proxy
(BungeeCord or Velocity). The Paper build behind a proxy would only ever see the proxy's own
address.

---

**[Watch ProxyShield in action](https://www.youtube.com/watch?v=p5o02yoP04Q)** - a short demonstration of the checks, the verdict and what a blocked connection looks like.

## Features

**Detection**

- 27 IP intelligence services built in, enabled by name - 16 of them need no API key at all
- PaperStream Intel as the first provider: network type, country and ASN from a daily feed, VPN,
  proxy and Tor lists, and addresses other ProxyShield servers reported
- The server lists that VPN operators publish themselves (Mullvad, IVPN, NordVPN, Private Internet
  Access), including IPv6 relays that no public list knows. A hit refuses the player at once
- Offline network feed: home and mobile networks are told apart from hosting networks without a
  request per player, so a quota that runs out does not open the door
- Consensus scoring: several providers are asked at once and their weights added up, so one service
  that has never heard of a VPN cannot clear it, and one noisy service cannot kick anybody alone
- Public VPN, datacenter and Tor exit feeds with correct CIDR matching, IPv4 and IPv6
- Network (ASN) block and allow rules, which catch a VPN's new range before any feed lists it,
  plus downloadable ASN lists that refresh on their own
- ISP filter with regular expressions, to block a hoster or always admit a mobile carrier
- Conditions on any provider's answer (`risk.score >= 85`, `connection.type = mobile`) and
  custom request headers, so an unlisted service can be wired in exactly
- Bogon addresses refused outright
- Reverse DNS patterns as a signal - free, unlimited, and effective on ranges nobody has catalogued
- Behavioural heuristics: join rate per subnet, accounts per address, an account changing country
- Trust for regulars, so a tightened rule or a provider having a bad day does not kick your players
- Country filtering, blacklist or whitelist mode
- Manual blacklist, checked before everything else
- Connection limit per address, by players online or within a time window
- Configurable fail-open or fail-closed behaviour when a check cannot complete
- Automatic fast admit: while many players join at once, addresses in home networks skip the
  provider lookup and keep the quota for the rest, so a join wave does not wear the services out

**Exemptions**

- IP whitelist accepting single addresses, CIDR blocks and ranges
- Player name whitelist
- Bypass permission
- Loopback and private addresses are never checked, and never cost lookup quota
- Bedrock players joining through Geyser/Floodgate are exempt by default

**Operations**

- Dry-run mode: detect and report without disconnecting anybody
- Passive mode: no checks at login, lookups on demand only
- Restricted servers on BungeeCord and Velocity: keep a flagged player in the lobby instead of
  disconnecting them
- Whitelist and blacklist entries with a reason and an expiry
- `/proxyshield alts` lists every account seen on the same address
- Debug output with every provider's raw answer
- Console commands on a detection, so a flagged player can be marked or restricted instead of kicked
- `/proxyshield check` shows what every single provider said, so a false positive can be traced
- Lookup cache survives restarts and reloads; simultaneous logins from one address share one query
- Shared storage for a network: MySQL, MariaDB, PostgreSQL, SQLite, H2 or Redis
- PlaceholderAPI support and anonymous bStats metrics
- Silent mode: no staff or console alerts, while the log file and webhook keep recording
- Discord webhook with queueing, retry and rate-limit handling, and a layout you write yourself
- Telegram and VK alerts
- Block log at `plugins/ProxyShield/blocks.log`
- Full `/proxyshield` command set with tab completion
- Update check in the console (once every 12 hours, nothing about your server is sent) and on
  request with `/proxyshield update`; on Paper, Folia and Spigot the new jar can be downloaded into
  the update folder automatically, if you switch that on
- `config.yml` upgrades itself on start: new options appear with their comments, nothing you
  deleted comes back and no value you changed is touched
- Optional reporting to PaperStream Intel, off by default
- English and German out of the box, any language by copying one file

---

## Getting started

1. Drop the jar into `plugins/` (`mods/` on Sponge) and start the server once.
2. Edit `plugins/ProxyShield/config.yml`.
3. Run `/proxyshield reload`.

Recommended first run: leave `detection.dry-run: true` for a day and watch `blocks.log`. It records
what *would* have been blocked without disconnecting anybody, which is the cheapest way to find false
positives before they hit real players.

### Providers and scoring

Enable a service by name. The fifteen listed as free need no key at all:

```yaml
api:
  mode: consensus          # or failover
  required-score: 1.5
  providers:
    ip-api:     { enabled: true, weight: 1.0 }
    blackbox:   { enabled: true, weight: 1.0 }
    ipapi-is:   { enabled: true, weight: 1.5 }
    proxycheck: { enabled: false, weight: 2.0, key: "" }
```

In consensus mode every enabled provider is asked at once and the weights of those flagging the
address are added up. At `required-score: 1.5` a single strong provider is enough, or any two weaker
ones, or one weak provider plus a reverse DNS hit. Raise it to 2.5 if you would rather miss a VPN
than kick a real player; lower it to 1.0 to block on any single hit.

This does not multiply your quota the way it looks. Answers are cached (IPv6 folded to its /64),
simultaneous logins from one address share one lookup, the fan-out stops the moment the score is
reached, the cache survives restarts and reloads, and a provider that starts failing is dropped from
the rotation until it recovers.

A service the catalog does not know can be described directly in `config.yml` with a URL and dotted
field paths - see the commented example at the bottom of the `providers` section.

### PaperStream Intel

PaperStream Intel is our own free anti-VPN service. ProxyShield downloads a signed copy of its data
every 4 hours (`detection.intel`, about 10 MB) and looks addresses up on the server itself, in
microseconds and without sending the player's address anywhere. VPN servers, Tor exits and open
proxies are refused right there, before any provider is asked. A copy ships inside the jar, so a
fresh install is protected from the first second. Hosting ranges and private relays (iCloud, WARP)
never refuse a player on their own.

The data comes from the server lists the VPN operators publish, the official Tor and cloud ranges,
a nightly network feed, more than fifty public VPN, proxy and datacenter lists, and the addresses
other ProxyShield servers reported. The service is also the first online provider, for the
addresses the local copy does not know. No key and no account.

- Look up any address or test your own connection: [paperstream.dev/vpn](https://paperstream.dev/vpn)
- API for your own plugin, bot or website: [paperstream.dev/api](https://paperstream.dev/api)

**Reporting is optional and off by default.** With `reporting.enabled: true` the addresses that the
providers refused as proxies are sent in batches every 10 minutes, together with a random install
id. No player names, no UUIDs, no server address. The service keeps them for 14 days and counts on
how many servers an address showed up; from 3 servers it votes "proxy" for everybody.
`/proxyshield reporting` shows the state and `/proxyshield reporting forget` deletes everything that
was sent. Details are in the [privacy policy](https://paperstream.dev/datenschutz).

### Country filtering

```yaml
country:
  enabled: true
  mode: whitelist        # only these countries may connect
  codes: ["DE", "AT", "CH"]
  block-unknown: false
```

Set `mode: blacklist` to invert it. Country data comes from the lookup provider, so `country.enabled`
triggers a provider query even when `detection.use-api` is off.

### Silent mode

```yaml
notifications:
  silent: true
```

Suppresses the staff broadcast and the console line. The log file and the webhook still record every
detection, so you keep the data without announcing to everyone online that the filter fired.

### Commands on a detection

Not every server wants a flagged player gone. To mark them instead, run whatever you would have run
by hand:

```yaml
detection:
  dry-run: true

actions:
  on-flag:
    - "lp user {player} permission set myserver.vpnflagged true"
    - "webhook {player} flagged {reason} from {ip}"
  delay-seconds: 3
  run-when: always
```

With `dry-run` on, the detection still fires, the alert and the webhook still go out and these
commands still run, but the player stays connected. That is the flag-instead-of-kick setup: put them
in a restricted group, make them verify through Discord, hand the name to another plugin.

Commands run as the console, with or without a leading slash. Available placeholders are
`{player}`, `{uuid}`, `{ip}`, `{reason}`, `{reason_id}`, `{country}`, `{isp}`, `{asn}`, `{score}`,
`{sources}`, `{action}` and `{platform}`.

`delay-seconds` matters more than it looks. A connection is judged before the player is on the
server, so at `0` the commands run while they are still connecting. That is fine for a permission
grant or a webhook, but anything that needs them actually online, such as messaging them or
prompting them to link an account, needs a few seconds here.

`run-when` accepts `always`, `kicked` or `allowed` when the commands should only fire for players
who were disconnected, or only for those who were not.

### Discord webhook

```yaml
discord:
  enabled: true
  webhook-url: "https://discord.com/api/webhooks/..."
  show-ip: true
```

`show-ip: false` posts `hidden` instead of the address. Only `https://` URLs are accepted.

The message layout is yours to write. By default it is a title and six inline boxes; clear the
fields and write a description instead:

```yaml
discord:
  embed:
    title: "`{player}`"
    description: |
      ```ansi
      IP: `{ip}`
      Country: {country}
      Action: {action}
      ```
    thumbnail: "https://your-server.example/alert.gif"
    fields: {}
```

Placeholders: `{player}` `{uuid}` `{ip}` `{reason}` `{country}` `{isp}` `{asn}` `{score}`
`{sources}` `{platform}` `{version}` `{action}` `{action_id}`. Fields are named entries and appear
in the order written.

Values go in exactly as written, so you place the backticks. Discord parses embed text as Markdown
and an underscore is a legal Minecraft name character, so without a code span `Some_Name` shows up
italic and `__Name__` underlined with the underscores gone. Deleting the whole `embed` section
keeps the layout from before 2.4.

### Storage on a network

One server needs no setup - verdicts and trust live in two files. A network of several proxies
should share them, so each address is looked up once for the whole network instead of once per
proxy:

```yaml
storage:
  type: redis            # or mysql, mariadb, postgresql, sqlite, h2, file, memory
  redis:
    host: "127.0.0.1"
    port: 6379
    password: ""
```

Redis also pushes invalidations: whitelisting an address or running `/proxyshield clearcache` on one
proxy takes effect on the others immediately, rather than when the entry expires.

ProxyShield bundles no database driver and no Redis library, so nothing is relocated into a server
that did not ask for it. Most Bukkit servers already have a MySQL and a SQLite driver; if yours does
not, drop the driver jar into the ProxyShield folder and name it under `storage.sql.driver-path`. If
the store cannot be reached, the plugin says so once and falls back to file storage - a database
outage never becomes a login outage.

### PlaceholderAPI

Available on the Bukkit builds when PlaceholderAPI is installed. Every placeholder reads the cache,
so none of them can stall the main thread:

| Placeholder | Shows |
|---|---|
| `%proxyshield_blocked%` / `%proxyshield_checked%` | Counters since start-up |
| `%proxyshield_blocked_proxy%` / `%proxyshield_blocked_hosting%` / `%proxyshield_blocked_country%` | Blocks by reason |
| `%proxyshield_country%` / `%proxyshield_isp%` / `%proxyshield_asn%` | The player's own address |
| `%proxyshield_is_proxy%` / `%proxyshield_is_hosting%` / `%proxyshield_score%` | The verdict on it |
| `%proxyshield_sources%` | Which services flagged it |
| `%proxyshield_trusted%` | Whether the player has earned an exemption |
| `%proxyshield_mode%` / `%proxyshield_providers%` / `%proxyshield_storage%` | How the plugin is set up |
| `%proxyshield_cache_size%` / `%proxyshield_trusted_players%` / `%proxyshield_uptime%` | Live state |

### Metrics

Anonymous statistics through bStats: server count, platform, Java version and which ProxyShield
settings are in use. No addresses and no player data. Public at
[bstats.org](https://bstats.org/plugin/bukkit/ProxyShield/33736), and switched off with
`metrics.enabled: false`.

### API for other plugins

```java
if (ProxyShieldApi.isAvailable() && ProxyShieldApi.isProxy(address)) {
    // cache-only, safe on the main thread
}

LookupResult result = ProxyShieldApi.lookup(address);   // blocking, async only
boolean regular = ProxyShieldApi.isTrusted(uuid);
```

`de.lucasthcr.bridgesave.proxyshield.api.ProxyShieldApi` is read-only: it answers questions, it never
changes a verdict or disconnects anybody.

### Language

All player facing text lives in `messages_en.yml` and `messages_de.yml`. Point `settings.language` at
the one you want. For another language, copy a file to `messages_<code>.yml`, translate it and set
`settings.language: <code>`. Any key you delete falls back to the built-in English, so a message file
from an older version keeps working after an update.

---

### Who receives a player's address

Out of the box an address leaves the server only when the local data does not decide it:

| Recipient | When | Note |
|---|---|---|
| PaperStream Intel (intel.paperstream.dev) | unknown addresses, `/proxyshield report` | our own service, no logs of lookups, [privacy policy](https://paperstream.dev/datenschutz) |
| Zowi (api.zowi.gay) | unknown addresses | keyless, no published data processing agreement |
| IPQuery, Blackbox, ip-check.net, IPLocate | unknown addresses | keyless, no published data processing agreement |

Lists, the network feed and the Intel copy are downloads without any player data. Turning a provider
off under `providers` stops it from receiving addresses.

## Commands

All of these need `proxyshield.admin`. Aliases: `/ps`, `/antivpn`.

| Command | Does |
|---|---|
| `/proxyshield info` | Version, active mode, lookup mode and list status |
| `/proxyshield providers` | Every enabled service with its weight, health and latency |
| `/proxyshield stats` | Detection counters, cache and webhook state |
| `/proxyshield check <player\|ip>` | Runs the full pipeline and explains the verdict |
| `/proxyshield lookup <player\|ip>` | Fresh provider lookup, ignoring the cache |
| `/proxyshield whitelist <add\|remove\|info\|list\|purge> [entry] [time] [reason]` | Manage the never-block list |
| `/proxyshield blacklist <add\|remove\|info\|list\|purge> [entry] [time] [reason]` | Manage the always-block list |
| `/proxyshield alts <player\|ip>` | Every account seen on the same address |
| `/proxyshield refresh` | Re-download the feeds |
| `/proxyshield update [install]` | Check for a new version, `install` downloads it into the update folder |
| `/proxyshield reporting [forget]` | Show the state of reporting, `forget` deletes everything sent so far |
| `/proxyshield recheck` | Re-check everyone online, disconnect whoever fails |
| `/proxyshield allow <code> [minutes]` | Lets a refused player through for a while, with the code from the kick screen |
| `/proxyshield fpreport <player\|ip>` | Anonymous report for a wrongly blocked player (version, verdict, network, provider answers) |
| `/proxyshield doctor` | Checks the setup (data age, lists, providers, unchecked logins) and says what needs attention |
| `/proxyshield explain <player\|ip>` | Shows step by step why an address is refused or let in |
| `/proxyshield report <player\|ip> <vpn\|clean>` | Tells PaperStream Intel about a missed VPN or a wrong block |
| `/proxyshield clearcache` | Drop cached lookup results |
| `/proxyshield reload` | Re-read `config.yml` and the message file |

Entries added in game are stored in `whitelist.txt` and `blacklist.txt` and survive restarts.
Entries that came from `config.yml` have to be removed there.

`/proxyshield check` is the tool for a false-positive report: it walks the whole pipeline and prints
what each stage decided, so you can see exactly which rule fired.

## Permissions

| Node | Default | Grants |
|---|---|---|
| `proxyshield.bypass` | op | Skip every check |
| `proxyshield.notify` | op | Receive live block alerts |
| `proxyshield.admin` | op | Use `/proxyshield` |

On Paper, BungeeCord and Sponge no permission data exists yet during the login handshake, so
`proxyshield.bypass` only resolves for operators there. For reliable exemptions on those platforms
use `whitelist.players` or `whitelist.ips`. On Velocity the player object is available at
`LoginEvent` and the permission works normally.

---

## How a connection is decided

Strictly top to bottom, first match wins. Everything that can *allow* a player is evaluated before
anything that can block one, so an operator can always whitelist their way out of a false positive.

| # | Check | Result | Cost |
|---|---|---|---|
| 1 | `proxyshield.bypass` permission | allow | none |
| 2 | Name in `whitelist.players` | allow | none |
| 3 | IP in `whitelist.ips` | allow | none |
| 4 | Bedrock player via Floodgate | allow | none |
| 5 | Loopback or private address | allow | none |
| 6 | Bogon address | **block** | none |
| 7 | IP in `blacklist.ips` | **block** | none |
| 8 | IP in a downloaded feed | **block** | ~0.6 µs |
| 9 | Network (ASN) or ISP rule | allow or **block** | one HTTP request per uncached IP |
| 10 | Provider reports `proxy` | **block** | same request |
| 11 | Provider reports `hosting` | **block** | same request |
| 12 | Country not permitted | **block** | same request |
| 13 | Over the connection limit | **block** | none |

Steps 1 to 8 never touch the network. Step 9 onwards costs one provider request per address that is
not in the cache, which is why the cache TTL matters more than the rate limit on most servers.

### Performance

Measured with the four default feeds (62,555 entries compiled into 35,161 merged ranges):

| | |
|---|---|
| Memory held | 1.3 MB |
| Startup parse | 259 ms, on an async thread |
| Feed check per login | 589 ns |
| 1000 logins | 0.59 ms total, about 1/85th of one tick |

The provider lookup is the only part with real latency: typically 50 to 200 ms, capped by
`api.timeout-seconds`. It runs off the main thread on every platform, so it delays that one player's
login and never the server tick. Set `detection.use-api: false` for a pure feed setup with zero
network traffic per login.

---

## Building

Requires JDK 21 and Maven.

```bash
mvn clean package
```

The jars land in `proxyshield-*/target/`; `proxyshield-universal` holds the one that is published. Tests run as part of the build.

### Module layout

```
proxyshield-common     detection core, no platform APIs, 321 tests
proxyshield-paper      Bukkit adapter    -> AsyncPlayerPreLoginEvent, Paper/Folia/Spigot
proxyshield-folia      same sources as proxyshield-paper, own descriptor and jar name
proxyshield-bungee     Bungee adapter    -> LoginEvent with intents
proxyshield-velocity   Velocity adapter  -> LoginEvent with EventTask.async
proxyshield-sponge     Sponge adapter    -> ServerSideConnectionEvent.Auth
```

Each platform module shades `proxyshield-common`, so every jar is self-contained. The Velocity and
Sponge builds also bundle a relocated SnakeYAML, because neither exposes a YAML config API and both
read the same `config.yml` as the others.

`proxyshield-folia` adds no Java sources of its own. It pulls in `proxyshield-paper/src/main/java`
with `build-helper-maven-plugin`, so both jars are compiled from one copy of the code and a fix can
never land in only one of them.

### Tests

```bash
mvn -pl proxyshield-common test
```

Beyond the unit tests, two of them are worth knowing about: `ShieldConfigTest` parses the
`config.yml` that actually ships in the jar and asserts every value the reader expects, and
`MessagesTest` asserts that both bundled message files define exactly the keys the code looks up and
that no key or value is swallowed by YAML's boolean coercion. Both of those caught real defects
during development.

---

## Changes from 1.1

See [CHANGELOG.md](CHANGELOG.md). The short version: the IP feeds never matched anything in v1
because the CIDR prefix was thrown away, proxy detection was a substring test, the webhook payload
was injectable, and BungeeCord and Velocity did blocking work on the wrong thread.

The original 1.1 sources are kept under `legacy-1.1/` and the raw decompiler output under
`decompiled/` for reference.

## Licence

GPL-3.0, see [LICENSE](LICENSE).
