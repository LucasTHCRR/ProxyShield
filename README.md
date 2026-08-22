# ProxyShield

[![Chat with us on Discord](https://raw.githubusercontent.com/intergrav/devins-badges/v3/assets/cozy/social/discord-plural_vector.svg)](https://dc.gg/paperstream)

Anti-VPN and anti-proxy protection for Minecraft servers. Country filtering, Discord webhook alerts,
a silent mode and a dry-run mode. One shared detection core, five native builds that behave
identically.

| Build | File | Runs on |
|---|---|---|
| Paper | `ProxyShield-Paper-2.1.jar` | Paper, Purpur and Spigot 1.21+ |
| Folia | `ProxyShield-Folia-2.1.jar` | Folia |
| BungeeCord | `ProxyShield-Bungee-2.1.jar` | BungeeCord / Waterfall |
| Velocity | `ProxyShield-Velocity-2.1.jar` | Velocity 3.3+ |
| Sponge | `ProxyShield-Sponge-2.1.jar` | SpongeAPI 17 |

The Paper and Folia jars are built from the same sources and are interchangeable — the scheduling
already uses the regionised API, so either one runs on either server. They exist separately because
server owners look for a jar named after their platform.

Spigot is supported by the same jar. Paper and Folia offer `AsyncScheduler`, a per-entity scheduler
and Adventure components; Spigot has none of the three. The jar picks an implementation at start-up,
and the Paper-only types live in a class that is never loaded on a server without them.

Install **one** jar, on the machine that accepts the connection. On a network that is the proxy
(BungeeCord or Velocity) — the Paper build behind a proxy would only ever see the proxy's own
address.

---

## Features

**Detection**

- Public VPN and proxy IP feeds with correct CIDR matching, IPv4 and IPv6
- Live provider lookup for proxy, VPN, Tor and datacenter flags, with failover across providers
- Country filtering, blacklist or whitelist mode
- Manual blacklist, checked before the feeds and the provider
- Configurable fail-open or fail-closed behaviour when a check cannot complete

**Exemptions**

- IP whitelist accepting single addresses, CIDR blocks and ranges
- Player name whitelist
- Bypass permission
- Loopback and private addresses are never checked, and never cost lookup quota
- Bedrock players joining through Geyser/Floodgate are exempt by default

**Operations**

- Dry-run mode: detect and report without disconnecting anybody
- Silent mode: no staff or console alerts, while the log file and webhook keep recording
- Discord webhook with queueing, retry and rate-limit handling
- Block log at `plugins/ProxyShield/blocks.log`
- Full `/proxyshield` command set with tab completion
- English and German out of the box, any language by copying one file

---

## Getting started

1. Drop the jar for your platform into `plugins/` and start the server once.
2. Edit `plugins/ProxyShield/config.yml`.
3. Run `/proxyshield reload`.

Recommended first run: leave `detection.dry-run: true` for a day and watch `blocks.log`. It records
what *would* have been blocked without disconnecting anybody, which is the cheapest way to find false
positives before they hit real players.

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

### Discord webhook

```yaml
discord:
  enabled: true
  webhook-url: "https://discord.com/api/webhooks/…"
  show-ip: true
```

`show-ip: false` posts `hidden` instead of the address. Only `https://` URLs are accepted.

### Language

All player facing text lives in `messages_en.yml` and `messages_de.yml`. Point `settings.language` at
the one you want. For another language, copy a file to `messages_<code>.yml`, translate it and set
`settings.language: <code>`. Any key you delete falls back to the built-in English, so a message file
from an older version keeps working after an update.

---

## Commands

All of these need `proxyshield.admin`. Aliases: `/ps`, `/antivpn`.

| Command | Does |
|---|---|
| `/proxyshield info` | Version, active mode and list status |
| `/proxyshield stats` | Detection counters, cache and webhook state |
| `/proxyshield check <player\|ip>` | Runs the full pipeline and explains the verdict |
| `/proxyshield lookup <player\|ip>` | Fresh provider lookup, ignoring the cache |
| `/proxyshield whitelist <add\|remove\|list> [entry]` | Manage the never-block list |
| `/proxyshield blacklist <add\|remove\|list> [entry]` | Manage the always-block list |
| `/proxyshield refresh` | Re-download the feeds |
| `/proxyshield recheck` | Re-check everyone online, disconnect whoever fails |
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
| 5 | IP in `blacklist.ips` | **block** | none |
| 7 | IP in a downloaded feed | **block** | ~0.6 µs |
| 8 | Provider reports `proxy` | **block** | one HTTP request per uncached IP |
| 9 | Provider reports `hosting` | **block** | same request |
| 10 | Country not permitted | **block** | same request |

Steps 1 to 7 never touch the network. Step 7 onwards costs one provider request per address that is
not in the cache, which is why the cache TTL matters more than the rate limit on most servers.

### Performance

Measured with the four default feeds (62,555 entries compiled into 35,161 merged ranges):

| | |
|---|---|
| Memory held | 1.3 MB |
| Startup parse | 259 ms, on an async thread |
| Feed check per login | 589 ns |
| 1000 logins | 0.59 ms total, about 1/85th of one tick |

The provider lookup is the only part with real latency: typically 50–200 ms, capped by
`api.timeout-seconds`. It runs off the main thread on every platform, so it delays that one player's
login and never the server tick. Set `detection.use-api: false` for a pure feed setup with zero
network traffic per login.

---

## Building

Requires JDK 21 and Maven.

```bash
mvn clean package
```

The five plugin jars land in `proxyshield-*/target/`. Tests run as part of the build.

### Module layout

```
proxyshield-common     detection core, no platform APIs, 124 tests
proxyshield-paper      Bukkit adapter    → AsyncPlayerPreLoginEvent, Paper/Folia/Spigot
proxyshield-folia      same sources as proxyshield-paper, own descriptor and jar name
proxyshield-bungee     Bungee adapter    → LoginEvent with intents
proxyshield-velocity   Velocity adapter  → LoginEvent with EventTask.async
proxyshield-sponge     Sponge adapter    → ServerSideConnectionEvent.Auth
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
