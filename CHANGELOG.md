# Changelog

## Unreleased

### Added

- **Appeal codes.** A refused player sees a short code on the kick screen ("PS-K7QM2"). A staff member enters
  `/proxyshield allow <code> [minutes]` and the address is let through for a while (default 60 minutes). It shows up on
  the whitelist with the reason "appeal <code>" and removes itself. Codes live in memory, the `appeal` section of the
  config switches them off or changes the times. Blacklisted and bogon addresses get no code.
- **`api.clean-settle-ms`** (off by default): an address in a home or mobile network can be let through after this
  many milliseconds on one clean answer. Measured: real players log in about a fifth faster, but open proxies in home
  networks are found less often, so it stays off unless you choose it.
- **`/proxyshield fpreport <player|ip>`** builds an anonymous report for a wrongly blocked player:
  version, verdict, network class, country, AS number, score, whether a list matched and what every
  provider said. It contains neither the address nor the player name. There is an issue template for
  it ("Wrongly blocked player").

### Changed

- **Runs on Java 17 now**, so the same jar also works on Paper, Purpur and Folia 1.18 to 1.20 (it needed Java 21 and
  Minecraft 1.21 before). The shared code is checked against the Java 17 library; tested on Paper 1.18.2 and 1.20.4
  (Java 17): start-up, lists, network feed and `/proxyshield check`. `api-version` in the plugin descriptor is 1.18.
- The start-up log now tells once that the optional reporting to PaperStream Intel is off and how to turn it on.
- Config comment for the Zowi provider: the keyless limit is now 250 requests a minute per address (was 150).
  The built-in limit of 120 a minute stays as it was.

## 3.1.0-RELEASE

### Added

- **PaperStream intel service as a provider.** `paperstream` is a new default provider, first in
  the list. It answers from a daily built network feed, the public VPN, datacenter, Tor and proxy
  lists and the addresses other ProxyShield servers reported. No key, 600 requests a minute per
  address, open to everyone at intel.paperstream.dev.
- **Reporting, off by default.** With `reporting.enabled: true` the addresses refused as proxies
  by the providers are sent to the service together with a random install id, in batches every 10
  minutes. No player names, no UUIDs, no server address. The service keeps them for 14 days and
  counts on how many servers an address showed up; from 3 servers it votes "proxy" for everybody.
  `/proxyshield reporting` shows the state, `/proxyshield reporting forget` deletes everything
  sent so far and drops the install id.
- **Automatic fast admit.** `detection.network-data.fast-admit` is `auto` by default: while 20 or
  more players join within 10 seconds (`fast-admit-burst`), addresses in end-user networks skip the
  provider lookup and keep the quota for the rest. Outside a wave every join is checked in full.
  `always` and `never` are still available; the old `fast-admit-end-user: true` counts as `always`.
- **Relay list from the VPN operators.** `lists.operator-relays` (on by default) adds the server
  addresses Mullvad, IVPN, NordVPN and PIA publish themselves, served by intel.paperstream.dev. A hit refuses
  the player at once, which also covers IPv6 relays that no public list knows.
- **Update checks.** The console is told when a newer ProxyShield is out (`updates.notify`, on by
  default): one small request every 12 hours to Modrinth, Hangar and Codeberg, nothing about the
  server is sent. `/proxyshield update` checks on demand. On Paper, Folia and Spigot,
  `updates.auto-update` (off by default) or `/proxyshield update install` downloads the new jar into
  the update folder, where the server applies it on the next restart; the running jar is never
  touched. Built on the open updater-api library (Apache-2.0).

- **config.yml upgrades itself.** On start, an existing config.yml gets the options a release really
  brought, in place and with its comments, and the old file is kept as `config.yml.bak`. Nothing an
  admin deleted comes back, and no value they edited is touched. The file carries a `version:`
  marker for this. Installs of 3.0.x get the `paperstream` provider and the `updates` and
  `reporting` sections that way.

### Changed

- **The network feed is on by default** for new installs: `detection.network-data.source` points at
  the feed of the service. Existing configs keep their value.
- **The feed covers every announced range** and has two more classes: `N` for networks where
  nobody was measured at all and `S` for small access networks. Both are only used for country
  and ASN. A network without measured users is no proof of hosting, so it is neither refused by
  `fallback-block-hosting` nor called hosting by the service.

### Tested

Started and joined with a bot on Paper 1.21.11 and Folia 1.21.11, started on Paper 26.3,
BungeeCord and Velocity, each with the update check. A Velocity proxy took 1,000 joins in 20
seconds with the provider quotas of the free services. Sponge was built and unit tested but not
started.

## 3.0.2-RELEASE

### Fixed

- **Velocity shows the real version.** The Velocity jar of 3.0.1 still introduced itself as 3.0.0
  in the plugin list and in the log, because the number was written into the code by hand. The
  build now fails when it differs from the version in the pom. Nothing else changed since 3.0.1.

## 3.0.1-RELEASE

### Fixed

- **Bursts of logins no longer queue behind each other.** The lookup pool was sized to the number
  of providers, so one login used all of it and every other login waited, some until the 6 second
  total timeout and then got in unchecked. `api.max-parallel` now sizes the pool (default 64, up to
  256). In a local join test, 21 of 60 joins in 6 seconds reached a provider before, all 60 now.

### Changed

- **Staged lookups.** A lookup now asks the first two providers (`api.first-wave`, 0 asks all at
  once) and stops there when both answer and neither flags the address. A flag, a failure or a slow
  answer brings in the rest. Providers that are out of quota or recovering are skipped instead of
  being asked and failing. An ordinary address costs two requests instead of five, so the free
  quotas serve about twice as many new addresses. The default provider order puts the strongest
  keyless ones first (blackbox, ip-check, iplocate, ip-api, iprisk).
- **Zowi's service is on by default, first in the list.** It was the strongest keyless provider in
  the public benchmark. The request uses `feature=security`, so only the verdict fields come back,
  and the provider limit is 120 a minute against the 150 the service allows per address. Existing
  configs keep their settings.
- **Open proxies are blocked from a list.** monosans/proxy-list (MIT, rebuilt hourly, about 1,300
  addresses) is a default list source. List entries may now be `socks5://1.2.3.4:1080`,
  `1.2.3.4:8080` or `[2001:db8::1]:8080`, only the address counts. proxifly's much larger,
  unverified list is in the config as a commented option.
- **Offline network data.** `detection.network-data.source` takes the URL of a feed file that marks
  end-user networks and hosting-like ones. It is read from disk, so a lookup costs no request.
  Two uses, both set under the same key: `fallback-block-hosting` (on) refuses a hosting-like
  network when no provider could answer, and `fast-admit-end-user` (off) skips the provider lookup
  for end-user networks and keeps the quota for the rest. The source is empty by default.
- **Redis no longer holds up the start or needs a reload.** With `storage.type: redis` the plugin
  answers from its local store at once and connects to Redis in the background, retrying every 5
  to 60 seconds. A start while Redis is down and a recovery afterwards both work without anybody
  touching the plugin.
- **Faster first start.** Without a cached list the download begins at once instead of after an
  8 second grace period, and the sources load side by side (at most three connections per host,
  the network feed alongside). A fresh install is protected about a second after it enables
  instead of 13.
- **A hosting flag alone no longer blocks.** `detection.hosting-min-score` (default 0.5) asks for
  at least that much score from other signals, so a provider tagging an ordinary ISP as hosting
  does not refuse a real player. Set it to 0 to block every hosting flag as before.
- **New default providers.** ip-check is on. ipapi.is (answers without flags when it has no key),
  IPQuery and FreeIPAPI (flagged no proxy in a public benchmark) are off, which saves requests.
  Existing configs keep their settings.

## 3.0.0

### Added

- **Rules on provider answers.** Every provider, listed or your own, takes a `conditions` block
  with named groups of `<field> <op> <value>` lines. A `bypass` group that matches clears every
  flag the provider raised, a `flag` group raises one the field mapping did not. Lines inside a
  group must all hold, any one group is enough. Numbers compare as numbers, text ignoring case,
  and a field missing from the answer never satisfies a line. An unreadable line is skipped with
  a warning at start-up instead of taking the whole config down.

- **Request headers per provider.** `headers:` adds any header to a provider's request, with
  `{key}` and `{ip}` filled in, for services that want `Authorization: Bearer ...` or similar.

- **`settings.debug`** prints every provider answer, raw body included, next to what was read
  from it. That is what you write conditions against.

- **ISP filter.** `detection.isp.blocked` and `detection.isp.allowed` take case-insensitive
  regular expressions matched against the provider's ISP name. An allowed ISP outranks the proxy
  and hosting flags, which makes it the place for a mobile carrier that keeps getting flagged.

- **Downloadable ASN lists.** `detection.asn.sources` takes https URLs serving a JSON array or
  plain text with one network per line. They refresh with the address feeds, and the last good
  download is kept in `asn-cache.txt`.

- **Bogon addresses are refused.** Documentation, benchmark, multicast and reserved ranges cannot
  belong to a real player; one of them at login means a forwarding layer was given a false
  address. Private and Tailscale ranges are not affected. `detection.block-bogon: false` turns it
  off.

- **Connection limit.** `limiter` caps accounts per address as a hard rule, either counting who is
  online right now or counting admissions inside a window such as `30m`, which resets on its own.
  Whitelisted, local and bypassing players never count. Off by default.

- **Restricted servers** on BungeeCord and Velocity. With `restricted.enabled`, a flagged player is
  not disconnected but kept on the backends you list, for example the lobby and the login server.
  On the first connect they are routed to the first allowed backend, and disconnected only if
  none exists.

- **Passive mode.** `detection.passive` checks nobody at login. `/proxyshield check` and the API
  keep working, so ProxyShield can sit next to another anti-VPN as a lookup tool.

- **Telegram and VK alerts**, plain text with the same placeholders as the console line, sent
  through the same bounded queue model as the Discord webhook.

- **`/proxyshield alts <ip|player>`** lists every account seen on the same address, newest first.
  The history lives in `alts.tsv` next to the config, is pruned after `alts.retention-days`, and
  groups IPv6 clients by their /64 the same way the cache does.

- **Whitelist and blacklist entries with a reason and an expiry.**
  `/proxyshield whitelist add <entry> [30m|12h|7d|perm] [reason...]` stores who added the entry,
  when, why, and until when. `info` shows that, `purge` clears every in-game entry, and `list`
  marks the timed ones. A timed entry stops matching the moment it runs out, not at the next
  save. Files written by older builds load unchanged, and a note written by hand after `#` is kept
  as the reason.

- `/proxyshield stats` counts network/ISP, account-limit and bogon blocks.

### Changed

- **The ISP name is the one most providers agree on**, not the first that answered. Providers
  disagree on names more than on anything else: for 1.1.1.1 one reports Cloudflare and another
  the registrant of the block, APNIC. Which of those landed in the alert and in the ISP filter
  used to depend on network timing.

### Upgrading

New options take effect with their defaults even when your `config.yml` does not list them yet:
bogon blocking and the account history are on, everything else is off. To see and change them,
compare your file with the new default or let the plugin write a fresh one.

### Testing

Live on Paper 1.21.11: bogon refusal, the ISP filter, a flag condition on a custom provider,
debug output, timed whitelist entries with `info` and `purge`, and the account history with two
connecting clients. Telegram, VK, the connection limit and restricted servers are covered by unit
tests only so far; the last two cannot be exercised from a loopback address, which ProxyShield
never checks.

## 2.5.1

### Fixed

Five defects that let a commercial VPN connect unflagged, and they compound: with the shipped
configuration, four of six real ProtonVPN exits passed every check. After this release all six are
stopped, and ten consumer ISP and mobile addresses across seven countries still connect.

- **`business` counted as a residential connection**, so `detection.allow-residential-hosting`
  waved every VPN operator past the hosting block. In iplocate's vocabulary a home line is `isp`,
  a datacenter is `hosting`, and `business` is a corporate network, which is exactly what a VPN
  company announcing its own ASN looks like. Proton AG comes back as `business`. The exemption
  now covers residential, mobile, cellular and `isp` only. An office or a school is `business`
  too, but a provider reports hosting for one of those only by mistake, and the carrier ranges
  this option exists for are `isp`.

- **The reverse DNS check found no name for any VPN exit.** It went through
  `InetAddress.getCanonicalHostName()`, which performs a forward confirmed reverse lookup: it
  reads the PTR, resolves the name it got back, and discards it unless the original address is
  among the answers. VPN operators routinely publish a PTR with no matching A record, so the
  confirmation failed and the JDK handed back the literal, which reads as "no PTR at all".
  ProtonVPN is the case that exposed it: every exit answers `185-70-41-1.protonmail.ch` to `dig`
  and that name has no A record, so the check saw nothing on precisely the addresses it exists to
  catch. The PTR record is now read directly. The JDK call remains as a fallback where JNDI is
  unavailable.

  The DNS context is built once and reused. Creating one costs about 80 ms, which on the shipped
  700 ms budget was most of a lookup, and building it per query made the first lookup after a
  restart time out. Warm lookups take about a millisecond.

- **The one built-in rDNS pattern aimed at Proton never matched Proton.** The list carried
  `protonvpn`; Proton names its exits after the mail brand. Of the seventeen ranges Proton
  announces, ten publish a PTR and not one matched. `protonmail` is now in the list, and `hosted`
  joins `hosting`, because `hosted-by-<name>.net` is a common shape the longer word does not
  cover.

- **A clean verdict from an incomplete round was cached for six hours.** One provider answering
  "not a proxy" is enough to settle a consensus round, so a rate limit or a timeout on the single
  provider that would have flagged the address produced a clean answer that then sat in the cache
  for the full `api.cache-minutes` and survived restarts through `lookup-cache.json`. The address
  kept passing long after the providers recovered, and nothing in the log said why. Clearing the
  cache was the only way out of it, and nothing pointed there.

  A clean verdict now gets the configured lifetime only when every provider actually answered. If
  any of them failed or the budget ran out, it is kept for five minutes instead, which still
  absorbs a burst of logins. A flagged verdict is unaffected, and so is a round that stopped early
  because the score was already reached: the answers still outstanding could not have changed it.

  `/proxyshield clearcache` empties both the in-memory cache and the stored one, which is the
  supported way to force a re-check.

- **`ipapi-is` failed on every request and said so nowhere.** It is the highest weighted provider
  in the shipped configuration at 1.5, and without a key ipapi.is answers on its anonymous tier:
  eleven flat keys, none of the risk fields, with `company` and `asn` as plain strings rather than
  objects. Every documented path found nothing, so the provider returned `response carried none of
  the expected fields` on every lookup and silently contributed zero.

  It now reads the anonymous shape as well, so an unkeyed install still gets the country, the ISP
  and the network from it, and a keyed install is untouched. It still cannot contribute a VPN
  verdict without a key, so the first time any provider answers without a single risk field the
  console says which provider, what it costs and what to do about it. A service quietly scoring
  zero for months is the failure this prevents.

## 2.5.0

### Added

- **One jar for every platform** (`ProxyShield-Universal-2.5.0.jar`). It carries all four entry
  points and all four plugin descriptors, and each server reads the one it knows: Bukkit takes
  `plugin.yml`, BungeeCord takes `bungee.yml` ahead of it, Velocity takes `velocity-plugin.json`
  and Sponge takes `META-INF/sponge_plugins.json`. The same file drops into a Paper `plugins/`
  folder, a BungeeCord one, a Velocity one or a Sponge `mods/` folder.

  It is an extra download, not a replacement. The five per-platform jars are unchanged and remain
  the plainer choice for a single server; the universal one saves a network running several of
  them from fetching four files that differ in about a hundred classes.

  Nothing in the plugin behaves differently. The universal build adds the platform modules' own
  sources rather than copying them, so it cannot drift from the jar it mirrors, and the four
  bStats artifacts it needs share one base and add a single class each. It costs roughly 400 KB
  over a single-platform jar, almost all of it the bundled YAML parser that Velocity and Sponge
  need and Bukkit does not.

## 2.4.1

### Fixed

- **The address count in the startup log was always the same number.** Every start reported
  `covering 9223372036854775807 addresses`, which is `Long.MAX_VALUE` and reads like a broken
  counter. It was not arithmetic going wrong: the total saturated on purpose, but a single IPv6
  `/64` already holds 2^64 addresses, so with the default feeds the guard tripped on the first
  IPv6 range every time. The figure never moved with its input, which is the giveaway that it was
  measuring nothing.

  There is no combined total any more, because no `long` can hold one. IPv4 is counted exactly and
  IPv6 is reported by range:

  ```
  VPN lists ready: 65295 entries compiled into 36349 ranges.
  IPv4: 31078 ranges covering 392968591 addresses. IPv6: 5271 ranges.
  ```

  `IpRangeSet.addressCount()` is now `ipv4AddressCount()`, joined by `ipv4RangeCount()` and
  `ipv6RangeCount()`. The `{addresses}` placeholder in `refresh-done` is IPv4 only and both
  message files say so.

## 2.4.0

### Added

- **The Discord embed layout is now yours to write** (`discord.embed`). The message used to be
  fixed at a title and six inline boxes, and the one thing an operator could not change from
  outside was what it looked like. Every visible part is a template string instead:

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
      footer: "ProxyShield {version} on {platform}"
      fields: {}
  ```

  Placeholders are `{player}`, `{uuid}`, `{ip}`, `{reason}`, `{country}`, `{isp}`, `{asn}`,
  `{score}`, `{sources}`, `{platform}`, `{version}`, `{action}` (`Connection denied` or
  `Logged only (dry run)`) and `{action_id}` (`kicked` or `allowed`).

  Fields are named entries rather than a list, the same way `api.providers` works, and appear in
  the order written. Clear them with `fields: {}` for a description-only message, or drop the
  whole `embed` section to keep the previous layout.

  Values are substituted exactly as written, so the backticks are yours to place. That matters
  because Discord parses embed text as Markdown and an underscore is a legal name character: the
  shipped layout wraps everything that can contain one.

  **Nothing changes for an existing server.** A config without an `embed` section renders the old
  layout, and the section now shipped in `config.yml` is that same layout spelled out, which a
  test pins.

  The thumbnail must be `https://`, the same rule the webhook URL is held to.

- **`{action_id}` in `actions.on-flag`**, matching the embed layout. `{action}` is the short
  `kicked` / `allowed` for a command but the readable `Connection denied` in the embed, which is
  a trap if you write both. `{action_id}` is the short form in either place. `{action}` keeps the
  meaning it shipped with in each, so nothing changes under an existing config.

## 2.3.0

### Added

- **Console commands on a detection** (`actions.on-flag`). Not every server wants a flagged player
  gone. Some would rather mark them: drop them into a restricted group, make them verify through
  Discord, hand the name to another plugin. That was previously impossible without waiting for each
  case to become its own setting, so it is now a list of commands instead:

  ```yaml
  actions:
    on-flag:
      - "lp user {player} permission set myserver.vpnflagged true"
      - "webhook {player} flagged {reason} from {ip}"
    delay-seconds: 3
    run-when: always
  ```

  Commands run as the console, with or without a leading slash. Placeholders are `{player}`,
  `{uuid}`, `{ip}`, `{reason}`, `{reason_id}`, `{country}`, `{isp}`, `{asn}`, `{score}`,
  `{sources}`, `{action}` and `{platform}`.

  Combined with `detection.dry-run: true` this gives a flag-instead-of-kick setup: the detection
  fires, the alert and the webhook go out, the commands run, and the player stays connected.

  `delay-seconds` exists because a connection is judged before the player is on the server. At `0`
  the commands run while they are still connecting, which is fine for a permission grant or a
  webhook but not for anything that needs them actually online. `run-when` takes `always`, `kicked`
  or `allowed` when the commands should only fire for one of the two outcomes.

  Values coming from a provider, such as `{isp}`, are stripped of characters a dispatcher would
  read as a separator, so a hostile network name cannot turn one configured command into two.

### Fixed

- **Clearing `discord.username` or `discord.title` broke the webhook entirely**, with every alert
  rejected as `HTTP 400`. Discord refuses the whole request when a string it expects to be filled
  arrives empty, and the plugin only ever saw the status code, so the cause looked like a bad
  webhook URL. Both options are now left out of the payload when blank rather than sent as `""`:
  an empty username falls back to whatever the webhook itself is named, which is what clearing it
  was meant to do. Embed field values are guarded the same way, so a provider answering with a
  blank ISP no longer costs the alert.
- **Underscores in a player name were eaten by Discord's Markdown.** `Some_Name` arrived italic and
  `__Name__` underlined with the underscores gone, which is the spelling staff then searched for and
  could not find. The name, the address and the ISP are now sent as code spans, so they show exactly
  as written and stay selectable. Escaping with backslashes would have rendered correctly but put
  the backslashes into the copied text, which is worse.
- **Providers that answer with a redirect were treated as failures.** The lookup now follows up to
  three hops, which is enough for an http-to-https move or a relocated path.
- **A keyed service left enabled without a key was asked with an empty key** rather than without
  one. `?key=` is not the same as omitting the parameter: iplocate.io reads the empty value as a
  wrong key and answers `401`, so a service that works perfectly well unauthenticated looked broken.
  The parameter is now dropped entirely when no key is configured.

## 2.2.1

### Fixed

- **The Bukkit builds refused to start without PlaceholderAPI installed.** The check for it lived
  inside the expansion class itself, so reaching the check meant loading that class, and loading it
  resolved its `PlaceholderExpansion` superclass - which does not exist on a server without
  PlaceholderAPI. The result was a `NoClassDefFoundError` during `onEnable` that took the whole
  plugin down, leaving the server with no proxy protection at all. The guard now sits in
  `PaperMain`, before anything names the expansion class, and the registration is additionally
  wrapped so an incompatible PlaceholderAPI version cannot stop the plugin either.

  Only the Paper and Folia builds of 2.2 were affected. BungeeCord, Velocity and Sponge never
  touched that code and are functionally unchanged in this release.

## 2.2

The detection layer, rebuilt. v2.1 asked one provider and took the first answer it got; if that
service had never heard of a particular commercial VPN, the connection was cleared and nothing else
was consulted. That is the miss this release exists to close.

### Added

- **A catalog of 26 IP intelligence services**, each with its own response layout, enabled by name:

  ```yaml
  api:
    providers:
      ip-api:     { enabled: true, weight: 1.0 }
      blackbox:   { enabled: true, weight: 1.0 }
      proxycheck: { enabled: false, weight: 2.0, key: "" }
  ```

  Free, no key: `ip-api`, `blackbox`, `iprisk`, `ipquery`, `ipapi-is`, `iplocate`, `freeipapi`,
  `funkemunky`, `negativity`, `fastasfuck`, `zombiebot`, `rayzs`, `marvinmc`, `ip-check`, `zowi`.
  Key based: `proxycheck`, `ipqualityscore`, `vpnapi`, `iphub`, `iphunter`, `ip2location`,
  `vpnblocker`, `getipintel`, `antivpn-io`, `2ip`, `abuseipdb`. A keyed service without a key is
  dropped at start-up with one warning instead of failing on every login.
- **Consensus mode** (`api.mode`, `api.required-score`). Providers are queried in parallel and their
  weights added up; the connection is refused once the total reaches the required score. A single
  blind provider can no longer wave a VPN through, and a single noisy one can no longer kick anybody
  on its own.
- **Network (ASN) rules** (`detection.asn`). Address feeds always lag behind a VPN renting a new
  range; the network number does not, so blocking the ASN catches every address inside it at once.
  ASNs are normalised across the four spellings providers use (`AS9009`, `9009`, `AS9009 M247 ...`).
- **Reverse DNS as a signal** (`detection.rdns`). Operators name their machines after themselves, so
  the PTR record catches ranges no feed lists yet, costs no quota and cannot be rate limited. It
  contributes weight rather than blocking outright, and runs under a hard timeout.
- **Trust** (`trust`). An account with a history of clean logins stops being re-judged on every
  connection. Mobile players behind carrier NAT are the ones a hosting block hits hardest, and this
  is what keeps them online. Never overrides the manual blacklist, and is reset the moment an
  account is caught behind a proxy.
- **Behavioural heuristics** (`heuristics`). Join rate per /24, distinct accounts per address and an
  account changing country within minutes. These catch an attack from a range rented this morning,
  which by definition appears on no list anywhere.
- **Tor exit list** as a default feed, and a `detection.block-tor` switch.
- **Custom providers in config.yml.** Any unlisted service can be described with a URL, dotted field
  paths, an optional score field and a threshold - no code needed.
- **On-disk lookup cache** (`api.persist-cache`), so a restart no longer spends its first minutes
  re-querying addresses the plugin already knew about.
- `/proxyshield providers` lists every enabled service with its live health, and
  `/proxyshield check` now prints what each provider individually said about an address.
- Log rotation for `blocks.log` at 16 MB.
- **Shared storage for a network** (`storage.type`). Verdicts and trust can live in MySQL,
  MariaDB, PostgreSQL, SQLite, H2 or Redis instead of a local file, so a network running several
  proxies pays for each address once rather than once per proxy, and every front end agrees about
  it. Redis additionally pushes invalidations, so whitelisting an address or clearing the cache on
  one server takes effect on the others immediately. No driver and no Redis library is bundled -
  the schema stays in portable SQL and the Redis protocol is spoken directly - so nothing is
  relocated into a server that did not ask for it. A store that cannot be reached falls back to
  file storage with one warning; a database outage never becomes a login outage.
- **bStats metrics** (`metrics`), reporting configuration shape and counters, never addresses or
  player data. The Bukkit build reports to
  [ProxyShield/33736](https://bstats.org/plugin/bukkit/ProxyShield/33736); the other platforms need
  their own id under `metrics.plugin-id`.
- **PlaceholderAPI support** on the Bukkit builds: `%proxyshield_blocked%`, `%proxyshield_checked%`,
  `%proxyshield_country%`, `%proxyshield_isp%`, `%proxyshield_asn%`, `%proxyshield_score%`,
  `%proxyshield_is_proxy%`, `%proxyshield_trusted%`, `%proxyshield_providers%`,
  `%proxyshield_storage%` and more. Every one reads the cache: placeholders resolve on the main
  thread, so none of them can perform a lookup.
- **A read-only API for other plugins**, `ProxyShieldApi`: cache-only `isProxy`/`isHosting` calls
  that are safe on the main thread, a blocking `lookup`, and `isTrusted`.

### Fixed

- **Nested and numeric responses were silently read as clean.** A flag at `security.vpn`,
  `privacy.is_vpn` or `risk.is_proxy` was invisible to the flat reader, and getipintel's probability
  arrives as the JSON string `"0.99"`, which read as a boolean is `false`. Both produced a false
  negative - a VPN let straight through with no error anywhere.
- **iphub's `block: 2` counted as a detection.** It means "unclear", not "block", so it kicked
  players the provider had explicitly declined to judge.
- **A response carrying none of a provider's documented fields now counts as a failure**, not as a
  clean address, so an API changing shape surfaces instead of quietly disabling detection.
- **`/proxyshield reload` threw the whole lookup cache away**, sending the server straight back into
  the providers' rate limits. The cache is now inherited.
- **Simultaneous logins from one address each triggered their own lookup.** They now share one.
- **The rate limiter had a race** between resetting its window and incrementing its counter, which
  let requests slip past the limit or vanish. Replaced with a token bucket.
- **A login could stall for the sum of every provider's timeout.** The lookup stage now has one
  budget (`api.total-timeout-seconds`) and answers with whatever arrived in time.
- **A dead provider was retried at full timeout on every single login.** A circuit breaker now
  takes it out of the rotation for two minutes after five consecutive failures.
- **IPv6 was cached per full address**, so a client rotating the host part inside its own /64 never
  hit the cache. Both the cache and the rate limiter now work per /64.
- **Mobile carriers in hosting ranges were kicked.** Where a provider reports the connection type,
  `detection.allow-residential-hosting` keeps those players online.

### Changed

- Flagged addresses are cached far longer than clean ones (`api.flagged-cache-minutes`): a confirmed
  VPN range stays one for days, while "looked clean an hour ago" goes stale quickly.
- Alerts, `blocks.log` and the webhook now record the ASN and which services flagged the address.
- 178 automated tests, up from 124, including the SQL store against a real database and the Redis
  client against a server that speaks the actual protocol.

## 2.1

### Added

- **Spigot support.** The Bukkit jar now runs on Paper, Purpur, Folia and plain Spigot. Async
  scheduling, disconnecting a player and sending a message go through a bridge chosen at start-up,
  so the Paper-only types are never loaded on a server that lacks them.
- **Bedrock players are exempt by default** (`whitelist.bedrock-players`). Wherever Geyser runs
  anywhere other than the player's own machine, the address seen here is Geyser's - and a Geyser
  instance on rented hardware sits in exactly the datacenter ranges the feeds list, so without this
  a server would drop every Bedrock player the moment hosting detection was switched on. Floodgate
  derives these UUIDs server side from the Xbox Live account, so a Java player cannot fake one.
- **Lookup provider failover** (`api.providers`). Endpoints are tried in order, so a rate limited or
  unreachable provider costs one failed request instead of the whole check. Responses are understood
  in both the flat shape (ip-api.com) and the nested-by-address shape (proxycheck.io), including the
  field spellings `proxy`/`vpn`/`tor`/`block`, `hosting`/`datacenter`, `countryCode`/`isocode`,
  `isp`/`provider`/`organisation` and `yes`/`no` flags.

### Changed

- `api.url` is superseded by `api.providers` and now defaults to empty. An existing `api.url` is
  still honoured as the first provider, but emptying the provider list now genuinely means "no
  provider" instead of silently falling back to a hardcoded endpoint.
- 124 automated tests, up from 111.

## 2.0

A full rewrite. One shared detection core, five platform builds, and every defect listed below
fixed. Configuration keys have changed; see *Upgrading* at the bottom.

### Feed downloading

Hardened after the first live server run, where all four feeds came back `429` from
raw.githubusercontent.com and the plugin started with no list protection at all.

- **Rate limits are retried instead of given up on.** A `429` or a transient `5xx` is retried up to
  three times, waiting for the interval the server asks for in `Retry-After`.
- **Conditional requests.** The `ETag` of each feed is stored next to its cached copy and sent back
  as `If-None-Match`, so an unchanged feed costs a small `304` instead of a full download. That alone
  keeps most refreshes well clear of the limit.
- **Sources are not fetched back to back.** A short gap between them stops several feeds on one host
  from looking like a burst.
- **The first download waits a few seconds after start-up**, which is exactly when every other plugin
  that polls GitHub is doing the same thing. Startup protection comes from the disk cache anyway.
- **The warning says what it means.** Losing every source with nothing cached reports that list
  detection is *inactive* and that the provider lookup still works, rather than the unhelpful
  "keeping the previous 0 ranges".

### Added

- **Spigot support.** The Bukkit jar now runs on Paper, Purpur, Folia and plain Spigot. The three
  calls that differ - async scheduling, disconnecting a player and sending a message - go through a
  bridge chosen at start-up, so the Paper-only types are never loaded on a server that lacks them.
- **Sponge and Folia support.** Five builds now: Paper, Folia, BungeeCord, Velocity, Sponge. Paper
  scheduling moved to the modern `AsyncScheduler` and entity schedulers, which is what lets the code
  run on a regionised Folia server at all. The Folia jar is compiled from the Paper module's sources
  rather than a copy, so the two can never drift apart.
- **Country filtering** in blacklist or whitelist mode, with a separate setting for addresses whose
  country cannot be determined.
- **Silent mode.** Suppresses the staff broadcast and the console line while the log file and the
  Discord webhook keep recording, so a server can watch for false positives without announcing every
  detection to everyone online.
- **Dry-run mode.** Detects and reports without disconnecting anybody.
- **IP whitelist and blacklist** accepting single addresses, CIDR blocks and start-end ranges, in
  IPv4 and IPv6, editable in game and persisted separately from `config.yml`.
- **`/proxyshield` command** with twelve subcommands and tab completion, identical on all five
  platforms: `info`, `stats`, `check`, `lookup`, `whitelist`, `blacklist`, `refresh`, `recheck`,
  `clearcache`, `reload`, `dryrun`, `silent`.
- **Localisation.** All player facing text lives in `messages_<code>.yml`; English and German ship
  with the plugin. A key you delete falls back to the built-in English, so an old message file keeps
  working after an update.
- **Block log** at `plugins/ProxyShield/blocks.log`.
- **Statistics** covering connections checked, blocks by reason, cache hit rate and webhook state.
- **Disk cache for the IP lists**, so a restart while the feed host is unreachable still comes up
  protected instead of with an empty list.
- **111 automated tests** and a GitHub Actions workflow.

### Fixed

- **The IP lists never matched anything.** Entries were parsed with
  `line.split(" ")[0].split("/")[0]`, discarding the CIDR prefix, and matching was a string equality
  test against the result. Every entry in the default feed is a CIDR block, so a `/24` matched only
  its own network address. Measured against the live X4BNet feed: v1 covered 42,510 addresses where
  the feed describes 377,108,792, and of 42,442 sampled hosts inside listed VPN blocks it detected
  none. The list check was effectively dead; only the provider lookup did anything.
- **Proxy detection was a substring test.** `readLine().contains("true")` matched anywhere in the
  response, including inside an ISP or country name, and broke entirely if the response spanned more
  than one line. Responses are now parsed as JSON.
- **The webhook payload was injectable.** Player names and config strings were concatenated straight
  into the JSON body. A name containing a quote produced malformed JSON; a crafted one could inject
  arbitrary embed fields. All output now goes through an escaping writer.
- **Blocking I/O on connection threads.** BungeeCord ran the HTTP lookup inline on the netty thread.
  Velocity checked in `PostLoginEvent`, so a blocked player was briefly fully connected. Both now run
  asynchronously in a pre-connection hook.
- **The lookup cache grew without bound** and never expired an entry. It is now LRU-bounded with a
  configurable TTL.
- **No rate limiting.** ip-api.com allows 45 requests per minute on the free tier and v1 ignored
  that, so a busy server would get the host banned. Requests beyond the limit are now skipped rather
  than sent.
- **Errors were silently swallowed.** Roughly a dozen empty `catch` blocks meant a dead feed URL, an
  unreachable provider or an unwritable config produced no output at all. Failures are now logged,
  and `settings.fail-closed` decides deliberately what an unresolvable check means.
- **The platforms disagreed with each other.** `whitelist` was only read on Paper. Velocity used a
  different config format with a different set of options and a hardcoded 24 hour refresh interval.
  Paper and BungeeCord reported version `1.0` while the jar was `1.1`.
- **A DNS lookup could run on a login thread.** Address parsing now validates the literal shape
  before touching `InetAddress`, so a hostname can never trigger a resolve.
- **The default feed URL was wrong.** `output_datacenter.txt` does not exist in the X4BNet
  repository and returned a 404. The defaults now point at the four feeds that do exist, and the
  root `ipv4.txt` v1 used turns out to be the datacenter list rather than the VPN list.

### Upgrading from 1.1

`config.yml` is not compatible and is not migrated automatically. Move the old file aside, let the
plugin write a fresh one and re-apply your settings. The notable moves:

| 1.1 | 2.0 |
|---|---|
| `settings.kick-message` | `kick-message` in `messages_<code>.yml` |
| `notifications.message` | `alert` in `messages_<code>.yml` |
| `settings.update-interval-hours` | `lists.update-interval-hours` |
| `sources` | `lists.sources` |
| `whitelist` | `whitelist.ips` |
| `discord.message-title` | `discord.title` |

The Velocity build previously used `config.properties`; it now reads the same `config.yml` as every
other platform, so those settings have to be re-entered.

## 1.1

Initial public release. Single jar containing separate Paper, BungeeCord and Velocity main classes
with no shared code.
