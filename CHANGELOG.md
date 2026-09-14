# Changelog

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
