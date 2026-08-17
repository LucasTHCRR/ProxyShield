# Changelog

## 2.1

### Added

- **Spigot support.** The Bukkit jar now runs on Paper, Purpur, Folia and plain Spigot. Async
  scheduling, disconnecting a player and sending a message go through a bridge chosen at start-up,
  so the Paper-only types are never loaded on a server that lacks them.
- **Bedrock players are exempt by default** (`whitelist.bedrock-players`). Wherever Geyser runs
  anywhere other than the player's own machine, the address seen here is Geyser's — and a Geyser
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
  calls that differ — async scheduling, disconnecting a player and sending a message — go through a
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
