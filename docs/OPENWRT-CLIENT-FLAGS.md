# fptn-client-cli on OpenWrt — every flag

Besides the ordinary VPN mode this client can **live next to a transparent
proxy**: leave the routes alone and hand traffic out over SOCKS5. That is
exactly how ZeroBlock runs it.

Русская версия — [OPENWRT-CLIENT-FLAGS.ru.md](OPENWRT-CLIENT-FLAGS.ru.md).

## Quick start

A plain VPN (the client sets up routes and DNS itself):

```sh
fptn-client-cli --access-token fptn://…
```

Coexisting with ZeroBlock (routes and DNS belong to someone else, SOCKS5 is the
way out):

```sh
fptn-client-cli \
  --access-token fptn://… \
  --socks-listen 127.0.0.2:20180 \
  --disable-routing \
  --tun-interface-name zbfptn0 \
  --tun-interface-ip 192.0.2.1 \
  --routing-mark 0x40000000
```

## A config file instead of flags

Keys such as `fptnb:` run to a kilobyte and a half and do not fit on a command
line, let alone several of them. So the same settings can come from a file:

```sh
fptn-client-cli -c /etc/fptn/zeroblock.json
```

```json
{
  "socks_listen": "127.0.0.2:20180",
  "disable_routing": true,
  "socks_route_table": 1080,
  "tun_interface_name": "zbfptn0",
  "tun_interface_ip": "192.0.2.1",
  "tun_interface_ipv6": "fd00:5a42:0::1",
  "bypass_method": "obfuscation",
  "routing_mark": "0x40000000",
  "access_token": ["fptn://…", "fptnb:…"]
}
```

The rules are simple:

- a key is a flag name without `--`; dashes and underscores are equivalent
  (`tun_interface_ip` = `tun-interface-ip`), on the command line as well:
  `--socks_listen` is understood the same as `--socks-listen`;
- an array expands into a repeated flag — this is how several tokens are given;
- `null` is skipped;
- **a flag given on the command line overrides the file** — it is then simply
  not taken from there. This includes arrays: your own `--access-token`
  arguments replace the file's list entirely rather than adding to it.

A note on `disable_routing`: on the command line it is a switch with no value,
so from a file it expands into a bare flag when the value is true and is not
added at all when false. True means `true`, the string `"true"`, `"1"`, `"yes"`,
`"on"` and any non-zero number, so `"disable_routing": true` and
`"disable-routing": "true"` behave the same.

## Tokens and server selection

| flag | default | what it does |
|---|---|---|
| `--access-token` | — | Access token (`fptn://` or the compressed `fptnb:`). **Required.** The flag repeats: several tokens form one shared server pool |
| `--preferred-server` | — | Name of the server to connect to without a race. Case-insensitive. When names collide between tokens, qualify it as `Service/Name` |
| `--exclude-servers` | — | Regular expression: servers whose name matches are left out of the pool, e.g. `Russia\|Vietnam`. Both the bare name and `Service/Name` are tested, so a whole service can be dropped |
| `--max-ping` | `5000` (`0` disables) | Latency limit in milliseconds. A server above it is not picked, and the one in use is replaced if it stays above |

Several tokens are **not** several tunnels. The client merges their servers into
one list, tagging each with its own account, and works through a single chosen
server. A second token helps when the server allows one active session per user:
it provides spare servers under a different account.

How a server is chosen:

1. if `--preferred-server` is set, it is used;
2. otherwise a **login race** runs (up to 8 servers in flight), and the first
   to answer wins;
3. with `--max-ping` set, the winner is measured as well; if it does not fit,
   it leaves the list and the race repeats. Three rounds, then the best of the
   remaining ones is taken.

After that a watchdog measures the latency once a minute. Three readings in a
row past the limit and the tunnel is brought down, the process exits cleanly,
and the service starts it again on a different server. A reading that times out
counts as over the limit, so a server that stops answering is left within three
minutes.

The watchdog is created unless one of three things is true: `--max-ping` is `0`,
the server is pinned with `--preferred-server`, or the pool holds a single
server. The last one matters on a router: with nowhere to move, dropping the
tunnel would restart the process every three minutes and change nothing, and a
slow server beats no server.

What the number measures is not an ICMP round trip. The probe opens a TLS
connection to the server, with the obfuscation and SNI the tunnel itself uses,
and downloads a 100 KB test file (`/api/v1/test/file.bin`) with a five-second
timeout. A healthy distant server therefore reads as hundreds of milliseconds
and a busy one as a second or two, which is why the default sits at five
seconds - the point past which the tunnel is unusable rather than merely slow.
The traffic cost is 100 KB a minute per client, and it does not go through the
tunnel.

Nothing keeps a bad server out for longer than the run it failed in: the pool
is rebuilt on every start, and a server dropped for being slow is measured
again next time. It stays out only while it stays slow.

## Coexisting with a transparent proxy

| flag | default | what it does |
|---|---|---|
| `--socks-listen` | — | Run SOCKS5 (CONNECT and UDP ASSOCIATE) on this address, e.g. `127.0.0.2:20180`. Implies `--disable-routing` |
| `--disable-routing` | off | Do not touch the system routes: the interface comes up, the default route stays someone else's |
| `--socks-route-table` | `1080` | Routing table id used for SOCKS traffic |
| `--socks-max-sessions` | from the descriptor limit | Cap on simultaneous SOCKS sessions. By default derived from the process `RLIMIT_NOFILE`: two descriptors per session plus headroom, which is 1920 at a limit of 4096 |
| `--routing-mark` | — | `SO_MARK` (hex or decimal) on every outgoing socket, so firewall rules can keep the client's traffic out of DPI bypass and transparent proxying, e.g. `0x40000000` |

The port opens **immediately at startup**, before the login race: connections
wait in the kernel backlog while the tunnel comes up. This matters for
ZeroBlock, which waits only seconds for the helper to become ready, while
working through several dozen servers takes up to a minute.

In this mode the client owns neither routes nor the resolver: `/etc/resolv.conf`
and dnsmasq are left alone, and the routing table belongs to whoever created it.

## Exposing status: the server pool and its latency

| flag | default | what it does |
|---|---|---|
| `--status-listen` | — | Serve a local HTTP API with the server list and their latency, e.g. `127.0.0.1:9091` |
| `--status-secret` | — | Token: requests must carry `Authorization: Bearer <token>`. Empty means no check, and then the endpoint may only be bound to the loopback |
| `--probe-interval` | `180` | Re-measure the whole pool every N seconds. `0` disables it |
| `--switch-tolerance` | `500` | How much faster another server must be, in milliseconds, before the tunnel moves to it on its own. `0` leaves only the "stopped answering" case |

The client knows which servers a token carries and how long each takes to
answer, but used to show that to nobody: the only output was log lines and the
process exit code. A transparent proxy running the client as its helper had
nowhere to read this from — hence the request to "show what you have inside".

The response shape follows the Clash API, because dashboards (yacd,
metacubexd) and router-side tooling already parse it:

| request | what it returns |
|---|---|
| `GET /proxies` | Every server: `type`, `name`, `udp`, `history` with the latest measurement, plus the selector group `FPTN` with `now` and `all` |
| `GET /proxies/<name>` | One server in the same shape |
| `GET /proxies/<name>/delay?timeout=8000` | Measures **now** and returns `{"delay": <ms>}`. The result also lands in the measurement window |
| `PUT /proxies/<name>` | Switch the tunnel to another server, body `{"name": "<name>"}`. Answers `{"now": "<name>"}` |
| `GET /status` | The detailed view: the measurement window per server, tunnel state, packet counters, SOCKS sessions |
| `GET /version` | Client version |

The latency is the login time: a small request, so the number describes the
link rather than the bandwidth. Zero means failure, as in the Clash API. A
window of the last ten measurements is kept, and `/status` reports its average,
minimum, maximum and failure count. One failed probe in the middle of the
window does not strike a server out: alive means its **latest** probe
succeeded.

```console
$ curl -s -H 'Authorization: Bearer secret' 127.0.0.1:9091/proxies
{"proxies":{
  "FPTN":{"type":"Selector","name":"FPTN","udp":true,"history":[],
          "now":"Example/eu-1","all":["Example/eu-1","Example/eu-2"]},
  "Example/eu-1":{"type":"FPTN","name":"Example/eu-1","udp":true,"alive":true,
                  "history":[{"time":"2026-09-10T11:27:50.638Z","delay":214}]},
  "Example/eu-2":{"type":"FPTN","name":"Example/eu-2","udp":true,"alive":false,
                  "history":[{"time":"2026-09-10T11:27:52.101Z","delay":0}]}}}
```

With `--probe-interval 0` the window holds only what was measured while
picking a server at startup, plus the checks of the current node from
`--max-ping`. That is, a server that was down at launch and has recovered since
keeps counting as dead. The sweep is on by default for that reason.

A sweep probes every server, at most eight at a time, so one dead node does not
hold up the rest. The probe is the same TLS connection the tunnel opens, with
the same obfuscation and SNI, followed by a request for the DNS record - a few
dozen bytes. It used to download a 100 KB test file, which turned a pool of
thirty-five servers into 3.5 MB per sweep for a number the handshake already
gives.

### Moving on its own

After each sweep the client compares the server in use with the best one that
answered, and moves the tunnel when that is clearly worth it. The shape is
sing-box's urltest, with the thresholds set for a tunnel rather than an
outbound - sing-box switches on 50 ms because switching costs it nothing,
while here it costs about a second of silence and a fresh login against a
server that counts sessions per user:

- **the server in use stopped answering, or answers past `--max-ping`** - move
  at once, without waiting for anything else;
- **otherwise** - move only if another server is faster by more than
  `--switch-tolerance`, and only if the last move was more than ten minutes
  ago. Without that floor a pool with two servers a few hundred milliseconds
  apart would swap on every sweep.

The comparison uses the average of a server's measurement window, not its last
reading: a single probe lies often enough - the network blinked, the node was
busy - that a decision made on one moves the tunnel for nothing.

Nothing moves on its own in four cases: the server is pinned with
`--preferred-server`, the pool holds one server, the client owns the routes
(see below), or somebody has picked a server through `PUT /proxies/<name>`.
That last one is deliberate: an explicit choice outranks a measurement, and
undoing it on the next sweep would read as the client fighting the dashboard.
It holds until the process restarts.

### Switching servers at runtime

`PUT /proxies/<name>` moves the tunnel to another server without restarting the
process. The TUN device stays open, SOCKS keeps accepting connections, and only
the far end changes; the address the server assigns is used to rewrite the
source IP of outgoing packets, so the interface does not need to come up again.

The order is deliberate: the new server is probed first, and only if it answered
is the current session released and the login started. This is because the
server may count sessions per user and refuse a second concurrent login: both
connections cannot be held at once, and dropping a working one for a node that
does not answer would be worse still. If the login fails anyway, the previous
server is brought back up and the request returns `503`.

A switch takes about a second, and there is no traffic in the tunnel during it.

**Switching requires `--disable-routing`** (and therefore `--socks-listen`).
When the client owns the routes, the route manager excludes the address of the
server it was started with — otherwise the tunnel would run inside itself — and
that exclusion cannot be rewritten in place. An attempt to switch in that mode
returns `503` and a log line. On a router this costs nothing: the transparent
proxy owns the routes there and the client runs as its helper.

### Reaching the API from another host

The endpoint hands out the server pool, runs a latency probe on demand and
accepts a switch request, so off the loopback the token is the only thing in
front of it. Two rules follow from that, and the client enforces the first:

**Off the loopback a secret is required.** `--status-listen 0.0.0.0:9091`
without `--status-secret` is refused at startup with a log line rather than
served wide open. sing-box takes the opposite route here — an empty `secret`
disables its Clash API authentication silently — and the Xray metrics server
that LuCI packages read has no authentication at all while bound to `0.0.0.0`.
Neither is an example worth following.

**With a secret set, any `Host` is accepted.** Without one the header is
checked against the loopback and the bound address, which is what stops a page
whose domain resolves to `127.0.0.1` from reaching an endpoint that asks for
nothing. Once a token is required that check buys nothing — the request still
has to carry it, and no `Access-Control-Allow-Origin` is sent back, so a
browser cannot read the answer either way — while it would break the case this
is for: an endpoint bound to a LAN address or to the wildcard, reached by
whatever name the caller used.

The token is compared without an early exit, so a wrong guess takes the same
time whether it differs in the first character or the last.

**CORS is open.** `Access-Control-Allow-Origin: *` goes out with every answer,
refusals included, the way sing-box and mihomo do it — a dashboard that
already speaks the Clash API works unchanged. It protects nothing to withhold
it: reading the pool still needs the token, and a page whose domain is rebound
to the loopback bypasses CORS entirely. The preflight carries no
`Authorization` by definition, so it is answered before the token is checked.

Chrome additionally asks before letting a page on a public origin reach a
private address, which is every useful case here. That preflight is answered
with `Access-Control-Allow-Private-Network: true` **only when a secret is
set** — an endpoint that asks for nothing keeps saying no, so a page cannot
use the browser to sweep `127.0.0.1`.

```sh
fptn-client-cli --status-listen 0.0.0.0:9091 --status-secret "$TOKEN" ...
curl -H "Authorization: Bearer $TOKEN" http://192.168.1.1:9091/proxies
```

## Network and tunnel

| flag | default | what it does |
|---|---|---|
| `--tun-interface-name` | `tun0` | Interface name |
| `--tun-interface-ip` | `10.0.0.1` | Interface IPv4 address |
| `--tun-interface-ipv6` | `fd00::1` | Interface IPv6 address |
| `--mtu-size` | `1420` | MTU |
| `--out-network-interface` | auto-detected | Outgoing interface |
| `--gateway-ip` | auto-detected | Default IPv4 gateway |
| `--gateway-ipv6` | auto-detected | Default IPv6 gateway |
| `--exclude-tunnel-networks` | `10.0.0.0/8,192.168.0.0/16` | Networks that bypass the tunnel, always direct. CIDR, comma-separated |
| `--include-tunnel-networks` | — | Networks that always go through the tunnel |

## Censorship bypass

| flag | default | what it does |
|---|---|---|
| `--sni` | `google.com` | Domain used as SNI in the TLS handshake |
| `--bypass-method` | `sni-spoofing-yandex-26-4` | Masking method, see below |
| `--connection-strategy` | `rolling-tunnel` | `rolling-tunnel` — one tunnel renewed every 10 minutes; `dual-rolling-tunnel` and `triple-rolling-tunnel` — two and three in parallel |

Values for `--bypass-method`:

| value | what it does |
|---|---|
| `sni` | Plain SNI spoofing, no Reality |
| `obfuscation` | TLS obfuscation |
| `reality` | Reality without a browser profile — **a server may refuse it**, see below |
| `reality-chrome-145` … `-149` | Reality with a Chrome handshake of that version |
| `reality-firefox-149` … `-151` | The same for Firefox |
| `reality-yandex-24`, `-25`, `-26-3`, `-26-4` | For Yandex Browser |
| `reality-safari-26-4`, `-26-5` | For Safari |

The former `sni-spoofing-*` names remain as aliases: `sni-spoofing-chrome-149`
and `reality-chrome-149` are the same thing. The name was misleading — those
modes always enabled Reality rather than "plain SNI spoofing"; spoofing on its
own is now available as `sni`. Existing configs need no changes.

An unknown value is rejected at startup with the accepted ones listed:
`Invalid bypass method 'reality-chrome-150'. Choose from: …`.

Every value was checked on a router (OpenWrt 24.10, aarch64) against a live
server: the tunnel comes up in about 2 s on `sni`, `obfuscation` and all
fourteen versioned `reality-*` values (and on their `sni-spoofing-*` aliases).
The one exception is `reality` without a browser version: the fake handshake
completes, but the real one fails with
`handshake: stream truncated [asio.ssl.stream:1]` (five attempts out of five).
The server appears to need a specific browser profile, so use a versioned value
in production.

`sni` has a quirk of its own: there is no handshake masking, so under active
DPI it can fall over after a successful login — the connection passes
authentication (`Status: 200`) while the websocket tunnel closes on a handshake
timeout. On a quiet link it works reliably.

## Filtering and split tunnelling

| flag | default | what it does |
|---|---|---|
| `--blacklist-domains` | `solovev-live.ru,ria.ru,tass.ru,1tv.ru,ntv.ru,rt.com,lenta.ru` | Block a domain and all of its subdomains outright |
| `--enable-split-tunnel` | `false` | Enable split tunnelling |
| `--split-tunnel-mode` | `exclude` | `exclude` — the listed domains bypass the tunnel and everything else goes through it; `include` — the other way round |
| `--split-tunnel-domains` | `ru,su,рф,xn--p1ai,vk.com,yandex.com,userapi.com,yandex.net,clstorage.net` | Domain list for the mode above. An empty value uses the built-in list |

There is no ad blocking on OpenWrt: `--enable-ad-block` is compiled into
desktop builds only (`#ifndef FPTN_OPENWRT`), and passing it here is not
possible — parsing fails with `Unknown argument`. On a router the lists belong
to the transparent proxy in front of the client.

## Housekeeping

| flag | what it does |
|---|---|
| `-c`, `--config` | Path to the JSON config (see above) |
| `-h`, `--help` | Help |
| `-v`, `--version` | Version |

## The service on a router

The package installs `/etc/init.d/fptn` and the UCI config `/etc/config/fptn`.
Option names match the flags (underscores instead of dashes), and there can be
several tokens:

```
config fptn 'config'
	option enabled '1'
	list access_token 'fptn://…'
	list access_token 'fptnb:…'
	option disable_routing '1'
	option socks_listen '127.0.0.2:20180'
	option tun_interface_name 'zbfptn0'
	option routing_mark '0x40000000'
```

A single `option access_token` from earlier versions is understood as well.

When ZeroBlock runs the client, this service is not used: the daemon starts
`/usr/bin/fptn-client-cli` itself and passes the parameters as arguments.

## Behaviour on a router worth knowing about

**Logging.** On OpenWrt it goes to two files of one megabyte with rotation —
it used to be three of twelve, and on tmpfs such a log ate the router's memory.

**Descriptors.** At startup the soft limit is raised to the hard one, and the
cap on simultaneous sessions is derived from it — 1920 at a limit of 4096. Past
the cap the client answers with an honest protocol-level refusal, idle sessions
are closed on a timeout (5 minutes), and when descriptors run short, accepting
connections is slowed with a growing pause instead of spinning. The log shows
what the client started with:

```
SOCKS5 session limit: 1920 (fd limit 4096)
```

**What that costs in memory.** An active session uses two relay buffers of
16 KB. Five hundred sessions come to about 16 MB, and the full cap of 1920
would be 61 MB. On a router with modest memory the cap is a fuse rather than a
target: if you hit it constantly, shrinking the buffer is cheaper than raising
the limit.

**The resolver.** Names are resolved inside the tunnel and answers are cached
for their TTL (from 10 seconds to 10 minutes, up to 512 entries). A lost query
is asked once more, and a truncated answer is fetched over TCP. A silent DNS
produces one log line per state change rather than one per connection.
