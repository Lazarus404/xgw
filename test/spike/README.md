# XGW browser spike

A small lab so you can watch a real browser talk to XGW -- Full ICE, DTLS,
and either microphone RTP or a DataChannel -- without wiring a whole SFU.

Think of it as: "start a tiny server, open Chrome, see `dtls=1` light up."

This is a **manual** proof harness. It is not part of the default `mix test`
CI run. Parent docs: [README.md](../../README.md) and
[ARCHITECTURE.md](../../ARCHITECTURE.md).

## What you are proving

In the browser you already know `RTCPeerConnection`. Here the other side is
XGW (`ice_lite: false` = Full ICE):

1. Browser and server exchange SDP (offer/answer) over HTTP
2. Both sides trickle ICE candidates (`POST /candidate`, poll `GET /candidates`)
3. ICE finds a path -> you see `ICE connected`
4. DTLS finishes -> status shows `dtls=1`
5. Optional: mic audio decrypts (`rtp=1`) or DataChannel echoes (`dc=1`)

If that sequence happens, the production `Listener` + `Peer` stack is doing
its job end to end.

## Prerequisites

- OTP 29+ with `:ssl` DTLS-SRTP support
- Chrome or Firefox (a clean profile / hard refresh avoids stale tabs)
- xmedialib and xsockets dependencies

## Happy path (same machine)

```bash
cd xgw
mix deps.get
mix xgw.spike --port 10000 --http-port 8080
```

Then open:

```
http://127.0.0.1:8080/
```

No microphone permission needed. The page adds an audio transceiver so ICE and
DTLS can finish without a live track. That is enough for a first pass.

**Hard-refresh** (Cmd+Shift+R) after every spike restart so you do not reuse
an old Peer from a previous run. Prefer one clean browser window -- a second
tab without the right query flags can "steal" the Peer first.

### Did it work?

Watch the spike terminal and the page status line.

| You want | Look for |
| --- | --- |
| Setup only | `ICE connected`, then `DTLS handshake complete`, status `dtls=1` |
| Real media | Reload with `?mic=1` -> status `dtls=1 rtp=1`, log `SRTP ok ...` |
| Data channel | Open `?dc=1` -> `sctp=1 dc=1`, browser `dcState=echo:ping` |

Default (no mic): `rtp=0` is **expected**. Transceiver-only proves ICE + DTLS,
not SRTP decrypt of live audio.

Typical log order:

1. `ICE connected`
2. `trickle local` (server discovered more candidates after the answer)
3. `DTLS handshake complete`
4. With `?mic=1`: `SRTP ok ssrc=... pt=... payload=...`
5. With `?dc=1`: `SCTP association connected` / `DataChannel open` / `SCTP ok ...`

Answer SDP must **not** include `a=ice-lite` (this harness is Full ICE).
Consent keepalives should not spam `MESSAGE-INTEGRITY false` in a healthy run.

## URL knobs (query string)

| URL | What it does |
| --- | --- |
| `/` | ICE + DTLS only (no mic) |
| `/?mic=1` | Ask for microphone; proves SRTP decrypt (`rtp=1`) |
| `/?dc=1` | Open a DataChannel; server echoes `ping` |
| `/?mic=1&codec=opus` | Default codec (`pt=111` on Chrome) |
| `/?mic=1&codec=pcmu` | G.711 u-law (`pt=0`) |
| `/?mic=1&codec=pcma` | G.711 A-law (`pt=8`) |
| `/?mic=1&codec=g722` | G.722 (`pt=9`) |
| `/?stun=host:port` | Extra browser STUN (helps when host candidates are mDNS-only) |

Examples:

```
http://127.0.0.1:8080/?mic=1
http://127.0.0.1:8080/?dc=1
http://127.0.0.1:8080/?mic=1&codec=pcmu
```

DataChannel needs a working `ex_sctp` build (comes in via xsockets). If SCTP
never comes up, check that dependency first.

## Another machine on the LAN

The answer already tries to include detected host IPs. Only force an address
when auto-detect picks the wrong one (for example a router IP you do not want):

```bash
mix xgw.spike --port 10000 --http-port 8080 --advert-ip 192.168.0.6
```

On a cloud VM: bind `0.0.0.0`, open UDP/TCP for the media port, and either
let auto-detect work or pass a reachable `--advert-ip`. The browser still
does Full ICE (host + srflx from its side).

## Relay-only lab (everything through TURN)

Use this when you want "no public media port" behaviour: colocated
[XTurn](https://github.com/Lazarus404/xturn) on the LAN, spike with
`--relay-only`.

**Terminal 1 -- TURN:**

```bash
cd xturn
XTURN_SERVER_IP=192.168.0.5 XTURN_STUN_PORT=3479 XTURN_API_PORT=8881 mix run --no-halt
```

Mint a long-term user that matches spike defaults:

```bash
curl -s -X POST http://127.0.0.1:8881/auth \
  -H 'Content-Type: application/json' \
  -d '{"username":"xgw","password":"xgwpass","namespace":"/","peer_id":"spike"}'
```

Do this **before** Allocate. Cold auth is a common "why won't relay work?" footgun.

**Terminal 2 -- spike:**

```bash
cd xgw
XGW_SPIKE_TURN_URI=turn:192.168.0.5:3479 \
  mix xgw.spike --port 10000 --http-port 8080 --relay-only
```

Open something like:

```
http://127.0.0.1:8080/?dc=1&stun=192.168.0.5:3479
```

or `?mic=1&stun=...` for media.

**Pass gate:** ICE connected with a `typ relay` local candidate, then
`dtls=1` (prefer `dtls=1 sctp=1 dc=1` or `dtls=1 rtp=1`).

Optional env overrides:

- `XGW_SPIKE_TURN_URI`
- `XGW_SPIKE_TURN_USER`
- `XGW_SPIKE_TURN_PASS`
- `XGW_SPIKE_TURN_REALM`

After CreatePermission, XGW ChannelBinds and prefers ChannelData for ICE,
DTLS, media, and DataChannels. Send Indication is only the fallback before
the channel is bound.

## ICE-TCP (when you want TCP instead of UDP)

```bash
mix xgw.spike --port 10000 --http-port 8080 --ice-tcp --ice-tcp-only
```

`--ice-tcp-only` drops UDP host candidates so the stack must use TCP. That is
the reliable lab mode on a Mac: same-host firewall tricks often cannot block
Chrome's UDP to the machine's own IP.

Open `http://127.0.0.1:8080/?mic=1` and confirm `dtls=1 rtp=1` with a TCP
selected pair. Spike logs mention `transport=tcp` / ICE-TCP DTLS send when
that path is armed.

## Tips that save time

- One window, hard refresh after each restart
- Check `/status` for `trickle=N` and `remote_trickle=M` if candidates feel stuck
- `?mic=1` needs a real mic permission grant or you will sit at `rtp=0`
- Codec query only affects the answer's offered payload; status shows `codec=...`

## Automated checks (not a browser substitute)

These cover HTTP/SDP helpers and optional live tags. They do **not** replace
opening Chrome yourself.

```bash
mix test test/spike/spike_http_test.exs
mix test test/xgw/spike_sdp_test.exs
XTURN_LIVE=1 mix test test/spike/spike_test.exs --include external
mix test test/xgw/ice_tcp_test.exs --include external
```

`:external` tests are skipped unless `XTURN_LIVE=1`.
