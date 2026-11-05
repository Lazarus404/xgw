# XGW

An Elixir **WebRTC gateway**: ICE, DTLS, and SRTP on the wire; plaintext
RTP/RTCP (and optional data channels) for your app.

Ported and updated from an earlier Xirsys media gateway implementation; 
released for public use.

If you have used `RTCPeerConnection` in the browser, you already know the hard
parts -- finding a path (ICE), securing it (DTLS), encrypting media (SRTP).
XGW is the **server-side half** of that peer connection. Your product still
owns signaling (offer/answer over WebSocket or similar). XGW takes over once
you have SDP.

Home: [https://github.com/Lazarus404/xgw](https://github.com/Lazarus404/xgw)

How the pieces fit together (friendly walkthrough):
[ARCHITECTURE.md](ARCHITECTURE.md).

## What problem this solves

Browsers speak encrypted WebRTC. Your media server wants **clear** packets so it
can mix, forward, or inspect them.

XGW sits in the middle:

```
Browser  -- ICE + DTLS + SRTP -->  XGW  -- plaintext RTP/RTCP -->  your app
```

Typical hosts are SFUs or media servers -- the same product role as
[Janus](https://janus.conf.meetecho.com/), [mediasoup](https://mediasoup.org/),
or [LiveKit](https://livekit.io/): they own rooms and signaling, then call into
`XGW.Peer`. Under the hood XGW leans on
[xsockets](https://github.com/Lazarus404/xsockets) for listeners/sockets and
[xmedialib](https://github.com/Lazarus404/xmedialib) for STUN/RTP/SRTP/SDP
helpers.

## Mental model (JS -> XGW)

| You already know | Rough XGW match |
| --- | --- |
| One `RTCPeerConnection` | One `XGW.Peer` process |
| `setRemoteDescription` / answer | `XGW.Peer.apply_descriptions/4` |
| `addIceCandidate` / `onicecandidate` | `add_remote_candidate/2` and `{:xgw, :local_candidate, ...}` |
| Media after connected | `{:xgw, :rtp, ...}` in / `SendHandle` out |
| Data channels | `XGW.Peer.Datachannel` + handler messages |

**Listener** = shared media port. **Peer** = one remote browser on that port.

## What you get

- Shared UDP listener with multi-peer demux (STUN / DTLS / RTP on one socket)
- ICE-lite by default; optional ICE-full (checks, nomination, srflx/relay gather)
- Trickle ICE both ways; consent freshness so dead paths close cleanly
- DTLS-SRTP handshake, fingerprint check, per-SSRC encrypt/decrypt
- Hot-path outbound RTP via `Peer.SendHandle` (skip GenServer when you can)
- Optional SCTP data channels over DTLS
- Optional ICE-TCP when UDP is blocked
- SDP helpers that turn offer/answer into transport config
- Browser spike harness: `mix xgw.spike`

## Main modules

You will touch these first:

| Module | Job in plain English |
| --- | --- |
| `XGW.Listener` | Shared UDP (+ optional TCP) port; classify packets; route to Peers |
| `XGW.Peer` | One remote client: ICE -> DTLS -> SRTP -> events to your handler |
| `XGW.Descriptions` | Parse SDP offer/answer into ICE creds, fingerprints, SSRC maps |
| `XGW.Demux` | "Is this STUN, DTLS, or media?" from the first byte |
| `XGW.ICE` / `Lite` / `Full` | Find a working network path |
| `XGW.DTLS` | Secure the path and export SRTP keys |
| `XGW.SRTPSession` | Encrypt outbound / decrypt inbound media |
| `XGW.Peer.SendHandle` | Fast outbound RTP after DTLS is up |
| `XGW.Peer.Datachannel` | Optional data-channel child (keeps Peer free for media) |

Full module map and call lifecycle: [ARCHITECTURE.md](ARCHITECTURE.md).

## ICE-lite vs ICE-full (quick pick)

**ICE-lite (default):** the browser does most connectivity-check work; XGW
answers STUN Bindings and tracks consent. Simple. Fine when the server address
is stable and well advertised.

**ICE-full (`ice_lite: false`):** XGW runs the full checklist -- pairs, checks,
nomination -- and can gather srflx/relay candidates (and trickle them to the
browser). Use this for tougher NATs, relay-heavy deploys, or when you need
ICE-TCP.

Either mode emits familiar handler messages like `{:xgw, :ice_connected, peer}`
and `{:xgw, :dtls_connected, peer}` when setup succeeds.

## RFCs (the specs we implement)

You do not need to read these to run tests. They are here when you want the
official wording:

- [RFC 8445](https://www.rfc-editor.org/rfc/rfc8445) -- ICE
- [RFC 8489](https://www.rfc-editor.org/rfc/rfc8489) -- STUN
- [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656) -- TURN (relay gather)
- [RFC 7675](https://www.rfc-editor.org/rfc/rfc7675) -- consent freshness
- [RFC 7983](https://www.rfc-editor.org/rfc/rfc7983) -- demux on one port
- [RFC 5761](https://www.rfc-editor.org/rfc/rfc5761) -- RTP/RTCP mux
- [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147) / [RFC 6347](https://www.rfc-editor.org/rfc/rfc6347) -- DTLS
- [RFC 5764](https://www.rfc-editor.org/rfc/rfc5764) -- DTLS-SRTP
- [RFC 3711](https://www.rfc-editor.org/rfc/rfc3711) -- SRTP
- [RFC 8838](https://www.rfc-editor.org/rfc/rfc8838) -- trickle ICE
- [RFC 8261](https://www.rfc-editor.org/rfc/rfc8261) / [RFC 8831](https://www.rfc-editor.org/rfc/rfc8831) -- SCTP data channels over DTLS
- [RFC 8866](https://www.rfc-editor.org/rfc/rfc8866) -- SDP

## Dependencies

- [xmedialib](https://github.com/Lazarus404/xmedialib) -- STUN, RTP, RTCP, SRTP, SDP helpers
- [xsockets](https://github.com/Lazarus404/xsockets) -- listeners and sockets

Local checkouts before remotes catch up:

```bash
mix deps.get
mix test
```

## Browser spike

Want to see a real Chrome/Firefox peer talk to XGW without wiring a full SFU?

```bash
mix xgw.spike --port 10000 --http-port 8080
```

Open the printed URL, allow mic if asked, and watch ICE/DTLS/RTP come up.
Steps and outcome notes: `test/spike/README.md`.

ICE-TCP variant:

```bash
mix xgw.spike --ice-tcp
```

## Tests

Default suite (unit + integration, no live browser):

```bash
mix test
```

Spike tests under `test/spike/` are tagged `:external` and excluded by default.

## Related reading in this package

- [ARCHITECTURE.md](ARCHITECTURE.md) -- layers, lifecycle, demux, module map
- `test/spike/README.md` -- manual browser interop steps
