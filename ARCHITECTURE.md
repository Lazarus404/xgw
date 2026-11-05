# XGW architecture

This note is for people who know WebRTC from the **JavaScript** side
(`RTCPeerConnection`, `getUserMedia`, `onicecandidate`) and want a friendly map
of how XGW is built -- without living in RFCs all day.

**One-line summary:** XGW is the server-side half of a browser peer connection.
It finishes ICE, DTLS, and SRTP for you, then hands your app **plaintext**
RTP/RTCP (and optional data-channel messages).

If you just want to run tests or the browser spike, start with
[README.md](README.md).

## Where XGW sits

```
Browser (RTCPeerConnection)
        |
   ICE + DTLS + SRTP on UDP/TCP
        v
     XGW (this package)
        |
   plaintext RTP / RTCP / datachannel events
        v
Your app (+ signaling)
```

Related pieces (not this package):

| Package                                              | Job                                                    |
|------------------------------------------------------|--------------------------------------------------------|
| [xsockets](https://github.com/Lazarus404/xsockets)   | Shared listeners / sockets (UDP, TCP, DTLS plumbing)   |
| [xsdp](https://github.com/Lazarus404/xsdp)           | SDP exchange processing library                        |
| [xsip](https://github.com/Lazarus404/xsip)           | Stateful SIP protocol engine                           |
| [xmedialib](https://github.com/Lazarus404/xmedialib) | STUN / RTP / RTCP / SRTP codecs and SDP helpers        |
| [XTurn](https://github.com/Lazarus404/xturn)         | Optional TURN relay when you gather `relay` candidates |

XGW does **not** replace your signaling server. You still exchange SDP offer/answer
(and trickle candidates) over WebSocket/HTTP/SIP. XGW takes over once you have
those descriptions.

## Mental model (JS -> XGW)

| You already know | What XGW does |
|---|---|
| `RTCPeerConnection` | Roughly one `XGW.Peer` GenServer |
| `setRemoteDescription` / `setLocalDescription` | `XGW.Peer.apply_descriptions/4` |
| `onicecandidate` / `addIceCandidate` | `add_remote_candidate/2` + `{:xgw, :local_candidate, ...}` |
| ICE "connected" | `{:xgw, :ice_connected, peer}` |
| DTLS fingerprint in SDP | Verified during DTLS; mismatch closes the peer |
| Encrypted media on the wire | `XGW.SRTPSession` decrypts inbound / encrypts outbound |
| `pc.ontrack` / sending RTP | Your handler gets `{:xgw, :rtp, ...}`; send with `SendHandle` |
| `createDataChannel` / `onmessage` | `XGW.Peer.Datachannel` + `{:xgw, :datachannel_message, ...}` |

Think of **Peer** as "one remote browser," and **Listener** as "the shared UDP
port many peers can share."

## Layers (big picture)

```
Browser
   |
   |  STUN / DTLS / SRTP / (optional) SCTP-over-DTLS
   v
XGW.Listener          shared UDP (+ optional ICE-TCP)
   |
   |  Demux: what kind of packet is this?
   v
XGW.Peer              one process per remote client
   |-- ICE (lite or full)     find a working path
   |-- DTLS                   authenticate + export SRTP keys
   |-- SRTPSession            encrypt/decrypt media
   +-- Peer.Datachannel       optional SCTP data channels
          |
          v
   your handler pid           plaintext RTP/RTCP/DC events
```

**Rule of thumb:** ICE and DTLS are "setup." After `{:xgw, :dtls_connected, ...}`,
media is the hot path (decrypt/encrypt and ship bytes). Data channels ride DTLS
application data in a child process so they do not block ICE/RTP on the Peer.

## Lifecycle of one call

```
1. Host starts a Listener (one media port)
2. Host starts a Peer, registers it on the Listener
3. Signaling: browser offer <-> your answer (you build SDP)
4. Peer.apply_descriptions(offer, answer, ...)
5. ICE finds a pair  ->  {:xgw, :ice_connected, peer}
6. DTLS finishes     ->  {:xgw, :dtls_connected, peer}
7. Media flows       ->  {:xgw, :rtp, ...} / send_rtp / SendHandle
8. Optional DC open  ->  {:xgw, :datachannel, ...}
9. Close / consent fail / fingerprint mismatch -> {:xgw, :closed, ...}
```

Embed host (and maybe srflx/relay) `a=candidate:` lines in the answer *before*
`apply_descriptions/4` when you can. Full ICE can also trickle more locals
afterward via handler messages.

## Packet kinds on one socket (demux)

WebRTC multiplexes several protocols on the **same** IP:port. The first byte
of each UDP datagram says which protocol it is (`XGW.Demux`, RFC 7983):

| Roughly | What it is | What happens next |
|---|---|---|
| STUN | "Are you there?" / ICE checks | Routed to a Peer by ICE ufrag |
| DTLS | Security handshake | Routed by remote `{ip,port}` after bind |
| RTP / RTCP | Media / media control | Decrypt with SRTP, notify handler |
| TURN ChannelData | Media wrapped for a TURN relay | Unwrap, then demux again |

So the Listener is a busy receptionist: classify the envelope, look up which
Peer owns it, forward the bytes.

## ICE-lite vs ICE-full (plain English)

**ICE-lite (default):** the server is mostly passive. The browser does the
heavy connectivity-check work; XGW answers STUN Bindings and tracks consent.
Simpler. Good when the server has a stable public (or well-advertised) address.

**ICE-full (`ice_lite: false`):** XGW runs a full checklist (RFC 8445): form
pairs, send checks, nominate a pair, then emit `{:xgw, :ice_connected, ...}`
before DTLS. Use this when you need srflx/relay gather, trickle locals, or
tougher NAT situations. Optional ICE-TCP for environments where UDP is blocked.

Note: If the IP your server sees maps 1:1 to the IP your peers see, such that
all traffic to the external IP is sent directly to your server, then you 
probably need ICE-lite. Otherwise, use ICE-full.

Either way, **consent freshness** (RFC 7675) keeps checking that the path is
still alive. If consent fails, the Peer closes with `:consent_failed`.

## Module map

### Entry and boot

| Module | Plain English |
|---|---|
| `XGW` | Package overview |
| `XGW.Application` | Boot: patch OTP DTLS demux, ensure ETS tables, start `PeerSupervisor` |
| `XGW.PeerSupervisor` | DynamicSupervisor that owns Peer processes |

Listeners are started by the **host** (your SFU/app, the browser spike, or
tests) -- not auto-bound in `Application`.

### Shared socket and routing

| Module | Plain English |
|---|---|
| `XGW.Listener` | Shared UDP (+ optional TCP) socket; demux + dispatch to Peers |
| `XGW.Listener.TCP` | ICE-TCP accept / connect helpers via xsockets TCP |
| `XGW.Demux` | First-byte classify: STUN vs DTLS vs media vs TURN channel |
| `XGW.Certs` | DTLS certificate / fingerprint helpers for SDP |

### One remote client

| Module | Plain English |
|---|---|
| `XGW.Peer` | Lifecycle GenServer: ICE -> DTLS -> SRTP -> handler events |
| `XGW.Peer.Gather` | Post-answer local candidate gather (srflx/relay) |
| `XGW.Peer.Turn` | TURN allocate / channel bind / relay wrap-unwrap |
| `XGW.Peer.Sctp` | Start SCTP association when the SDP asks for data channels |
| `XGW.Peer.Datachannel` | Child process: SCTP + DTLS app-data so Peer stays responsive |
| `XGW.Peer.SendHandle` | Hot-path outbound RTP (ETS + encrypt + UDP send) |

### ICE family

| Module | Plain English |
|---|---|
| `XGW.ICE` | Shared types, priorities, role helpers, candidate merge |
| `XGW.ICE.Gather` | Build host / srflx / relay candidates |
| `XGW.ICE.Lite` | Lite Binding answers + trickle remote merge |
| `XGW.ICE.Full` | Full agent: checks, nomination, phases |
| `XGW.ICE.Checklist` | Pair formation / sort / prune / check state |
| `XGW.ICE.Consent` | Keepalive probes and expiry |
| `XGW.ICE.Binding` | STUN Binding helpers |
| `XGW.TURN.Client` | TURN Allocate / Refresh / Delete for gather |
| `XGW.Stun.TCP` | STUN-over-TCP helpers when ICE-TCP is on |

### Security and media

| Module | Plain English |
|---|---|
| `XGW.Descriptions` | SDP offer/answer -> ICE creds, fingerprints, SSRC/mid maps |
| `XGW.DTLS` | Server-side DTLS-SRTP accept, handshake, fingerprint check |
| `XGW.DTLS.Transport` | Shared-socket DTLS I/O (not a private `:gen_udp` per peer) |
| `XGW.DTLS.SrtpKeys` | Export SRTP keys after the handshake |
| `XGW.DTLS.OtpDemux` | OTP patch so DTLS can share the Listener UDP socket |
| `XGW.SRTPSession` | Per-SSRC protect / unprotect |

### Edge-to-edge trunk (multi-home)

| Module | Plain English |
|---|---|
| `XGW.Trunk.Pipe` | SFU-to-SFU UDP+SRTP path (not WebRTC/ICE, not Distributed Erlang) |
| `XGW.Trunk.Crypto` / `Frame` | Keys and frame layout for that trunk |

## Supervision model

```
XGW.Application
   |
   +-- XGW.Supervisor
          |
          +-- XGW.PeerSupervisor (DynamicSupervisor)
                 |
                 +-- XGW.Peer  (one per remote client)
                        |
                        +-- XGW.Peer.Datachannel  (optional child)
```

`XGW.Listener` processes are started by the host and sit beside this tree.
Each Peer is monitored/registered with a Listener for demux keys (ufrag,
remote 5-tuple, TURN channel).

## Control vs media (why it feels like two speeds)

Same idea as separating signaling from media in the browser.

| Kind of traffic | Examples | Where it runs |
|---|---|---|
| Setup / control | ICE STUN, DTLS handshake, consent | Peer GenServer (+ Listener demux) |
| Media hot path | RTP/RTCP after keys exist | Decrypt on ingress; `SendHandle` on egress |
| Data channels | SCTP messages over DTLS | `Peer.Datachannel` child (batched send) |

Media after DTLS should not wait behind a slow data-channel burst. That is why
DC has its own process.

## How hosts usually wire it

1. Start `XGW.Listener` on your media IP/port (gather opts if you need srflx/relay).
2. Start `XGW.Peer` with a `handler` pid (your session process).
3. `Listener.register_peer/2` (and later `bind_ufrag` / `bind_remote` as ICE progresses).
4. Build an SDP answer (host candidates from `gather_candidates/2` or
   `host_candidate_lines/1`).
5. `Peer.apply_descriptions/4` with the remote offer and local answer.
6. Trickle remote candidates with `add_remote_candidate/2` as they arrive.
7. On `{:xgw, :dtls_connected, peer}`, take `outbound_handle/1` and ship RTP.
8. Handle `{:xgw, :rtp, ...}` / `{:xgw, :rtcp, ...}` / datachannel messages.

For a hands-on browser path, see `mix xgw.spike` and `test/spike/README.md`.

## Dependencies (what XGW leans on)

- **xsockets** -- UDP/TCP listen and connect, DTLS-friendly shared socket use,
  WebRTC SCTP association helpers (`XSockets.Sctp.Association`)
- **xmedialib** -- STUN parse/build, RTP/RTCP structs, SRTP crypto, SDP candidate
  and fingerprint types

XGW is the "glue + state machine" between those libraries and your product.

## Related reading in this package

- [README.md](README.md) -- quick start, ICE-lite vs full, spike and tests
- `test/spike/README.md` -- manual browser interop steps
