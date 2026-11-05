defmodule XGW do
  @moduledoc """
  XGW is a **media gateway**: it sits between a browser (or other WebRTC client)
  and your application so you do not have to implement ICE, DTLS, and SRTP yourself.

  ## What problem this solves

  Real-time audio/video on the public internet is not a plain TCP socket. Clients
  must:

  1. Find a working UDP (or TCP) path through NATs and firewalls (**ICE**).
  2. Authenticate each other and encrypt the path (**DTLS**).
  3. Protect media packets with short-lived keys (**SRTP** / **SRTCP**).

  XGW terminates that stack per remote peer and delivers **plaintext** RTP/RTCP
  (and optional data-channel bytes) to a handler you register. Your app owns
  rooms, signaling (SIP/WebSocket/HTTP), and SDP answers -- the same split as
  an SFU such as Janus or mediasoup, or a SIP path with
  [xsip](https://github.com/Lazarus404/xsip) and
  [xsdp](https://github.com/Lazarus404/xsdp).

  ## Main pieces

  ```text
  UDP/TCP Listener  -- demux STUN / DTLS / media -->  Peer GenServer
                                                          |
                                                          v
                                                    ICE then DTLS
                                                          |
                                                          v
                                                    SRTP decrypt/encrypt
                                                          |
                                                          v
                                                    your handler (RTP callbacks)
  ```

  - `XGW.Listener` -- shared socket(s) and packet demux.
  - `XGW.Peer` -- one remote endpoint's ICE/DTLS/SRTP lifecycle.
  - `XGW.ICE.*` -- connectivity checks and candidate gathering.
  - `XGW.DTLS.*` -- handshake transport and SRTP key export.
  - `XGW.SRTPSession` -- encrypt/decrypt media after DTLS.

  See `ARCHITECTURE.md` in this package for ICE-lite vs full, demux, and the
  module map.

  ## RFCs

  Primary stack: RFC 8445 (ICE), RFC 8489 (STUN), RFC 8656 (TURN), RFC 9147 /
  RFC 6347 (DTLS), RFC 5764 (DTLS-SRTP), RFC 3711 (SRTP), RFC 7983 (demux),
  RFC 8866 (SDP). See child modules for narrower citations.
  """
end
