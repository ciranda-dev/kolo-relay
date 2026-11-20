# Protocol and design

## Design

- The relay is opt-in for every call: no discovery, no automatic use, no fallback.
- End-to-end security is kolo-secure's own handshake on an inner QUIC connection, not a second design; the relay is not a TLS endpoint of that connection, so its exporter values differ from anything the relay can make.
- Each side runs the inner connection on a virtual `net.PacketConn` over its stream to the relay (`kolotransport.ListenConn`); the dialer's listener refuses every incoming attempt, the target's accepts exactly one.
- The virtual conn never blocks a write: when `SendQueue` is full its oldest packet is dropped, as on UDP, so the inner congestion control sees loss instead of stalling, and the newest packet, such as a CONNECTION_CLOSE, is kept.
- Closing a relayed connection drops the packets still queued and sends only the newest one, the CONNECTION_CLOSE, for at most 1s, then waits at most 1s for the other side to end its stream, so the close code reaches the peer instead of being lost to a reset or a slow relay; with the other side gone, `Close` takes about 2s. A relay too slow to pass even that packet within 1s loses the code, and the peer sees the session end instead. When the relay ends a session, each side's `Conn` closes within about 1s, after quic-go has handled the packets that were still on their way.
- Packets keep quic-go's sizes: path MTU discovery is off on a virtual conn, so they stay at the 1200 bytes kolo-transport starts with (1280 before its v0.1.5), and frames accept up to 1452.
- One relay connection has one role, set by its first stream: a reservation, or one session. Any further stream from the client, unidirectional ones included, closes it with code 1, and a refused client's stream is stopped at once; data a client sends that the relay has not read is bounded by the receive windows, counted in the memory bound. Floods must open new connections, which kolo-transport (Retry, `MaxConns`, `MaxConnsPerIP`) and kolo-secure (`MaxPending`) bound.
- The relay never dials anyone and only joins two of its own authenticated clients, towards a key that reserved, so it is not an open proxy.
- The relay sends the chunks that arrive within `FlushInterval` of its last write in one write, because quic-go keeps a 1452-byte buffer for every unacknowledged STREAM frame, however small.
- Each byte the relay sends is a byte it read from another authenticated client, paced by that client's token bucket (golang.org/x/time/rate) and counted against the session's limits; nothing is amplified.
- Sessions end, on both streams, at `MaxSessionDuration`, `MaxSessionBytes` in either direction (exactly that many bytes pass), `SessionIdleTimeout` with no byte either way (a stalled writer counts as idle), the other side's reset, or `Server.Close`. Keep-alive is always on, so a session between two peers that are still up never reaches a `SessionIdleTimeout` above their `KeepAlivePeriod` (5s by default against 60s); `MaxSessionDuration` and `MaxSessionBytes` still end it, and `AllowReserve` is the defense against holding slots.
- A reservation ends after `ReservationLifetime`; sessions it already carries go on, and the peer must reserve again, which re-runs `AllowReserve`.
- The relay signs nothing and holds no client key: authentication to it, and between peers, is kolo-secure's.
- What the relay learns: both keys of every session, both clients' addresses, which keys hold reservations, when sessions start and end, and the sizes and timing of the inner packets. It cannot read or change them, and it can always drop, delay or end them.
- Two encryptions per packet and two flow controls: the outer windows to the relay and the inner windows end to end both limit throughput. Only loopback tests exist; throughput on real networks is not measured.

## Formats

Control messages are framed as one length byte (1 to 64) and a body in
[kolo-codec](https://github.com/ciranda-dev/kolo-codec) encoding:

| Type | Direction | Body |
|---|---|---|
| 1 Reserve | client to relay, its first stream | `uvarint(1) ‖ uvarint(version 0)` |
| 2 Connect | client to relay, its first stream | `uvarint(2) ‖ uvarint(version 0) ‖ target key (32)` |
| 3 Incoming | relay to target, on a stream the relay opens | `uvarint(3) ‖ uvarint(version 0) ‖ initiator key (32)` |
| 4 Status | answer to 1, 2 and 3 | `uvarint(4) ‖ uvarint(code)` |

Status codes: 0 OK, 1 Unavailable, 2 NotAllowed, 3 Limit, 4
UnsupportedVersion. Version 0 accepts only 0. After an OK to Connect and
Incoming, both streams carry packet frames, `uvarint(length) ‖ packet`
with a length from 1 to 1452, which the relay copies without parsing.

Codes on the connection or streams to the relay: 1 protocol violation or
refused stream, 2 reservation lifetime over, 3 reservation replaced, 4
relay closing.
Session end codes on both streams: 1 duration, 2 bytes, 3 idle, 4 other
side ended, 5 relay closing. There is no JSON form.

## References

- [RFC 8656, TURN: Relay Extensions to STUN](https://www.rfc-editor.org/info/rfc8656) (Proposed Standard, February 2020).
  Takes: allocations, lifetimes, quotas.
  Not implemented: the TURN and STUN wire format.
- [RFC 8445, ICE: A Protocol for NAT Traversal](https://www.rfc-editor.org/info/rfc8445) (Proposed Standard, July 2018).
  Takes: the relayed path as a last resort.
  Not implemented: candidate gathering and connectivity checks.
- [RFC 8827, WebRTC Security Architecture](https://www.rfc-editor.org/info/rfc8827) (Proposed Standard, January 2021).
  Takes: the WebRTC security model for relays.
- [WebRTC: Real-Time Communication in Browsers](https://www.w3.org/TR/webrtc/#dom-rtcicetransportpolicy) (W3C Recommendation, 13 March 2025).
  Takes: the `iceTransportPolicy` idea, the application chooses whether a relay is used.
- [RFC 9000, QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/info/rfc9000) (Proposed Standard, May 2021).
  Takes: QUIC through [kolo-transport](https://github.com/ciranda-dev/kolo-transport).
