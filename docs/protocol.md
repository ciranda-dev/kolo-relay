# Protocol and design

## Design

- The relay is opt-in for every call: no discovery, no automatic use, no fallback.
- End-to-end security is kolo-secure's own handshake on an inner QUIC connection, not a second design; the relay is not a TLS endpoint of that connection, so its exporter values differ from anything the relay can make.
- Each side runs the inner connection on a virtual `net.PacketConn` over its connection to the relay (`kolotransport.ListenConn`); the dialer's listener refuses every incoming attempt, the target's accepts exactly one.
- Inner packets travel as frames on the session's stream, or as QUIC datagrams (RFC 9221) when the application opts in with `Transport.Datagrams` in `Config.Relay` and the relay offers them. A stream is reliable and ordered, so a packet lost between a peer and the relay is resent and every packet behind it waits: the inner congestion control sees delay, never loss. A datagram is not resent, so the inner connection sees the loss and recovers as on a direct path.
- The virtual conn never blocks a write: when `SendQueue` is full its oldest packet is dropped, as on UDP, so the inner congestion control sees loss instead of stalling, and the newest packet, such as a CONNECTION_CLOSE, is kept. A datagram that the connection's full send queue (32) refuses is dropped the same way.
- Closing a relayed connection drops the packets still queued and sends only the newest one, the CONNECTION_CLOSE, for at most 1s, then waits at most 1s for the other side to end its stream, so the close code reaches the peer instead of being lost to a reset or a slow relay; with the other side gone, `Close` takes about 2s. A relay too slow to pass even that packet within 1s loses the code, and the peer sees the session end instead. When the relay ends a session, each side's `Conn` closes within about 1s, after quic-go has handled the packets that were still on their way.
- Packets keep quic-go's sizes: path MTU discovery is off on a virtual conn, so they stay at the 1200 bytes kolo-transport starts with, and frames and datagrams accept up to 1452.
- One relay connection has one role, set by its first stream: a reservation, or one session. Any further stream from the client, unidirectional ones included, closes it with code 1, and a refused client's stream is stopped at once; data a client sends that the relay has not read is bounded by the receive windows, counted in the memory bound. Floods must open new connections, which kolo-transport (Retry, `MaxConns`, `MaxConnsPerIP`) and kolo-secure (`MaxPending`) bound.
- The relay never dials anyone and only joins two of its own authenticated clients, towards a key that reserved, so it is not an open proxy.
- The relay sends the chunks that arrive within `FlushInterval` of its last write in one write, because quic-go keeps a 1452-byte buffer for every unacknowledged STREAM frame, however small.
- Each byte the relay sends is a byte it read from another authenticated client, paced by that client's token bucket (golang.org/x/time/rate) and counted against the session's limits; nothing is amplified. A frame waits for the bucket; a datagram the bucket cannot pay at once is dropped, as a router polices. In a version 1 session each packet also costs 37 bytes, the per-packet overhead kolo-transport reserves for a datagram, so small packets cannot multiply the work per byte.
- Sessions end, on both streams, at `MaxSessionDuration`, `MaxSessionBytes` in either direction (exactly that many bytes pass in a version 0 session; a version 1 session forwards whole packets, so the packet that would pass it ends the session), `SessionIdleTimeout` with no packet on either path either way (a stalled writer counts as idle, and so does a datagram the bucket drops), the other side's reset, or `Server.Close`. Keep-alive is always on, so a session between two peers that are still up never reaches a `SessionIdleTimeout` above their `KeepAlivePeriod` (5s by default against 60s); `MaxSessionDuration` and `MaxSessionBytes` still end it, and `AllowReserve` is the defense against holding slots.
- A reservation ends after `ReservationLifetime`; sessions it already carries go on, and the peer must reserve again, which re-runs `AllowReserve`.
- The relay signs nothing and holds no client key: authentication to it, and between peers, is kolo-secure's.
- What the relay learns: both keys of every session, both clients' addresses, which keys hold reservations, when sessions start and end, and the sizes and timing of the inner packets. It cannot read or change them, and it can always drop, delay or end them.
- Two encryptions per packet and two flow controls: the outer windows to the relay and the inner windows end to end both limit throughput. Only loopback tests exist; throughput on real networks is not measured.

## Formats

Control messages are framed as one length byte (1 to 64) and a body in
[kolo-codec](https://github.com/ciranda-dev/kolo-codec) encoding:

| Type | Direction | Body |
|---|---|---|
| 1 Reserve | client to relay, its first stream | `uvarint(1) ‖ uvarint(version)` |
| 2 Connect | client to relay, its first stream | `uvarint(2) ‖ uvarint(version) ‖ target key (32)` |
| 3 Incoming | relay to target, on a stream the relay opens | `uvarint(3) ‖ uvarint(version) ‖ initiator key (32)` |
| 4 Status | answer to 1, 2 and 3 | `uvarint(4) ‖ uvarint(code)` |

Status codes: 0 OK, 1 Unavailable, 2 NotAllowed, 3 Limit, 4
UnsupportedVersion. The version is checked before the rest of the
message: 0 and 1 have the same layout, any other is UnsupportedVersion.

Version 0 carries packets only as frames on the session's stream.
Version 1 also carries them as QUIC datagrams:

- After an OK to Connect and Incoming, both streams carry packet frames,
  `uvarint(length) ‖ packet` with a length from 1 to 1452.
- A datagram's payload is `uvarint(quarter stream ID) ‖ packet`, the
  packet 1 to 1452 bytes. The quarter stream ID is the ID of the
  session's stream on that connection divided by 4 (RFC 9297 section
  2.1): the initiator's Connect stream, or the target's Incoming stream,
  so a reservation's connection carries the datagrams of many sessions.
  The division is an integer division. RFC 9297 defines it for
  client-initiated bidirectional streams, and an Incoming stream is one
  the relay opens (IDs 1, 5, 9 and so on), so the division drops its low
  bits. The ID is still unambiguous because one connection has one role:
  a session connection carries only its Connect stream, and on a
  reservation's connection only the Incoming streams carry sessions
  (the control stream carries none).
  The relay translates the ID between the two legs. A datagram that does
  not parse or names no open session is dropped, never an error: it may
  arrive after its session ended.
- Sending rule, at each client and at the relay, for each leg on its
  own: a packet goes as a datagram when that leg speaks version 1 and
  the connection's datagram queue takes it. One that does not fit in a
  packet of the connection's current size goes as a frame on the stream;
  one that the full queue refuses is dropped, so the inner connection
  sees a loss. Packets from both paths reach the same inner connection;
  mixing them can reorder packets, which QUIC tolerates (RFC 9002
  section 6.1). The last packet a side sends before it ends its stream,
  normally the CONNECTION_CLOSE, also goes as a frame, so a full queue
  cannot lose it.
- MTU: inner packets stay at 1200 bytes, and a datagram carries the
  connection's packet size minus 37 bytes. A 1200-byte packet and its ID
  fit once the outer packet size reaches 1238 bytes. Outer connections
  start at 1200 bytes and grow by path MTU discovery, which probes about
  5 round trips after the handshake, so a new connection carries
  full-size packets as frames for its first moments and as datagrams
  after; on a path that never carries more, every full-size packet stays
  a frame. The inner handshake's Initial packets usually travel as
  frames for the same reason.
- Choice of version: a client speaks version 1 when its connection to
  the relay supports datagrams (both ends set
  `kolotransport.Config.Datagrams`), else version 0. The relay offers
  datagrams by default and a client does not, so a client speaks version
  1 only after its application sets `Transport.Datagrams` in
  `Config.Relay`; the measurement in limits.md shows why. A relay answers
  version 1 on a connection without datagrams with UnsupportedVersion.
  The relay sends Incoming in the version the target reserved with, so a
  version 0 target never receives a datagram.
- Interop: an older relay never offers datagrams, so new clients speak
  version 0 to it; older clients speak version 0 to a new relay. A relay
  that offers datagrams but answers version 1 with UnsupportedVersion,
  such as an older relay whose listener was given `Datagrams`, gets the
  same Reserve or Connect once more in version 0, on a new connection;
  an UnsupportedVersion answer to version 0 is `ErrUnsupportedVersion`. A
  session whose two legs speak version 0 is copied as bytes, without
  parsing. A session with a version 1 leg is forwarded packet by packet:
  the relay reads the frames of both streams and the datagrams of each
  version 1 connection and sends each packet to the other leg by the
  sending rule, with a queue of 32 packets per direction. A packet from a
  stream waits while the queue is full, so the stream stays flow
  controlled; a packet from a datagram is dropped.

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
- [RFC 9221, An Unreliable Datagram Extension to QUIC](https://www.rfc-editor.org/info/rfc9221) (Proposed Standard, March 2022).
  Takes: inner packets as DATAGRAM frames, dropped rather than queued without bound.
- [RFC 9297, HTTP Datagrams and the Capsule Protocol](https://www.rfc-editor.org/info/rfc9297) (Proposed Standard, August 2022).
  Takes: the quarter stream ID that tags each datagram, and a stream as the fallback when a datagram cannot be used.
  Not implemented: HTTP and capsules; a too-large packet takes the stream instead of being dropped, since path MTU discovery is off on the inner connection.
