# Limits

Every option, default and bound of kolo-relay, with the reason for it, and how much memory and bandwidth a relay can use.

## Server

The defaults suit a trial on a host with about 8 GiB (the worst-case heap below is 7.3 GiB) and leave the relay open to every key. Before you expose a relay, set `AllowReserve` and size `MaxConns`, the receive windows and `MaxSessions` for your host (the recipe for a 300 MiB host is below); the README says the same in short.

`ServerConfig` (nil or a zero field means the default; out of range is
`ErrInvalidConfig`):

| Option | Default | Range | Why |
|---|---|---|---|
| `Secure` (the relay's kolo-secure listener) | nil: the listener rows below | any `*kolosecure.Config`, used as given | Protocol: a non-nil one sets every listener field. |
| `MaxReservations` | 64 | 1 to 100000 | Security: it bounds the table a flood of free keys fills. |
| `MaxSessions` (being set up or open) | 16 | 1 to 10000 | Memory: it bounds the egress (2 × `MaxSessions` × `RateBytes`) and the send term of the heap. |
| `MaxSessionsPerPeer` (started by one key) | 4, or `MaxSessions` if lower | 1 to `MaxSessions` | Security: one key cannot take every session. |
| `MaxSessionsPerTarget` (towards one reserved key) | 8, or `MaxSessions` if lower | 1 to `MaxSessions` | Security: one target cannot be flooded with sessions. |
| `ReservationLifetime` | 1h | 1s to 24h | Security: a stale reservation ends and `AllowReserve` runs again. |
| `MaxSessionDuration` | 1h | 1s to 24h | Security: a session cannot hold its slot forever. |
| `MaxSessionBytes` (each direction) | 1 GiB | 64 KiB to 1 TiB | Security: it bounds the egress one session costs. |
| `SessionIdleTimeout` (no byte either way) | 60s | 1s to 10m | Security: it ends quiet sessions. Keep-alive is always on, so a session between two peers that are still up never reaches a `SessionIdleTimeout` above their `KeepAlivePeriod` (5s by default); it lasts until `MaxSessionDuration` or `MaxSessionBytes`, and `AllowReserve` is the defense against holding slots. A smaller `SessionIdleTimeout`, or a `Peer` `KeepAlivePeriod` above it, still ends quiet sessions. |
| `ConnectTimeout` (target accepts a session) | 15s | 1s to 60s | Protocol: default clients wait `ControlTimeout` 20s for the answer, so a `ConnectTimeout` above about 15s needs clients with a longer `ControlTimeout`. |
| `ControlTimeout` (client's first message) | 15s | 1s to 60s | Security: it bounds a client's first message; kolo-secure bounds the TLS handshake apart (`HandshakeTimeout` 10s). |
| `RateBytes` (read from each client connection, bytes/s) | 1 MiB | 16 KiB to 1 GiB | Security: an open relay pays for every byte it forwards. |
| `RateBurst` (bytes) | 256 KiB | 16 KiB to 64 MiB | Security: kept with `RateBytes`. |
| `FlushInterval` (shortest time between two writes of less than a full buffer, in one direction of a session) | 1ms | 100µs to 100ms | Memory: it holds a direction to about 1000 writes and about 1690 STREAM frames per second at the default `RateBytes` (below). |
| `AllowReserve func(key) bool` | nil: every key, and `Listen` logs a warning | a panic refuses | A policy hook, not a limit. Set it before the relay is reachable: see "Keys are free to make" below. |
| `AllowConnect func(from, to) bool` | nil: every pair | a panic refuses; must be fast: it runs before a session slot is taken, and `Close` waits for calls in progress | A policy hook, not a limit. |
| `Logger` | nil: `slog.Default()` | any `*slog.Logger` | Receives the one warning of an open relay. |
| copy buffer per direction | 64 KiB | fixed | Protocol: the relay reads a byte stream, and the buffer matches the 64 KiB stream window, so one read can take all a client has in flight on the stream. |
| control message | 64 bytes | fixed | Protocol: the largest message is 34 bytes. |
| packet frame | 1452 bytes | fixed | Protocol: quic-go never sends a larger packet (`MaxPacketBufferSize`, internal/protocol/protocol.go:111). |
| listener `MaxConns` (`Secure` nil) | 128 | 1 to 10000 | Memory: it bounds the connections a flood holds, each up to 47.2 MiB of heap (below). |
| listener `MaxConnsPerIP` | 4 | 1 to `MaxConns` | Security: one address cannot take every connection. |
| listener `MaxDialed` | 1 | kolo-transport's minimum | Protocol: the relay never dials. |
| listener `MaxIncomingStreams` | 2 | 1 to 1000 | Protocol: the handshake and one control stream; any other stream closes the connection. |
| listener `MaxStreamReceiveWindow` | 64 KiB | 64 KiB to 16 MiB | Measured security reason: the relay cannot read what a client sends behind a gap, at about 176 heap bytes per byte (kolo-transport limits, memory section; 154 to 159 measured here), so it is kolo-transport's minimum. |
| listener `MaxConnReceiveWindow` | 256 KiB | 64 KiB to 64 MiB | Same measured reason: 47.2 MiB of heap per connection at 256 KiB. |
| other listener fields | kolo-transport and kolo-secure defaults | as there | Documented in their repositories. |

With `Secure` nil the relay listens with kolo-transport `MaxConns` 128,
`MaxConnsPerIP` 4, `MaxDialed` 1, `MaxIncomingStreams` 2 (the kolo-secure
handshake and one control stream), `MaxStreamReceiveWindow` 64 KiB
(kolo-transport's minimum) and `MaxConnReceiveWindow` 256 KiB, and
kolo-secure's defaults. Every session needs its own client connection, so
a source address holds at most `MaxConnsPerIP` sessions. A non-nil
`Secure` is used as given, without these values.

The relay's worst-case live heap is the sum of these terms, with one
exception below. 176 and 96 heap bytes per byte of window are
kolo-transport's measurements of quic-go with 1-byte STREAM frames; the
other numbers are quic-go v0.65.0 constants.

    per connection, × MaxConns:
        MaxConnReceiveWindow × 176     unread data sent as 1-byte frames, on any stream
      + 16 KiB × 176                   out-of-order 1-RTT CRYPTO data quic-go buffers
      + 256 × 1.5 KiB                  packets queued for the connection
      + 64 KiB                         the connection itself
    per connection the relay sends on, at most 2 × MaxSessions:
        25000 × 1.8 KB                 packets sent and not yet acknowledged
    plus
        (MaxSessions − 1) × MaxStreamReceiveWindow × 96   frame maps kept by a target's other sessions
      + 1024 × 1.5 KiB                 packets queued for new connections
      + 2 × MaxSessions × 64 KiB       copy buffers

At the defaults:

| Term | Formula | Heap |
|---|---|---|
| unread 1-byte frames | 128 × 256 KiB × 176 | 5632 MiB |
| out-of-order CRYPTO data | 128 × 16 KiB × 176 | 352 MiB |
| packets queued per connection | 128 × 256 × 1.5 KiB | 48 MiB |
| the connections | 128 × 64 KiB | 8 MiB |
| packets sent and not acknowledged | 32 × 25000 × 1.8 KB | 1373.3 MiB |
| frame maps of a target's other sessions | 15 × 64 KiB × 96 | 90 MiB |
| packets queued for new connections | 1024 × 1.5 KiB | 1.5 MiB |
| copy buffers | 32 × 64 KiB | 2 MiB |
| total | | 7506.8 MiB (7.3 GiB) |

The receive terms (the first four, 47.2 MiB per connection) hold on
every connection, sessions or not. A client with its own QUIC stack can
leave a gap at the start of a stream, and nothing after it can be read
until the relay closes the connection.

The send term comes from quic-go's packet cap. quic-go keeps every sent
packet until it is acknowledged, each STREAM frame in its own pooled
1452-byte buffer whatever its size. It caps only the number of packets
per connection (`MaxOutstandingSentPackets` 20000 and, with probes,
`MaxTrackedSentPackets` 25000, in `internal/protocol/params.go`), and all
streams of the connection share that cap. A client that delays its
acknowledgments, which no relay can tell from a long path, can hold the
cap on its connection. `FlushInterval` does not lower this bound; it
slows the way to it. The relay sends the chunks that arrive within 1 ms
of its last write in one write, so a peer that sends 1-byte frames gets
at most about 1000 packets per second per direction, and needs an
acknowledgment delay of about 20 s to reach the cap.

The exception is a client with its own QUIC stack that acknowledges only
some packets. quic-go declares the others lost and resends their frames
packed together, which frees packet slots, so the packet cap no longer
bounds what the relay keeps; the client's flow-control window does, and
the client chooses it. The relay then keeps about 1.5 KB of heap for
each STREAM frame it sent, and the rate of frames is what bounds it:

- `FlushInterval` allows about 1000 writes per second per direction. A
  write of less than a packet is one frame; a write just over one packet
  is two.
- The client can keep packets at kolo-transport's 1200-byte initial
  packet size by not acknowledging MTU probes, so a packet carries about
  1160 bytes. `RateBytes` (1 MiB/s) then allows about 900 writes of
  1161 bytes per second: about 1800 frames per second.
- That is about 2.6 MiB of heap per second per direction, and 83 MiB per
  second with all 32 directions of 16 sessions under attack.
  `GOMEMLIMIT=8500MiB` is reached after about 100 s from an idle relay.
  (These two figures and the 1160 are arithmetic from the packet size,
  not a measurement; the heap table below was measured with
  1280-byte packets.)
- Over a session, frames are bounded by about 1000 writes per second for
  `MaxSessionDuration` (3.6 million) plus one extra frame per 1241 bytes
  of `MaxSessionBytes` (0.87 million). Mixing 1-byte writes and writes
  just over one packet for the whole hour reaches about 4.47 million
  frames: about 6.2 GiB per direction and 200 GiB in total at the
  defaults.
- `MaxSessionBytes` counts each direction but ends the whole session, so
  each direction stays just under 1 GiB.

Only a change in quic-go bounds this. A relay that does not trust its
clients sets `AllowReserve`.

Measured with `KOLORELAY_HEAP=1 go test -count=1 -run '^TestHeap$' -v
-timeout 30m .` (about 3.5 minutes; Apple M5 with 10 cores, Go 1.27,
three runs). The test runs the relay at its defaults in a child process,
with `MaxConnsPerIP` raised to `MaxConns` so that every client can come
from 127.0.0.1. It samples the relay's live heap after a forced GC every
250 ms, minus the idle relay, while quic-go clients attack it over
loopback, some through a UDP proxy that delays their packets to the
relay. The test fails if a measurement is above its bound.

| Step | Run 1 | Run 2 | Run 3 | Bound |
|---|---|---|---|---|
| idle connection | 39 KiB | 39 KiB | 39 KiB | 64 KiB |
| receive: 20 session connections full | 307.1 MiB | 307.2 MiB | 317.5 MiB | |
| receive: plus 108 parked connections | 890.5 MiB | 887.7 MiB | 881.5 MiB | 6133.5 MiB |
| send: 16 connections at the packet cap | 292.2 MiB | 522.1 MiB | 271.1 MiB | 1373.3 MiB |
| send, per connection | 18.3 MiB | 32.6 MiB | 16.9 MiB | 42.9 MiB |
| both at once | 897.8 MiB | 1089.2 MiB | 639.1 MiB | 7506.8 MiB |

- Idle: 64 reservations (`MaxReservations`).
- Receive: 16 initiators and 4 targets with 4 sessions each, so each
  target's 256 KiB connection window is full. Every session stream is
  full of 1-byte frames (154 to 159 heap bytes per byte of window). Then
  108 connections park in their control phase with 1-byte frames on a
  stream the relay has not accepted. A parked connection is closed after
  `ControlTimeout`; with 108 of them sharing one host's CPU, each sends
  52 to 55 KB of its 64 KiB window in that time. Parking took 7.9 s, 4.2
  s and 14.0 s, so not every parked connection was open at the peak.
- Send: one stream per session at the packet cap, with acknowledgments
  delayed 27 s after a bulk transfer over a 1.2 s round trip has grown
  the relay's congestion window: 23344 to 23502 packets per connection
  in the last 27 s. In runs 1 and 3 the packets were as many but smaller.
- Both: the send step, then 1-byte frames on the 16 target streams and
  96 parked connections (95 in run 3, where one did not finish its
  handshake).

The highest total, 1089.2 MiB, is 6.9 times below the documented bound,
a margin of 6418 MiB. The highest receive step is 6.9 times below its
bound, the highest send step 2.6 times, and 1.3 times per connection.

What the test does not reach comes from the factors above, not from a
measurement. A quic-go client cannot delay its acknowledgments and still
send fast, and the 64 KiB stream window keeps a delayed sender to 64 KiB
per round trip, so the clients reach the packet cap on one direction of
each session only. A quic-go client fills a 256 KiB connection window
only as a target with 4 or more sessions; elsewhere it fills at most its
stream windows. The other terms (both directions at the cap,
out-of-order stream and CRYPTO data, queued packets, the frame maps of a
target's other sessions, the full connection window on every
connection) and the exception above need a client with its own QUIC
stack or a flood.

All of this is live heap. The process is bigger: with the default `GOGC`
the Go runtime lets the heap grow to about twice the live heap before it
collects, and goroutine stacks, the runtime and the kernel's socket
buffers come on top. Set `GOMEMLIMIT` a little above the bound of your
configuration (for example `GOMEMLIMIT=8500MiB` at the defaults) and
give the host some memory beyond it. The runtime then collects more
often instead of growing past the limit, as long as the live heap fits.

On a small host, lower the limits and recompute. A non-nil `Secure` is
used as given, so it sets every listener field:

    cfg := &kolorelay.ServerConfig{
        MaxSessions: 2,
        Secure: &kolosecure.Config{Transport: &kolotransport.Config{
            MaxConns: 5, MaxConnsPerIP: 4, MaxDialed: 1, MaxIncomingStreams: 2,
            MaxStreamReceiveWindow: 64 << 10, MaxConnReceiveWindow: 64 << 10,
        }},
    }

This gives 5 × 14.2 MiB + 4 × 42.9 MiB + 6 MiB + 1.8 MiB, about 250 MiB
of live heap. The same kind of attack measured 85 to 88 MiB with it in
three runs, with a 16 KiB copy buffer and a 10s `ControlTimeout`. Run it with `GOMEMLIMIT=300MiB`. Each byte of
`MaxConnReceiveWindow` costs 176 heap bytes on every connection (14.2
MiB per connection at 64 KiB, 47.2 MiB at 256 KiB), and each session
about 92 MiB (its two sending connections and one frame map).

Throughput at the defaults:

- The 64 KiB stream window limits a session to 64 KiB per round trip in
  each direction: about 5 Mbit/s at 100 ms and 26 Mbit/s at 20 ms.
- `RateBytes` limits each client connection to 1 MiB/s (8.4 Mbit/s).
- The 256 KiB connection window is shared by a target's sessions, so 4
  of them get the full stream window per round trip.
- At most 16 sessions run at once, on at most 128 connections
  (reservations, initiators and handshakes together).
- A session is paced by the initiator's bucket one way and by the
  target's the other way (a target's bucket is shared by its sessions),
  so the relay's egress is at most 2 × `MaxSessions` × `RateBytes`,
  32 MiB/s.
- `FlushInterval` delays a chunk by up to 1 ms when it follows the last
  write by less than that; a full 64 KiB read leaves at once.
- Buckets start empty, so a new session or reservation adds no burst;
  only a bucket that refilled while idle sends up to `RateBurst` at once.

A connection whose end chose `CongestionControl: "bbr"` in `Peer`, `Relay` or `Secure` adds up to 5.5 MiB of BBR samples (kolo-transport,
limits, "Queue (BBR)"), a term the formula above omits; the relay's own listener uses Reno unless its `Secure` says otherwise.

Keys are free to make, so per-key limits bind only together with
kolo-transport's per-address limits. With `AllowReserve` nil anyone can
reserve, and since one source address holds at most `MaxConnsPerIP`
sessions, ceil(`MaxSessions` / `MaxConnsPerIP`) addresses (4 at the
defaults) can take every session slot, and 32 addresses every
connection. A relay for your own nodes should set `AllowReserve` and, if
needed, `AllowConnect`; `Listen` logs a warning while `AllowReserve` is nil.
Sessions between two live peers last until `MaxSessionDuration` (1h), so
the four addresses hold their slots for that long and then take them again:
lower `MaxSessionDuration`, `MaxSessions` and `RateBytes` for a relay that
must stay open. Every refused Connect, one that `AllowConnect`
refuses included, frees its session slot before the relay answers and
waits for the client to leave, so only allowed initiators fill the
session limits. An allowed initiator can hold up to
`MaxSessionsPerTarget` sessions to one target; a target that only wants
some peers sets `AllowFunc`.

## Sizing a relay for a swarm

A kolo-swarm with this relay in its `Config.Relays` reserves here while
it announces a topic, and dials through here when a direct connection
fails. From that, with no new default:

- Every announcing member that lists the relay holds one reservation
  connection, and for up to `MaxSessionDuration` after each lifetime end
  a second one while sessions on the old reservation last. Every pair
  relayed here holds one session and one more client connection (the
  initiator's, a new socket per `Dial`), two for a moment when both ends
  dial. A member that lists several relays reserves at all of them, so
  each relay counts every member that lists it, but only the sessions
  whose dial stopped there.
- So set `MaxReservations` to at least the announcing members online
  that list the relay; `MaxSessions` to at least the pairs relayed here;
  `MaxSessionsPerPeer` and `MaxSessionsPerTarget` to at least the
  relayed partners of one member; the listener's `MaxConns` to at least
  2 × reservations plus sessions; and the listener's `MaxConnsPerIP` to
  at least (2 + relayed partners it starts here) × the members behind one
  address. Raising the listener values needs a non-nil `Secure` with
  every listener field set.
- At the defaults that is 64 members, 16 relayed pairs, at most 4
  partners started by one key, and 4 connections per address: one member
  behind an address gets its reservation and 3 sessions it starts, and
  people behind one home NAT or a carrier-grade NAT share those 4. With
  `AllowReserve` nil, 16 addresses can take all 64 reservations.
- A call of N people in which every pair is relayed here needs
  N(N-1)/2 sessions and N-1 per key.
- At the default `RateBytes` a session reaches `MaxSessionBytes` in
  about 17 minutes. A relay for calls raises `MaxSessionBytes`,
  `MaxSessionDuration` and `RateBytes` to cover a call at its media rate;
  each session end costs the pair one relay dial.

## Client

`Config` (for `Reserve` and `Dial`; nil or a zero field means the
default; out of range is `ErrInvalidConfig`):

| Option | Default | Range | Why |
|---|---|---|---|
| `Relay` (connection to the relay) | nil: kolo-secure defaults with `KeepAlivePeriod` 5s | any `*kolosecure.Config`, used as given | Protocol: a reservation's connection to the relay must stay alive between sessions. |
| `Peer` (end-to-end connection) | nil: kolo-secure and kolo-transport defaults | any `*kolosecure.Config` | Documented in their repositories. |
| `ControlTimeout` (each exchange with the relay) | 20s | 1s to 60s | Protocol: a Connect waits for the target's answer, so the client waits 5s longer than the relay's default 15s, for `AllowConnect` and two round trips. |
| `MaxPending` (reservation: sessions not yet returned by `Accept`) | 16 | 1 to 256 | Memory: each waiting session holds an inner QUIC listener. |
| `SendQueue` (packets queued per session; when full the oldest is dropped) | 512 | 8 to 1024 | Memory: at most about 726 KiB per session. |
| `AllowFunc func(initiator) bool` (reservation: who may reach it) | nil: every key | a panic refuses | A policy hook, not a limit. |

A reservation's connection to the relay must stay alive between
sessions; kolo-transport's keep-alive is always on (5s by default, from
500ms to below `IdleTimeout`), so it does with a non-nil `Relay` too.
The end-to-end connection has it as well, so a session between two peers
that are still up never reaches a `SessionIdleTimeout` above their
`KeepAlivePeriod`. In `Peer`, kolorelay sets `MaxConns`, `MaxConnsPerIP` and
`MaxDialed` to 1 and replaces `AcceptFunc`, and a zero `HandshakeTimeout`
(in `Peer` or `Peer.Transport`) is 10s. A target waits at most
`ControlTimeout` plus both handshake timeouts (40s at the defaults) for
an announced peer to finish its handshake, then frees the slot.

