# Guide

How to use kolo-relay beyond the README quick start. Every default and bound is in [limits.md](limits.md); the design, the wire format and references are in [protocol.md](protocol.md).

In a real deployment the relay runs on a host with a public address and loads its identity with `koloid.Load`; peers learn its address and key from their own configuration, and a target tells others which relay it reserved on through the application. A kolo-swarm does all of this itself when its `Config.Relays` lists the relay: it reserves while it announces a topic and dials through the relay when a direct connection fails; kolo-node's `relay` command runs a relay.

## API

Server:

- `Listen(ctx, addr, id, cfg) (*Server, error)` starts a relay on `addr`,
  authenticated as `id` with kolo-secure. Clients must know `id`'s public
  key. `(*Server).Addr()` is its UDP address. With `AllowReserve` nil
  the relay is open to every key and `Listen` logs a warning, to
  `ServerConfig.Logger` or `slog.Default()`.
- `(*Server).Close()` stops accepting and ends every session with stream
  code 5 (a Connect or Reserve still being set up gets stream code 5 or
  connection code 4). It gives each initiator up to 1s to close its
  connection, then ends every reservation with connection code 4, closes
  every connection and waits for its goroutines.

Client:

- `Reserve(ctx, relayAddr, relayKey, id, cfg) (*Reservation, error)`
  connects to the relay, checks it holds `relayKey`, and reserves `id`'s
  key there. Only the holder of a key can reserve it; a newer reservation
  of the same key replaces the older one.
- `(*Reservation).Accept(ctx) (*Conn, error)` returns the next peer that
  connected through the relay and proved its key end to end, which is
  also the key the relay announced. When the relay ends the reservation
  it returns an error wrapping `ErrReservationEnded` and the
  kolo-transport error with the relay's code: 2 when
  `ReservationLifetime` passed, 3 when the key reserved again, 4 when the
  relay closed. Connections already returned keep working, and the
  connection to the relay stays open until the last one closes. Call
  `Close` after `Accept` fails; nothing reserves again by itself.
- `(*Reservation).Close()` first closes every relayed connection of the
  reservation with code 0, so the peers get that code, then the
  connection to the relay. It can take about 2s, as `Conn.Close` does.
- `Dial(ctx, relayAddr, relayKey, id, target, cfg) (*Conn, error)` opens
  its own connection to the relay, asks for `target` and returns once
  `target` has proved its key end to end. `target` must be 32 bytes and
  not our own key or the relay's (`ErrInvalidArgument`). The connection
  to the relay is closed with the returned `Conn`.
- `Conn` has `RemotePublicKey`, `OpenStream`, `AcceptStream`,
  `OpenUniStream`, `AcceptUniStream`, `Context`, `Close` and
  `CloseWithError`, which behave as on `kolosecure.Conn` and return
  kolo-transport stream types, so one interface can cover direct and
  relayed connections. `Stats` returns the transport statistics of the
  end-to-end connection, which crosses the relay (its round trip time is
  the whole path, and it is the zero value once the connection has
  ended). `RelayPublicKey` and `RelayAddr` name the relay.
  There is no `RemoteAddr`: the only address on the path is the relay's.
  `Context` is canceled when the connection ends for any reason,
  including the relay ending the session.
- A nil or zero identity is `ErrInvalidArgument`.
- kolo-relay is IPv4 only and IPv6 input is refused: an IPv6 address
  given to `Listen`, `Reserve` or `Dial`, v4-mapped included, is
  `ErrInvalidArgument` before anything is sent, and a kolo-transport
  `Network` other than `"udp4"` in `Config` or `ServerConfig` is
  `ErrInvalidConfig`.
- Every blocking call returns `ctx.Err()` as soon as its context is done.

## Errors

Errors, for `errors.Is`; none of them carries anything the peer or the
relay sent except numeric codes:

- `ErrUnavailable`: the target has no reservation, the relay's
  `AllowConnect` refused, the target has `MaxSessionsPerTarget`
  sessions, or the target refused or did not answer. The relay gives one
  answer for all of them on purpose. It checks `MaxSessions` and
  `MaxSessionsPerPeer` before and after `AllowConnect`, so one Connect's
  `ErrLimit` does not depend on what `AllowConnect` decided. Any
  authenticated key learns that the relay or that key is at its limit.
- What a key can still learn: only Connects that `AllowConnect` allowed,
  to a reserved target, hold a per-peer slot. With `MaxSessionsPerPeer`
  + 1 Connects at once to a reserved target, an allowed key gets
  `ErrLimit` on the last one and a denied key gets `ErrUnavailable` on
  all of them. The answer time shows the same: a missing reservation or
  a denial is answered at once, while an allowed Connect to a reserved
  target costs a round trip to it. So a key can learn its own
  `AllowConnect` decision and whether a target is reserved, but nothing
  about other keys.
- `ErrNotAllowed`: the relay's `AllowReserve` refused this key.
- `ErrLimit`: `MaxReservations`, `MaxSessions` or `MaxSessionsPerPeer`
  was reached; trying later may work.
- `ErrReservationEnded`, `ErrClosed` (the reservation was closed).
- `ErrProtocol`.
- `ErrUnsupportedVersion`: the relay refused both versions. A version 1 request it
  refuses is sent once more in version 0, on a new connection.
- `ErrInvalidConfig`, `ErrInvalidArgument`.
- A relay that does not answer within `ControlTimeout` gives an error
  wrapping `os.ErrDeadlineExceeded`.
- kolo-secure errors pass through: a relay without `relayKey` gives
  `kolosecure.ErrUnexpectedPeer`, and so does a relay that answers for
  `target` with another key. kolo-transport errors also pass through.

A target that receives a peer whose proved key is not the one the relay
announced closes that connection with code 1 and never returns it.
