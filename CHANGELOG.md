# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Datagram path, protocol version 1: inner packets travel as QUIC datagrams (RFC 9221) on each leg whose connection to the relay supports them, tagged with the session stream's quarter stream ID (RFC 9297 section 2.1), and as frames on the session stream when they do not fit; a datagram the full send queue refuses is dropped, so the inner connection sees a loss instead of a delay. Reserve, Connect and Incoming carry version 1 with the version 0 layouts; a client speaks version 1 only when its relay connection supports datagrams, which it does when the application sets `Transport.Datagrams` in `Config.Relay`, and the relay sends Incoming in the version the target reserved with. Version 0 clients and relays keep working, with packets on the stream only (docs/protocol.md).
- The relay forwards a session with a version 1 leg packet by packet, with a 32-packet queue per direction and writes of at most 64 KiB; the token bucket charges each packet its frame plus 37 bytes, the per-packet overhead kolo-transport reserves for a datagram, so a client connection gets at most `RateBytes` / 39 packets per second, and drops a datagram it cannot pay at once. `MaxSessionBytes` counts the frames of both paths, and `SessionIdleTimeout` sees the packets of both paths, but not the datagrams the bucket drops (docs/limits.md).
- A client whose version 1 Reserve or Connect gets UnsupportedVersion from a relay that offers datagrams sends it once more in version 0, on a new connection, so it still connects, in stream mode, to an older relay whose listener was given `Datagrams`.
- The heap measurement (`KOLORELAY_HEAP=1`) has a datagram flood step, and the memory bound adds the datagram queues of each connection and the packet queues of each session (docs/limits.md).
- `FuzzDecodeDatagram`.
- `TestPath`, an opt-in measurement (`KOLORELAY_PATH=1`) of a bulk transfer through a relay over two simulated 3 Mbit/s legs with a 470 ms round trip and random loss, across the relay's stream window, the outer and inner congestion controllers and both protocol versions (stream and datagram), with the packet counters of each path; each row is logged as TSV after a `path-tsv` prefix (docs/limits.md). In datagram mode at 1% loss the inner connection must see lost packets and a lower smoothed RTT than in stream mode, and at 0% loss with the 64 KiB window the goodput must reach 1.3 times the stream mode's.

### Changed

- **Breaking:** `ServerConfig.MaxReservations` defaults to (listener `MaxConns` - `MaxSessions`) / 2, at least 1, instead of 64: 56 at the default listener, and it grows with `MaxConns`, so a relay no longer needs the reservation count set apart from the connection count. A relay with a bigger `MaxConns` can now hold more than 64 reservations without setting it; one with a smaller `MaxConns` holds fewer. A positive value is still an operator cap.
- **Breaking:** `ServerConfig.MaxSessions` defaults to 16 or a quarter of the listener `MaxConns` if lower, at least 1, so the derived `MaxReservations` no longer collapses to 1 at a small `MaxConns`: 4 reservations and 3 sessions at a `MaxConns` of 12 (they were 1 and 16), 4 and 2 at 10. Defaults at a `MaxConns` of 64 or more are unchanged.
- `ServerConfig.MaxReservations` has no maximum (it was 100000); a reservation lives on its client's connection, so `MaxConns` bounds it.
- **Breaking:** `ServerConfig.MaxSessions` is at most the listener `MaxConns`, instead of 10000: a value above it is now `ErrInvalidConfig` (129 at the default listener of 128, where up to 10000 was accepted), and a listener with more than 10000 connections accepts more than 10000 sessions. A session lives on the connections of its two clients, which `MaxConns` bounds.
- `ServerConfig.MaxSessionBytes` has no maximum (it was 1 TiB); `MaxSessionDuration` and `RateBytes` bound what a session carries, far below its counter's `int64`. The minimum of 64 KiB stays.
- The default relay listener (`ServerConfig.Secure` nil) offers QUIC datagrams (`Transport.Datagrams`); clients opt in: the default client connection to the relay (`Config.Relay` nil) does not, so it speaks version 0, and an application sets `Transport.Datagrams` in a non-nil `Config.Relay` to use the datagram path. A non-nil config is used as given. The measurement showed no goodput gain under 1% loss and 1.6 times without loss at the relay's 64 KiB window (docs/limits.md).
- The end-to-end connection never offers QUIC datagrams of its own: `Transport.Datagrams` in `Config.Peer` is ignored, since its packets already travel as datagrams or frames to the relay.

### Fixed

- A `Config.Peer` with `MaxPending` above 1, as an application sets it for its own listener, no longer fails every Dial and every incoming session with kolo-secure's `ErrInvalidConfig` (MaxPending above the transport MaxConns): the end-to-end listener holds one connection, so kolorelay sets its `MaxPending` to 1.

## [0.1.0] - 2026-11-20

### Added

- First release of kolo-relay.
