# kolo-relay

An optional relay for Kolo peers that cannot connect directly, chosen by the application and meant to be self-hosted.

[![status: experimental](https://img.shields.io/badge/status-experimental-orange)](#status)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![go: 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)

## What it is

kolo-relay forwards traffic for peers that cannot connect directly, with allocations, lifetimes and quotas modeled on [TURN (RFC 8656)](https://www.rfc-editor.org/info/rfc8656), used only when the application chooses it, like the `relay` policy of [WebRTC](https://www.w3.org/TR/webrtc/#dom-rtcicetransportpolicy).

Some peers cannot reach each other: both behind symmetric NAT or CGNAT, or behind a firewall that only lets traffic out. A relay with a reachable address lets them connect anyway. A peer reserves a slot on the relay; another peer asks the relay for that peer's key; the relay joins the two and forwards their packets.

The two peers run an ordinary [kolo-secure](https://github.com/ciranda-dev/kolo-secure) connection end to end. Its QUIC packets travel inside each peer's own kolo-secure connection to the relay: as frames on one stream, or as QUIC datagrams ([RFC 9221](https://www.rfc-editor.org/info/rfc9221)) when both ends of that connection offer them and a packet fits. The relay offers datagrams; a client uses them when its application sets `Transport.Datagrams` in `Config.Relay`. A datagram is not resent, so a packet lost on the way to the relay is a loss for the end-to-end connection, which recovers from it as on a direct path, instead of a delay for every packet behind it. On the simulated path in [Limits](docs/limits.md) the datagram path gained no goodput under loss and 1.6 times without loss at the relay's default window, so clients opt in. The relay forwards ciphertext of a TLS session it is not part of and cannot pose as either peer. It can see who talks to whom, when, and how much. The relay is never used on its own: the application passes the relay's address and key to every call, and nothing tries a direct path or falls back to a relay.

It is Go only and builds without cgo. It is IPv4 only: IPv6 input is refused with `ErrInvalidArgument`.

## Install

```sh
go get github.com/ciranda-dev/kolo-relay
```

## Quick start

A relay, a target that reserves its key on it, and a dialer that connects to the target through it, all on loopback.

```go
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolorelay "github.com/ciranda-dev/kolo-relay"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	relayID, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	targetID, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	dialerID, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}

	// A nil config is an open relay: any key may reserve. Set ServerConfig.AllowReserve before exposing one.
	relay, err := kolorelay.Listen(ctx, "127.0.0.1:0", relayID, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer relay.Close()
	addr, key := relay.Addr().String(), relayID.PublicKey()

	res, err := kolorelay.Reserve(ctx, addr, key, targetID, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Close()
	go func() {
		c, err := res.Accept(ctx)
		if err != nil {
			return
		}
		s, err := c.AcceptStream(ctx)
		if err != nil {
			return
		}
		io.Copy(s, s)
		s.Close()
	}()

	c, err := kolorelay.Dial(ctx, addr, key, dialerID, targetID.PublicKey(), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	fmt.Printf("connected to %x through relay %x\n", c.RemotePublicKey()[:4], c.RelayPublicKey()[:4])
	s, err := c.OpenStream(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := s.Write([]byte("hello kolo")); err != nil {
		log.Fatal(err)
	}
	s.Close()
	reply, err := io.ReadAll(s)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", reply)
}
```

```text
$ go run .
connected to <8 hex characters> through relay <8 hex characters>
hello kolo
```

In a real deployment the relay runs on a host with a public address and loads its identity with `koloid.Load`. Peers learn its address and key from their own configuration.

## API

| Symbol | What it does |
|---|---|
| `Listen` | Start a relay on an address, authenticated as an identity |
| `Server.Close` | Stop accepting and end every session |
| `Reserve` | Reserve an identity's key on a relay; the key's holder only |
| `Reservation.Accept` | Return the next peer that connected through the relay and proved its key |
| `Dial` | Ask the relay for a target's key and connect to it end to end |
| `Conn` | A relayed connection with kolo-secure's methods, plus `Stats` (the transport statistics of the whole path), `RelayPublicKey` and `RelayAddr` |
| `ServerConfig`, `Config` | Reservation, session, rate and memory limits; `AllowReserve`, `AllowConnect` and `AllowFunc` policy hooks |

Errors are sentinels for `errors.Is`: `ErrUnavailable`, `ErrNotAllowed`, `ErrLimit`, `ErrReservationEnded`, `ErrClosed`, `ErrProtocol`, `ErrUnsupportedVersion`, `ErrInvalidConfig` and `ErrInvalidArgument`.

## Before you expose a relay

The defaults are for trying it out, not for the open internet. Two things to settle first; the numbers are in [Limits](docs/limits.md).

- **Who may use it.** With `AllowReserve` nil, any key may reserve and keys cost nothing. `Listen` logs a warning when it is nil (to `ServerConfig.Logger`, or `slog.Default()`). Four addresses, each at the default `MaxConnsPerIP` of 4, can take all 16 session slots and hold them for `MaxSessionDuration` (1 hour) with keep-alive traffic, and 16 addresses can fill all 64 reservations. A relay for your own nodes sets `AllowReserve` to the keys it serves and, if needed, `AllowConnect` to the pairs it joins; a relay that is open on purpose sets `MaxSessions`, `RateBytes` and `MaxSessionDuration` to what you can pay for, since it pays for every byte it forwards.
- **How much memory it needs.** At the defaults (`MaxConns` 128, receive window 256 KiB) the worst-case live heap is 7.4 GiB, reached only by a client with its own QUIC stack that leaves gaps at the start of its streams; the measured attack reached 1.1 GiB. Run it on a host with about 8 GiB and `GOMEMLIMIT=8500MiB`, or lower the limits. For a small host (about 252 MiB of live heap, `GOMEMLIMIT=300MiB`):

```go
cfg := &kolorelay.ServerConfig{
	MaxSessions: 2,
	AllowReserve: func(key ed25519.PublicKey) bool { return mine[string(key)] },
	Secure: &kolosecure.Config{Transport: &kolotransport.Config{
		MaxConns: 5, MaxConnsPerIP: 4, MaxDialed: 1, MaxIncomingStreams: 2,
		MaxStreamReceiveWindow: 64 << 10, MaxConnReceiveWindow: 64 << 10,
		Datagrams: true,
	}},
}
```

## Documentation

- [Guide](docs/guide.md): every call and every error.
- [Limits](docs/limits.md): server and client options, memory and throughput.
- [Protocol and design](docs/protocol.md): what the relay learns, the wire format and references.

## Status

Experimental. The API may change before v1.0.0. The wire protocol is version 1, which adds the datagram path; version 0 clients and relays still connect, with packets on the stream only, and default clients speak version 0. Throughput was measured only on loopback.

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE) or the [MIT license](LICENSE-MIT), at your option.
