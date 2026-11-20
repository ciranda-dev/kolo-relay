package kolorelay

import (
	"errors"

	"github.com/ciranda-dev/kolo-relay/internal/limits"
	"github.com/ciranda-dev/kolo-relay/internal/wire"
)

var (
	// ErrInvalidConfig means a Config or ServerConfig field is out of range, or a kolo-transport Network in it is not "udp4".
	ErrInvalidConfig = errors.New("kolorelay: invalid config")
	// ErrInvalidArgument means a nil or zero identity, an IPv6 address (v4-mapped included),
	// or a target key that is not 32 bytes or is the local or the relay's key.
	ErrInvalidArgument = errors.New("kolorelay: invalid argument")
	// ErrClosed means the Server or Reservation is closed.
	ErrClosed = errors.New("kolorelay: closed")
	// ErrProtocol means a relay message was malformed, truncated, too large or unexpected.
	ErrProtocol = wire.ErrProtocol
	// ErrUnsupportedVersion means the other side speaks another kolo-relay version.
	ErrUnsupportedVersion = wire.ErrUnsupportedVersion
	// ErrUnavailable means the target cannot be reached through the relay: no reservation,
	// MaxSessionsPerTarget sessions, or the relay or the target refused.
	ErrUnavailable = errors.New("kolorelay: target unavailable through the relay")
	// ErrNotAllowed means the relay does not let this key reserve.
	ErrNotAllowed = errors.New("kolorelay: not allowed by the relay")
	// ErrLimit means MaxReservations, MaxSessions or MaxSessionsPerPeer was reached; trying later may work.
	ErrLimit = limits.ErrLimit
	// ErrReservationEnded means the reservation ended: its lifetime passed, the key reserved again,
	// the relay closed, or the connection was lost.
	ErrReservationEnded = errors.New("kolorelay: reservation ended")
)

// Application codes on connections and streams to the relay.
const (
	codeProtocol = 1
	codeLifetime = 2
	codeReplaced = 3
	codeClosing  = 4
)

// codeUnexpectedPeer closes an inner connection whose key is not the one the relay announced.
const codeUnexpectedPeer = 1

// guard runs an allow func and treats a panic as a refusal.
func guard(f func() bool) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return f()
}
