// Package limits counts the reservations and sessions of a relay against its limits.
package limits

import (
	"errors"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ErrLimit means a relay limit was reached.
var ErrLimit = errors.New("kolorelay: relay limit reached")

// ErrTargetLimit means the target has MaxSessionsPerTarget sessions; the relay answers it as Unavailable.
var ErrTargetLimit = errors.New("kolorelay: target session limit reached")

// Key is a kolo-id public key.
type Key = [32]byte

// KeyOf returns pub as a Key, or false if it is not 32 bytes.
func KeyOf(pub []byte) (Key, bool) {
	if len(pub) != len(Key{}) {
		return Key{}, false
	}
	return Key(pub), true
}

// Config holds the counts a Table enforces; the caller validates them.
type Config struct {
	MaxReservations      int
	MaxSessions          int
	MaxSessionsPerPeer   int
	MaxSessionsPerTarget int
}

// Table tracks who holds a reservation and how many sessions are open, per peer and per target.
type Table[T comparable] struct {
	mu       sync.Mutex
	cfg      Config
	owners   map[Key]T
	sessions int
	byPeer   map[Key]int
	byTarget map[Key]int
}

// New returns an empty Table.
func New[T comparable](cfg Config) *Table[T] {
	return &Table[T]{cfg: cfg, owners: make(map[Key]T), byPeer: make(map[Key]int), byTarget: make(map[Key]int)}
}

// Reserve makes owner the holder of k and returns the holder it replaced; replacing works even at MaxReservations.
func (t *Table[T]) Reserve(k Key, owner T) (prev T, replaced bool, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	prev, replaced = t.owners[k]
	if !replaced && len(t.owners) >= t.cfg.MaxReservations {
		return prev, false, ErrLimit
	}
	t.owners[k] = owner
	return prev, replaced, nil
}

// Unreserve removes the reservation of k if owner still holds it.
func (t *Table[T]) Unreserve(k Key, owner T) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if o, ok := t.owners[k]; ok && o == owner {
		delete(t.owners, k)
	}
}

// Lookup returns the holder of k's reservation.
func (t *Table[T]) Lookup(k Key) (T, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	o, ok := t.owners[k]
	return o, ok
}

// AtLimit returns ErrLimit if peer cannot open a session now because of MaxSessions or MaxSessionsPerPeer; it counts nothing.
func (t *Table[T]) AtLimit(peer Key) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sessions >= t.cfg.MaxSessions || t.byPeer[peer] >= t.cfg.MaxSessionsPerPeer {
		return ErrLimit
	}
	return nil
}

// OpenSession counts a session from peer to target: ErrLimit for the total and per-peer limits, checked first, ErrTargetLimit for the per-target one.
// release frees the session and may be called more than once.
func (t *Table[T]) OpenSession(peer, target Key) (release func(), err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sessions >= t.cfg.MaxSessions || t.byPeer[peer] >= t.cfg.MaxSessionsPerPeer {
		return nil, ErrLimit
	}
	if t.byTarget[target] >= t.cfg.MaxSessionsPerTarget {
		return nil, ErrTargetLimit
	}
	t.sessions++
	t.byPeer[peer]++
	t.byTarget[target]++
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			t.sessions--
			decrement(t.byPeer, peer)
			decrement(t.byTarget, target)
		})
	}, nil
}

func decrement(m map[Key]int, k Key) {
	if m[k]--; m[k] == 0 {
		delete(m, k)
	}
}

// Bucket returns a token bucket of bytesPerSec that holds at most burst bytes, empty at the start,
// so a new session or reservation cannot send a fresh burst.
func Bucket(bytesPerSec, burst int64) *rate.Limiter {
	b := rate.NewLimiter(rate.Limit(bytesPerSec), int(burst))
	b.AllowN(time.Now(), int(burst))
	return b
}
