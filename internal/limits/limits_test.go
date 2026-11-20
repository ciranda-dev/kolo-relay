package limits

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func k(b byte) Key { return Key{b} }

func TestReserve(t *testing.T) {
	tab := New[int](Config{MaxReservations: 2, MaxSessions: 1, MaxSessionsPerPeer: 1, MaxSessionsPerTarget: 1})
	if _, replaced, err := tab.Reserve(k(1), 10); err != nil || replaced {
		t.Fatalf("first: %v %v", replaced, err)
	}
	if _, _, err := tab.Reserve(k(2), 20); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tab.Reserve(k(3), 30); !errors.Is(err, ErrLimit) {
		t.Fatalf("over MaxReservations: %v", err)
	}
	prev, replaced, err := tab.Reserve(k(1), 11)
	if err != nil || !replaced || prev != 10 {
		t.Fatalf("replace at the limit: prev %d replaced %v err %v", prev, replaced, err)
	}
	if o, ok := tab.Lookup(k(1)); !ok || o != 11 {
		t.Fatalf("Lookup after replace: %d %v", o, ok)
	}
	tab.Unreserve(k(1), 10)
	if _, ok := tab.Lookup(k(1)); !ok {
		t.Fatal("a replaced owner removed the new reservation")
	}
	tab.Unreserve(k(1), 11)
	if _, ok := tab.Lookup(k(1)); ok {
		t.Fatal("Unreserve by the owner did not remove it")
	}
	if len(tab.owners) != 1 {
		t.Fatalf("Reservations %d, want 1", len(tab.owners))
	}
	if _, _, err := tab.Reserve(k(3), 30); err != nil {
		t.Fatalf("slot not freed: %v", err)
	}
}

func TestSessionLimits(t *testing.T) {
	tab := New[int](Config{MaxReservations: 1, MaxSessions: 4, MaxSessionsPerPeer: 2, MaxSessionsPerTarget: 2})
	open := func(peer, target byte) func() {
		t.Helper()
		r, err := tab.OpenSession(k(peer), k(target))
		if err != nil {
			t.Fatalf("%d to %d: %v", peer, target, err)
		}
		return r
	}
	refused := func(peer, target byte, want error, why string) {
		t.Helper()
		if _, err := tab.OpenSession(k(peer), k(target)); err != want {
			t.Fatalf("%s: %v, want %v", why, err, want)
		}
	}
	r1 := open(1, 9)
	r2 := open(1, 8)
	refused(1, 7, ErrLimit, "over MaxSessionsPerPeer")
	r3 := open(2, 9)
	refused(3, 9, ErrTargetLimit, "over MaxSessionsPerTarget")
	refused(1, 9, ErrLimit, "the per-peer limit is checked before the per-target one")
	r4 := open(3, 6)
	refused(5, 5, ErrLimit, "over MaxSessions")
	refused(5, 9, ErrLimit, "the total limit is checked before the per-target one")
	r1()
	r1()
	if tab.sessions != 3 {
		t.Fatalf("Sessions %d after a double release, want 3", tab.sessions)
	}
	r5 := open(3, 9)
	for _, r := range []func(){r2, r3, r4, r5} {
		r()
	}
	if tab.sessions != 0 || len(tab.byPeer) != 0 || len(tab.byTarget) != 0 {
		t.Fatalf("not empty after release: %d %v %v", tab.sessions, tab.byPeer, tab.byTarget)
	}
}

func TestSessionsConcurrent(t *testing.T) {
	const max, perTarget = 8, 3
	tab := New[int](Config{MaxReservations: 1, MaxSessions: max, MaxSessionsPerPeer: 2, MaxSessionsPerTarget: perTarget})
	var open, peak atomic.Int64
	var target [4]atomic.Int64
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Go(func() {
			for j := range 50 {
				tg := byte(j % 4)
				release, err := tab.OpenSession(k(byte(i)), k(100+tg))
				if err != nil {
					continue
				}
				n := open.Add(1)
				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				if target[tg].Add(1) > perTarget {
					t.Errorf("target %d over its limit", tg)
				}
				time.Sleep(time.Microsecond)
				target[tg].Add(-1)
				open.Add(-1)
				release()
			}
		})
	}
	wg.Wait()
	if p := peak.Load(); p > max {
		t.Fatalf("peak %d sessions, limit %d", p, max)
	}
	if tab.sessions != 0 {
		t.Fatalf("Sessions %d after all released", tab.sessions)
	}
}

func TestKeyOf(t *testing.T) {
	if _, ok := KeyOf(make([]byte, 31)); ok {
		t.Fatal("31 bytes accepted")
	}
	b := make([]byte, 32)
	b[0] = 5
	key, ok := KeyOf(b)
	if !ok || key != k(5) {
		t.Fatalf("KeyOf: %v %v", key, ok)
	}
}

func TestBucket(t *testing.T) {
	now := time.Now()
	b := Bucket(1000, 500)
	if b.AllowN(now, 1) {
		t.Fatal("a new bucket must start empty")
	}
	if !b.AllowN(now.Add(time.Second), 500) {
		t.Fatal("bucket did not refill at the rate")
	}
	if b.AllowN(now.Add(time.Second), 1) {
		t.Fatal("more than the burst allowed at once")
	}
	if b.Burst() != 500 {
		t.Fatalf("Burst %d", b.Burst())
	}
}

func TestAtLimit(t *testing.T) {
	tab := New[int](Config{MaxReservations: 1, MaxSessions: 2, MaxSessionsPerPeer: 1, MaxSessionsPerTarget: 2})
	if err := tab.AtLimit(k(1)); err != nil {
		t.Fatalf("empty table: %v", err)
	}
	r1, _ := tab.OpenSession(k(1), k(9))
	if err := tab.AtLimit(k(1)); err != ErrLimit {
		t.Fatalf("peer at MaxSessionsPerPeer: %v", err)
	}
	if err := tab.AtLimit(k(2)); err != nil {
		t.Fatalf("other peer: %v", err)
	}
	tab.OpenSession(k(2), k(9))
	if err := tab.AtLimit(k(3)); err != ErrLimit {
		t.Fatalf("table at MaxSessions: %v", err)
	}
	if tab.sessions != 2 {
		t.Fatalf("AtLimit counted: %d sessions", tab.sessions)
	}
	r1()
	if err := tab.AtLimit(k(1)); err != nil {
		t.Fatalf("after release: %v", err)
	}
}
