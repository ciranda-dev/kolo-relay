package splice

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-relay/internal/wire"
	kolotransport "github.com/ciranda-dev/kolo-transport"
	"golang.org/x/time/rate"
)

// datagramSink records the datagrams the relay sends to one client and answers each with err.
type datagramSink struct {
	mu   sync.Mutex
	got  [][]byte
	err  error
	wake chan struct{}
}

func newSink() *datagramSink { return &datagramSink{wake: make(chan struct{}, 1)} }

func (d *datagramSink) send(p []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return d.err
	}
	d.got = append(d.got, bytes.Clone(p))
	select {
	case d.wake <- struct{}{}:
	default:
	}
	return nil
}

func (d *datagramSink) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.got)
}

// packetsRun is a packet session between two clients; a and b are the clients' ends, la and lb the relay's legs.
type packetsRun struct {
	a, b   *memStream
	la, lb *Leg
	code   chan uint64
}

// sendFunc returns d.send, or nil for a version 0 leg.
func sendFunc(d *datagramSink) func([]byte) error {
	if d == nil {
		return nil
	}
	return d.send
}

func startPackets(t *testing.T, ctx context.Context, buffer int, ra, rb *rate.Limiter, da, db *datagramSink, lim Limits) *packetsRun {
	t.Helper()
	a, ra1 := streamPair(buffer)
	b, rb1 := streamPair(buffer)
	s := &packetsRun{a: a, b: b, code: make(chan uint64, 1)}
	s.la = NewLeg(ra1, ra, sendFunc(da), 10)
	s.lb = NewLeg(rb1, rb, sendFunc(db), 20)
	go func() { s.code <- Packets(ctx, s.la, s.lb, lim) }()
	t.Cleanup(func() {
		a.CancelWrite(0)
		a.CancelRead(0)
		b.CancelWrite(0)
		b.CancelRead(0)
		select {
		case <-s.code:
		case <-time.After(5 * time.Second):
			t.Error("Packets did not return")
		}
	})
	return s
}

func (s *packetsRun) wait(t *testing.T, within time.Duration) uint64 {
	t.Helper()
	select {
	case c := <-s.code:
		s.code <- c
		return c
	case <-time.After(within):
		t.Fatalf("Packets still running after %v", within)
		return 0
	}
}

func (s *packetsRun) running() bool {
	select {
	case c := <-s.code:
		s.code <- c
		return false
	default:
		return true
	}
}

func writeFrames(t *testing.T, st *memStream, packets ...[]byte) {
	t.Helper()
	var w wire.PacketWriter
	for _, p := range packets {
		if err := w.Write(st, p); err != nil {
			t.Fatal(err)
		}
	}
}

func readFrame(t *testing.T, st *memStream) []byte {
	t.Helper()
	st.SetReadDeadline(time.Now().Add(5 * time.Second))
	p := make([]byte, wire.MaxPacketSize)
	n, err := wire.NewPacketReader(st).Read(p)
	if err != nil {
		t.Fatalf("reading a frame: %v", err)
	}
	return p[:n]
}

// waitFor polls cond for up to 5 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// running reports whether the leg's session has started, so Deliver forwards.
func (l *Leg) running() bool { return l.s.Load() != nil }

func TestPacketsFramesBothWays(t *testing.T) {
	checkGoroutines(t)
	s := startPackets(t, context.Background(), 1<<16, nil, nil, nil, nil, long)
	writeFrames(t, s.a, []byte("hello"), bytes.Repeat([]byte{1}, wire.MaxPacketSize))
	s.a.Close()
	if got := readFrame(t, s.b); string(got) != "hello" {
		t.Fatalf("b got %q", got)
	}
	if got, err := readAll(t, s.b); err != nil || len(got) != 2+wire.MaxPacketSize {
		t.Fatalf("b got %d more bytes, %v; want one full frame and the end", len(got), err)
	}
	writeFrames(t, s.b, []byte("world"))
	s.b.Close()
	if got, err := readAll(t, s.a); err != nil || !bytes.Equal(got, append([]byte{5}, "world"...)) {
		t.Fatalf("a got %x %v", got, err)
	}
	if c := s.wait(t, 5*time.Second); c != Done {
		t.Fatalf("code %d, want Done", c)
	}
}

func TestPacketsFramesBecomeDatagrams(t *testing.T) {
	checkGoroutines(t)
	db := newSink()
	s := startPackets(t, context.Background(), 1<<16, nil, nil, nil, db, long)
	writeFrames(t, s.a, []byte("one"), []byte("two"))
	waitFor(t, "two datagrams", func() bool { return db.count() == 2 })
	for i, want := range []string{"one", "two"} {
		id, p, err := wire.DecodeDatagram(db.got[i])
		if err != nil || id != 20 || string(p) != want {
			t.Fatalf("datagram %d: ID %d %q %v, want ID 20 %q", i, id, p, err, want)
		}
	}
}

func TestPacketsTooLargeTakesTheStream(t *testing.T) {
	checkGoroutines(t)
	db := newSink()
	db.err = kolotransport.ErrDatagramTooLarge
	s := startPackets(t, context.Background(), 1<<16, nil, nil, nil, db, long)
	writeFrames(t, s.a, bytes.Repeat([]byte{3}, 1200))
	if got := readFrame(t, s.b); len(got) != 1200 {
		t.Fatalf("b got %d bytes, want the 1200-byte packet as a frame", len(got))
	}
}

func TestPacketsDroppedDatagramIsNotAFrame(t *testing.T) {
	checkGoroutines(t)
	db := newSink()
	db.err = kolotransport.ErrDatagramDropped
	s := startPackets(t, context.Background(), 1<<16, nil, nil, nil, db, long)
	writeFrames(t, s.a, []byte("lost"), []byte("close"))
	s.a.Close()
	if got, err := readAll(t, s.b); err != nil || !bytes.Equal(got, append([]byte{5}, "close"...)) {
		t.Fatalf("b's stream carried %x, %v; a dropped datagram must not become a frame, except the last", got, err)
	}
}

func TestPacketsDeliver(t *testing.T) {
	checkGoroutines(t)
	da := newSink()
	s := startPackets(t, context.Background(), 1<<16, nil, nil, da, nil, long)
	waitFor(t, "the session", s.la.running)
	s.la.Deliver([]byte("datagram"))
	if got := readFrame(t, s.b); string(got) != "datagram" {
		t.Fatalf("b got %q", got)
	}
	s.lb.Deliver([]byte("from b"))
	waitFor(t, "a datagram to a", func() bool { return da.count() == 1 })
	if id, p, err := wire.DecodeDatagram(da.got[0]); err != nil || id != 10 || string(p) != "from b" {
		t.Fatalf("a got ID %d %q %v", id, p, err)
	}
}

func TestPacketsDeliverBeforeRunIsDropped(t *testing.T) {
	checkGoroutines(t)
	a, ra := streamPair(1 << 16)
	b, rb := streamPair(1 << 16)
	la, lb := NewLeg(ra, nil, nil, 1), NewLeg(rb, nil, nil, 2)
	la.Deliver([]byte("early"))
	code := make(chan uint64, 1)
	go func() { code <- Packets(context.Background(), la, lb, long) }()
	a.Close()
	if got, err := readAll(t, b); err != nil || len(got) != 0 {
		t.Fatalf("b got %x %v; a datagram before the session must be dropped", got, err)
	}
	b.Close()
	if c := <-code; c != Done {
		t.Fatalf("code %d", c)
	}
}

func TestPacketsDeliverNeverBlocks(t *testing.T) {
	checkGoroutines(t)
	// b never reads, so its stream fills and the queue towards it stays full.
	s := startPackets(t, context.Background(), 4096, nil, nil, newSink(), nil, long)
	waitFor(t, "the session", s.la.running)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			s.la.Deliver(make([]byte, 1000))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Deliver blocked on a full queue")
	}
}

func TestPacketsStreamWaitsWhenTheQueueIsFull(t *testing.T) {
	checkGoroutines(t)
	s := startPackets(t, context.Background(), 1<<20, nil, nil, nil, nil, long)
	const total = 3 * QueueSize
	go func() {
		for i := range total {
			writeFrames(t, s.a, bytes.Repeat([]byte{byte(i)}, 1000))
		}
	}()
	for i := range total {
		if got := readFrame(t, s.b); len(got) != 1000 || got[0] != byte(i) {
			t.Fatalf("frame %d: %d bytes starting %d; stream packets must neither drop nor reorder", i, len(got), got[0])
		}
	}
}

func TestPacketsBucketDropsDatagrams(t *testing.T) {
	checkGoroutines(t)
	const perSec, burst = 16 << 10, 16 << 10
	ra := rate.NewLimiter(perSec, burst)
	ra.AllowN(time.Now(), burst)
	db := newSink()
	s := startPackets(t, context.Background(), 1<<20, ra, nil, nil, db, long)
	waitFor(t, "the session", s.la.running)
	begin := time.Now()
	for time.Since(begin) < 500*time.Millisecond {
		s.la.Deliver(make([]byte, 1000))
		time.Sleep(100 * time.Microsecond)
	}
	time.Sleep(50 * time.Millisecond)
	if got, max := db.count()*1002, int(perSec*time.Since(begin).Seconds())+2004; got > max || got == 0 {
		t.Fatalf("forwarded %d bytes of datagrams in %v, want some and at most %d at %d B/s", got, time.Since(begin), max, perSec)
	}
}

func TestPacketsMaxBytes(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.MaxBytes = 10000
	db := newSink()
	s := startPackets(t, context.Background(), 1<<20, nil, nil, newSink(), db, lim)
	waitFor(t, "the session", s.la.running)
	var w wire.PacketWriter
	for range 20 {
		s.la.Deliver(make([]byte, 998))
		w.Write(s.a, make([]byte, 998))
	}
	if c := s.wait(t, 5*time.Second); c != EndBytes {
		t.Fatalf("code %d, want EndBytes", c)
	}
	if got := int64(db.count()) * 1000; got > lim.MaxBytes {
		t.Fatalf("forwarded %d frame bytes, above MaxBytes %d", got, lim.MaxBytes)
	}
	_, err := readAll(t, s.b)
	if code := resetCode(t, err); code != EndBytes {
		t.Fatalf("b code %d", code)
	}
}

func TestPacketsIdle(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.Idle = 300 * time.Millisecond
	db := newSink()
	s := startPackets(t, context.Background(), 1<<16, nil, nil, newSink(), db, lim)
	waitFor(t, "the session", s.la.running)
	for range 20 {
		s.la.Deliver([]byte("x"))
		time.Sleep(50 * time.Millisecond)
	}
	if !s.running() {
		t.Fatalf("ended with code %d while datagrams flowed", s.wait(t, 0))
	}
	if c := s.wait(t, 5*time.Second); c != EndIdle {
		t.Fatalf("code %d after datagrams stopped, want EndIdle", c)
	}
	_, err := readAll(t, s.b)
	if code := resetCode(t, err); code != EndIdle {
		t.Fatalf("b code %d", code)
	}
}

func TestPacketsHalfFrameIsIdle(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.Idle = 300 * time.Millisecond
	s := startPackets(t, context.Background(), 1<<16, nil, nil, nil, nil, lim)
	s.a.Write([]byte{100, 1, 2})
	if c := s.wait(t, 5*time.Second); c != EndIdle {
		t.Fatalf("code %d, want EndIdle", c)
	}
}

func TestPacketsStalledReaderIsIdle(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.Idle = 300 * time.Millisecond
	s := startPackets(t, context.Background(), 1<<12, nil, nil, nil, nil, lim)
	go func() {
		var w wire.PacketWriter
		for {
			if w.Write(s.a, make([]byte, 1000)) != nil {
				return
			}
		}
	}()
	if c := s.wait(t, 5*time.Second); c != EndIdle {
		t.Fatalf("code %d, want EndIdle", c)
	}
}

func TestPacketsRateWaitIsNotIdle(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.Idle = 300 * time.Millisecond
	ra := rate.NewLimiter(8<<10, 8<<10)
	s := startPackets(t, context.Background(), 1<<20, ra, nil, nil, nil, lim)
	go func() {
		var w wire.PacketWriter
		for {
			if w.Write(s.a, make([]byte, 1000)) != nil {
				return
			}
		}
	}()
	go func() {
		r := wire.NewPacketReader(s.b)
		p := make([]byte, wire.MaxPacketSize)
		for {
			if _, err := r.Read(p); err != nil {
				return
			}
		}
	}()
	time.Sleep(2500 * time.Millisecond)
	if !s.running() {
		t.Fatalf("ended with code %d while waiting on the bucket", s.wait(t, 0))
	}
}

func TestPacketsRate(t *testing.T) {
	checkGoroutines(t)
	const perSec, burst, total = 64 << 10, 16 << 10, 96
	ra := rate.NewLimiter(perSec, burst)
	s := startPackets(t, context.Background(), 1<<20, ra, nil, nil, nil, long)
	begin := time.Now()
	go func() {
		for range total {
			writeFrames(t, s.a, make([]byte, 1022))
		}
		s.a.Close()
	}()
	got, err := readAll(t, s.b)
	if err != nil || len(got) != total*1024 {
		t.Fatalf("b got %d bytes, %v", len(got), err)
	}
	if min := time.Duration(float64(total*1024-burst) / perSec * float64(time.Second)); time.Since(begin) < min*9/10 {
		t.Fatalf("%d bytes in %v, faster than %d B/s with burst %d", total*1024, time.Since(begin), perSec, burst)
	}
}

func TestPacketsBadFrameEndsTheSession(t *testing.T) {
	checkGoroutines(t)
	s := startPackets(t, context.Background(), 1<<16, nil, nil, nil, nil, long)
	s.a.Write([]byte{0})
	if c := s.wait(t, 5*time.Second); c != EndPeer {
		t.Fatalf("code %d, want EndPeer", c)
	}
}

func TestPacketsPeerReset(t *testing.T) {
	checkGoroutines(t)
	s := startPackets(t, context.Background(), 1<<16, nil, nil, newSink(), newSink(), long)
	s.a.CancelWrite(9)
	if c := s.wait(t, 5*time.Second); c != EndPeer {
		t.Fatalf("code %d, want EndPeer", c)
	}
}

func TestPacketsClosingAndDuration(t *testing.T) {
	checkGoroutines(t)
	ctx, cancel := context.WithCancel(context.Background())
	s := startPackets(t, ctx, 1<<16, nil, nil, newSink(), newSink(), long)
	cancel()
	if c := s.wait(t, 5*time.Second); c != EndClosing {
		t.Fatalf("code %d, want EndClosing", c)
	}
	lim := long
	lim.MaxDuration = 200 * time.Millisecond
	s = startPackets(t, context.Background(), 1<<16, nil, nil, newSink(), newSink(), lim)
	if c := s.wait(t, 5*time.Second); c != EndDuration {
		t.Fatalf("code %d, want EndDuration", c)
	}
	_, err := readAll(t, s.a)
	if code := resetCode(t, err); code != EndDuration {
		t.Fatalf("a code %d", code)
	}
}

func TestPacketsFlushGathersFrames(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.Flush = 20 * time.Millisecond
	s := startPackets(t, context.Background(), 1<<20, nil, nil, nil, nil, lim)
	const packets = 300
	begin := time.Now()
	go func() {
		for i := range packets {
			writeFrames(t, s.a, []byte{byte(i)})
			time.Sleep(200 * time.Microsecond)
		}
		s.a.Close()
	}()
	got, err := readAll(t, s.b)
	if err != nil || len(got) != 2*packets {
		t.Fatalf("b got %d bytes, %v", len(got), err)
	}
	for i := range packets {
		if got[2*i] != 1 || got[2*i+1] != byte(i) {
			t.Fatalf("frame %d is %x, out of order", i, got[2*i:2*i+2])
		}
	}
	if max := int(time.Since(begin)/lim.Flush) + 2; s.b.writesIn() > max {
		t.Fatalf("%d one-byte frames became %d writes in %v, want at most %d", packets, s.b.writesIn(), time.Since(begin), max)
	}
}

func TestPacketsFlushSendsTheFirstFrameAtOnce(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.Flush = time.Second
	s := startPackets(t, context.Background(), 1<<20, nil, nil, nil, nil, lim)
	time.Sleep(lim.Flush + lim.Flush/10)
	begin := time.Now()
	writeFrames(t, s.a, []byte("x"))
	readFrame(t, s.b)
	if d := time.Since(begin); d > lim.Flush/2 {
		t.Fatalf("a frame after an idle period waited %v", d)
	}
}

func TestPacketsLastFrameAlsoTakesTheStream(t *testing.T) {
	checkGoroutines(t)
	db := newSink()
	s := startPackets(t, context.Background(), 1<<16, nil, nil, nil, db, long)
	writeFrames(t, s.a, []byte("data"), []byte("close"))
	s.a.Close()
	if got, err := readAll(t, s.b); err != nil || !bytes.Equal(got, append([]byte{5}, "close"...)) {
		t.Fatalf("b's stream carried %x, %v; want the last packet as a frame, then the end", got, err)
	}
	if db.count() != 2 {
		t.Fatalf("%d datagrams, want 2", db.count())
	}
}

// never is a bucket that pays only its burst; it never refills within a test.
func never(burst int) *rate.Limiter { return rate.NewLimiter(rate.Every(time.Hour), burst) }

func TestPacketsBucketChargesEachDatagramItsOverhead(t *testing.T) {
	checkGoroutines(t)
	const paid = 10
	db := newSink()
	s := startPackets(t, context.Background(), 1<<16, never(paid*(wire.FrameSize(1)+37)), nil, nil, db, long)
	waitFor(t, "the session", s.la.running)
	for range 2 * paid {
		s.la.Deliver([]byte{1})
	}
	waitFor(t, "the paid datagrams", func() bool { return db.count() >= paid })
	time.Sleep(50 * time.Millisecond)
	if got := db.count(); got != paid {
		t.Fatalf("forwarded %d one-byte datagrams, want %d: each costs its 2-byte frame plus 37 bytes", got, paid)
	}
}

func TestPacketsBucketChargesEachFrameItsOverhead(t *testing.T) {
	checkGoroutines(t)
	const paid = 10
	s := startPackets(t, context.Background(), 1<<16, never(paid*(wire.FrameSize(1)+37)), nil, nil, nil, long)
	for i := range 2 * paid {
		writeFrames(t, s.a, []byte{byte(i)})
	}
	got := 0
	r := wire.NewPacketReader(s.b)
	p := make([]byte, wire.MaxPacketSize)
	for {
		s.b.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := r.Read(p); err != nil {
			break
		}
		got++
	}
	if got != paid {
		t.Fatalf("forwarded %d one-byte frames, want %d: each costs its 2-byte frame plus 37 bytes", got, paid)
	}
}

func TestPacketsPolicedDatagramsAreIdle(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.Idle = 300 * time.Millisecond
	s := startPackets(t, context.Background(), 1<<16, never(1), nil, nil, newSink(), lim)
	waitFor(t, "the session", s.la.running)
	for begin := time.Now(); s.running(); time.Sleep(20 * time.Millisecond) {
		if time.Since(begin) > 3*time.Second {
			t.Fatal("datagrams the bucket drops kept the session open for 3s, 10 times its idle timeout")
		}
		s.la.Deliver([]byte("x"))
	}
	if c := s.wait(t, time.Second); c != EndIdle {
		t.Fatalf("code %d, want EndIdle: datagrams the bucket drops are not activity", c)
	}
}

func TestPacketsDeliverAfterItsDirectionEndedEndsNothing(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.MaxBytes = 10000
	s := startPackets(t, context.Background(), 1<<16, nil, nil, nil, nil, lim)
	waitFor(t, "the session", s.la.running)
	s.a.Close()
	if got, err := readAll(t, s.b); err != nil || len(got) != 0 {
		t.Fatalf("b got %x, %v; want a clean end", got, err)
	}
	for range 20 {
		s.la.Deliver(make([]byte, 998))
	}
	writeFrames(t, s.b, []byte("still open"))
	s.b.Close()
	if got, err := readAll(t, s.a); err != nil || !bytes.Equal(got, append([]byte{10}, "still open"...)) {
		t.Fatalf("a got %x, %v", got, err)
	}
	if c := s.wait(t, 5*time.Second); c != Done {
		t.Fatalf("code %d, want Done: datagrams after a direction ended must not end the session", c)
	}
}

func TestPacketsWritesStayWithinTheBuffer(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.Flush = time.Second
	s := startPackets(t, context.Background(), 1<<20, nil, nil, nil, nil, lim)
	const packets = 200
	go func() {
		for range packets {
			writeFrames(t, s.a, make([]byte, wire.MaxPacketSize))
		}
		s.a.Close()
	}()
	if got, err := readAll(t, s.b); err != nil || len(got) != packets*wire.FrameSize(wire.MaxPacketSize) {
		t.Fatalf("b got %d bytes, %v", len(got), err)
	}
	if got := s.b.largestWriteIn(); got > BufferSize {
		t.Fatalf("a write of %d bytes, above the %d-byte buffer", got, BufferSize)
	}
}
