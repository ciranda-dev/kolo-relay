package splice

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

var long = Limits{MaxDuration: time.Minute, MaxBytes: 1 << 30, Idle: 10 * time.Second}

type spliced struct {
	a, b *memStream // the clients' ends
	code chan uint64
}

// start splices two stream pairs, as the relay does with an initiator and a target.
func start(t *testing.T, ctx context.Context, buffer int, ra, rb *rate.Limiter, lim Limits) *spliced {
	t.Helper()
	a, ra1 := streamPair(buffer)
	b, rb1 := streamPair(buffer)
	s := &spliced{a: a, b: b, code: make(chan uint64, 1)}
	go func() { s.code <- Run(ctx, ra1, rb1, ra, rb, lim) }()
	t.Cleanup(func() {
		a.CancelWrite(0)
		a.CancelRead(0)
		b.CancelWrite(0)
		b.CancelRead(0)
		select {
		case <-s.code:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return")
		}
	})
	return s
}

func (s *spliced) wait(t *testing.T, within time.Duration) uint64 {
	t.Helper()
	select {
	case c := <-s.code:
		s.code <- c
		return c
	case <-time.After(within):
		t.Fatalf("Run still running after %v", within)
		return 0
	}
}

func readAll(t *testing.T, s *memStream) ([]byte, error) {
	t.Helper()
	s.SetReadDeadline(time.Now().Add(10 * time.Second))
	return io.ReadAll(s)
}

func resetCode(t *testing.T, err error) uint64 {
	t.Helper()
	var ce *codeErr
	if !errors.As(err, &ce) || !ce.remote {
		t.Fatalf("got %v, want a reset or stop from the relay", err)
	}
	return ce.code
}

func TestForwardBothWays(t *testing.T) {
	checkGoroutines(t)
	s := start(t, context.Background(), 1<<16, nil, nil, long)
	s.a.Write([]byte("hello"))
	s.a.Close()
	if got, err := readAll(t, s.b); err != nil || string(got) != "hello" {
		t.Fatalf("b got %q %v", got, err)
	}
	s.b.Write([]byte("world"))
	s.b.Close()
	if got, err := readAll(t, s.a); err != nil || string(got) != "world" {
		t.Fatalf("a got %q %v", got, err)
	}
	if c := s.wait(t, 5*time.Second); c != Done {
		t.Fatalf("code %d, want Done", c)
	}
}

func TestLargeTransfer(t *testing.T) {
	checkGoroutines(t)
	s := start(t, context.Background(), 1<<12, nil, nil, long)
	data := bytes.Repeat([]byte("0123456789abcdef"), 1<<14)
	go func() {
		s.a.Write(data)
		s.a.Close()
	}()
	if got, err := readAll(t, s.b); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("b got %d bytes, %v", len(got), err)
	}
}

func TestMaxBytes(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.MaxBytes = 64 << 10
	s := start(t, context.Background(), 1<<20, nil, nil, lim)
	go s.a.Write(make([]byte, 100<<10))
	got, err := readAll(t, s.b)
	if code := resetCode(t, err); code != EndBytes {
		t.Fatalf("b code %d, want EndBytes", code)
	}
	if len(got) > 64<<10 {
		t.Fatalf("b got %d bytes, over the limit", len(got))
	}
	if c := s.wait(t, 5*time.Second); c != EndBytes {
		t.Fatalf("code %d, want EndBytes", c)
	}
}

func TestMaxBytesExact(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.MaxBytes = 1000
	s := start(t, context.Background(), 1<<20, nil, nil, lim)
	s.a.Write(make([]byte, 1000))
	s.a.Close()
	if got, err := readAll(t, s.b); err != nil || len(got) != 1000 {
		t.Fatalf("b got %d bytes, %v; exactly the limit must pass", len(got), err)
	}
}

func TestMaxDuration(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.MaxDuration = 200 * time.Millisecond
	s := start(t, context.Background(), 1<<16, nil, nil, lim)
	begin := time.Now()
	if c := s.wait(t, 5*time.Second); c != EndDuration {
		t.Fatalf("code %d, want EndDuration", c)
	}
	if d := time.Since(begin); d < 150*time.Millisecond {
		t.Fatalf("ended after %v", d)
	}
	_, err := readAll(t, s.a)
	if code := resetCode(t, err); code != EndDuration {
		t.Fatalf("a code %d", code)
	}
}

func TestIdle(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.Idle = 200 * time.Millisecond
	s := start(t, context.Background(), 1<<16, nil, nil, lim)
	if c := s.wait(t, 5*time.Second); c != EndIdle {
		t.Fatalf("code %d, want EndIdle", c)
	}
	_, err := readAll(t, s.b)
	if code := resetCode(t, err); code != EndIdle {
		t.Fatalf("b code %d", code)
	}
}

func TestOneWayTrafficIsNotIdle(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.Idle = 300 * time.Millisecond
	s := start(t, context.Background(), 1<<16, nil, nil, lim)
	go io.Copy(io.Discard, s.b)
	for range 20 {
		if _, err := s.a.Write([]byte("x")); err != nil {
			t.Fatalf("write: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case c := <-s.code:
		s.code <- c
		t.Fatalf("ended with code %d while one direction was busy", c)
	default:
	}
	if c := s.wait(t, 5*time.Second); c != EndIdle {
		t.Fatalf("code %d after traffic stopped, want EndIdle", c)
	}
}

func TestStalledReaderIsIdle(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.Idle = 300 * time.Millisecond
	s := start(t, context.Background(), 1<<12, nil, nil, lim)
	go s.a.Write(make([]byte, 1<<20))
	if c := s.wait(t, 5*time.Second); c != EndIdle {
		t.Fatalf("code %d, want EndIdle", c)
	}
}

func TestPeerReset(t *testing.T) {
	checkGoroutines(t)
	s := start(t, context.Background(), 1<<16, nil, nil, long)
	s.a.CancelWrite(9)
	if c := s.wait(t, 5*time.Second); c != EndPeer {
		t.Fatalf("code %d, want EndPeer", c)
	}
	_, err := readAll(t, s.b)
	if code := resetCode(t, err); code != EndPeer {
		t.Fatalf("b code %d", code)
	}
}

func TestPeerStop(t *testing.T) {
	checkGoroutines(t)
	s := start(t, context.Background(), 1<<16, nil, nil, long)
	s.b.CancelRead(9)
	s.a.Write([]byte("lost"))
	if c := s.wait(t, 5*time.Second); c != EndPeer {
		t.Fatalf("code %d, want EndPeer", c)
	}
}

func TestClosing(t *testing.T) {
	checkGoroutines(t)
	ctx, cancel := context.WithCancel(context.Background())
	s := start(t, ctx, 1<<16, nil, nil, long)
	cancel()
	if c := s.wait(t, 5*time.Second); c != EndClosing {
		t.Fatalf("code %d, want EndClosing", c)
	}
	_, err := readAll(t, s.a)
	if code := resetCode(t, err); code != EndClosing {
		t.Fatalf("a code %d", code)
	}
}

func TestRate(t *testing.T) {
	checkGoroutines(t)
	const perSec, burst, total = 64 << 10, 16 << 10, 96 << 10
	ra := rate.NewLimiter(perSec, burst)
	s := start(t, context.Background(), 1<<20, ra, nil, long)
	begin := time.Now()
	go func() {
		s.a.Write(make([]byte, total))
		s.a.Close()
	}()
	got, err := readAll(t, s.b)
	if err != nil || len(got) != total {
		t.Fatalf("b got %d bytes, %v", len(got), err)
	}
	if min := time.Duration(float64(total-burst) / perSec * float64(time.Second)); time.Since(begin) < min*9/10 {
		t.Fatalf("%d bytes in %v, faster than %d B/s with burst %d", total, time.Since(begin), perSec, burst)
	}
	s.b.Close()
}

func TestSmallBurstStillWorks(t *testing.T) {
	checkGoroutines(t)
	ra := rate.NewLimiter(1<<20, 1000)
	s := start(t, context.Background(), 1<<20, ra, nil, long)
	go func() {
		s.a.Write(make([]byte, 10000))
		s.a.Close()
	}()
	if got, err := readAll(t, s.b); err != nil || len(got) != 10000 {
		t.Fatalf("b got %d bytes, %v", len(got), err)
	}
}

func TestRateWaitIsNotIdle(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.Idle = 300 * time.Millisecond
	ra := rate.NewLimiter(8<<10, 8<<10)
	s := start(t, context.Background(), 1<<20, ra, nil, lim)
	go func() {
		for {
			if _, err := s.a.Write(make([]byte, 4096)); err != nil {
				return
			}
		}
	}()
	go io.Copy(io.Discard, s.b)
	time.Sleep(2500 * time.Millisecond)
	select {
	case c := <-s.code:
		s.code <- c
		t.Fatalf("ended with code %d while waiting on the bucket", c)
	default:
	}
}

func TestCopyBuffer(t *testing.T) {
	checkGoroutines(t)
	s := start(t, context.Background(), 1<<20, nil, nil, long)
	s.a.Write(make([]byte, 1<<20))
	s.a.Close()
	if got, err := readAll(t, s.b); err != nil || len(got) != 1<<20 {
		t.Fatalf("b got %d bytes, %v", len(got), err)
	}
	if n, want := s.b.writesIn(), (1<<20)/(64<<10); n != want {
		t.Fatalf("1 MiB available at once took %d writes, want %d of 64 KiB", n, want)
	}
}

func TestFlushCoalescesSmallReads(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.Flush = 20 * time.Millisecond
	s := start(t, context.Background(), 1<<20, nil, nil, lim)
	const chunks = 300
	begin := time.Now()
	go func() {
		for i := range chunks {
			s.a.Write([]byte{byte(i)})
			time.Sleep(200 * time.Microsecond)
		}
		s.a.Close()
	}()
	got, err := readAll(t, s.b)
	if err != nil || len(got) != chunks {
		t.Fatalf("b got %d bytes, %v", len(got), err)
	}
	for i, c := range got {
		if c != byte(i) {
			t.Fatalf("byte %d is %d, out of order", i, c)
		}
	}
	if max := int(time.Since(begin)/lim.Flush) + 2; s.b.writesIn() > max {
		t.Fatalf("%d one-byte reads became %d writes in %v, want at most %d", chunks, s.b.writesIn(), time.Since(begin), max)
	}
}

func TestFlushSendsFirstChunkAtOnce(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.Flush = time.Second
	s := start(t, context.Background(), 1<<20, nil, nil, lim)
	time.Sleep(lim.Flush + lim.Flush/10)
	begin := time.Now()
	s.a.Write([]byte("x"))
	s.b.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(s.b, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(begin); d > lim.Flush/2 {
		t.Fatalf("a chunk after an idle period waited %v", d)
	}
}

func TestFlushDoesNotSlowFullBuffers(t *testing.T) {
	checkGoroutines(t)
	lim := long
	lim.Flush = 30 * time.Second
	s := start(t, context.Background(), 1<<20, nil, nil, lim)
	data := bytes.Repeat([]byte("0123456789abcdef"), 1<<16)
	begin := time.Now()
	go func() {
		s.a.Write(data)
		s.a.Close()
	}()
	if got, err := readAll(t, s.b); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("b got %d bytes, %v", len(got), err)
	}
	// Flush is far above any scheduling delay, so a copy that waited for it even once cannot finish within half of it.
	if d := time.Since(begin); d > lim.Flush/2 {
		t.Fatalf("%d bytes took %v; full buffers must not wait for Flush", len(data), d)
	}
}
