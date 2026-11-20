package pconn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-relay/internal/wire"
)

var (
	localA = &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 1001}
	localB = &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 1002}
	relay  = &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 4000}
)

func connPair(t *testing.T, buffer, queue int) (*Conn, *Conn, *memStream, *memStream) {
	t.Helper()
	a, b := streamPair(buffer)
	ca, cb := New(a, localA, relay, queue), New(b, localB, relay, queue)
	t.Cleanup(func() {
		ca.Close()
		cb.Close()
	})
	return ca, cb, a, b
}

func seq(i, size int) []byte {
	p := make([]byte, size)
	binary.BigEndian.PutUint32(p, uint32(i))
	return p
}

func read(t *testing.T, c *Conn) []byte {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	p := make([]byte, wire.MaxPacketSize)
	n, addr, err := c.ReadFrom(p)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if addr.String() != relay.String() {
		t.Fatalf("source %v, want %v", addr, relay)
	}
	return p[:n]
}

func TestRoundTrip(t *testing.T) {
	checkGoroutines(t)
	ca, cb, _, _ := connPair(t, 1<<16, 16)
	for _, n := range []int{1, 1200, 1280, wire.MaxPacketSize} {
		p := bytes.Repeat([]byte{byte(n)}, n)
		if got, err := ca.WriteTo(p, relay); err != nil || got != n {
			t.Fatalf("WriteTo %d: %d %v", n, got, err)
		}
		p[0] ^= 0xff
		if got := read(t, cb); !bytes.Equal(got, bytes.Repeat([]byte{byte(n)}, n)) {
			t.Fatalf("packet of %d bytes changed in transit (%d bytes)", n, len(got))
		}
	}
	if _, err := cb.WriteTo([]byte("back"), nil); err != nil {
		t.Fatal(err)
	}
	if got := read(t, ca); string(got) != "back" {
		t.Fatalf("got %q", got)
	}
}

func TestWriteToSize(t *testing.T) {
	checkGoroutines(t)
	ca, _, _, _ := connPair(t, 1<<16, 16)
	for _, n := range []int{0, wire.MaxPacketSize + 1} {
		if _, err := ca.WriteTo(make([]byte, n), relay); !errors.Is(err, wire.ErrPacketSize) {
			t.Errorf("%d bytes: %v, want ErrPacketSize", n, err)
		}
	}
}

func TestDropWhenFull(t *testing.T) {
	checkGoroutines(t)
	const queue, total = 8, 200
	ca, cb, _, _ := connPair(t, 4096, queue)
	start := time.Now()
	for i := range total {
		if n, err := ca.WriteTo(seq(i, 1000), relay); err != nil || n != 1000 {
			t.Fatalf("WriteTo %d: %d %v", i, n, err)
		}
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("WriteTo blocked: %v for %d packets", d, total)
	}
	dropped := ca.Dropped()
	if dropped == 0 || dropped >= total {
		t.Fatalf("dropped %d of %d", dropped, total)
	}
	go ca.Close()
	got, last := 0, -1
	p := make([]byte, wire.MaxPacketSize)
	for {
		select {
		case <-cb.Done():
			cb.SetReadDeadline(time.Now())
		default:
			cb.SetReadDeadline(time.Now().Add(5 * time.Second))
		}
		n, _, err := cb.ReadFrom(p)
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("ReadFrom: %v", err)
			}
			break
		}
		s := int(binary.BigEndian.Uint32(p))
		if n != 1000 || s <= last {
			t.Fatalf("packet %d: %d bytes, sequence %d after %d", got, n, s, last)
		}
		got, last = got+1, s
	}
	// Close drops the queued packets but the newest, so count the drops once it has run.
	if dropped = ca.Dropped(); uint64(got)+dropped != total {
		t.Fatalf("delivered %d + dropped %d != %d", got, dropped, total)
	}
	// Queue, one frame in the writer, five frames in the 4096-byte stream buffer, two in the reader.
	if got > queue+8 {
		t.Fatalf("delivered %d, more than the queue and stream buffer can hold", got)
	}
}

func TestReadDeadline(t *testing.T) {
	checkGoroutines(t)
	ca, cb, _, _ := connPair(t, 1<<16, 16)
	p := make([]byte, 100)
	ca.SetReadDeadline(time.Now().Add(-time.Second))
	_, _, err := ca.ReadFrom(p)
	var ne net.Error
	if !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("past deadline: %v", err)
	}

	ca.SetReadDeadline(time.Time{})
	errc := make(chan error, 1)
	go func() {
		_, _, err := ca.ReadFrom(p)
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)
	ca.SetDeadline(time.Now())
	select {
	case err := <-errc:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("unblocked with %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SetReadDeadline did not unblock ReadFrom")
	}

	ca.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, _, err := ca.ReadFrom(p); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("timer deadline: %v", err)
	}

	ca.SetReadDeadline(time.Time{})
	cb.WriteTo([]byte("after"), relay)
	if got := read(t, ca); string(got) != "after" {
		t.Fatalf("got %q", got)
	}
}

func TestTruncatedRead(t *testing.T) {
	checkGoroutines(t)
	ca, cb, _, _ := connPair(t, 1<<16, 16)
	ca.WriteTo([]byte("abcdef"), relay)
	p := make([]byte, 3)
	cb.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, _, err := cb.ReadFrom(p); err != nil || string(p[:n]) != "abc" {
		t.Fatalf("got %q %v", p[:n], err)
	}
}

// waitEnd checks that the read side ends and that ReadFrom then waits like UDP instead of failing.
func waitEnd(t *testing.T, c *Conn) {
	t.Helper()
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done not closed")
	}
	c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := c.ReadFrom(make([]byte, 10)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom after the end: %v, want it to wait until the deadline", err)
	}
}

func TestPeerCloseEndsRead(t *testing.T) {
	checkGoroutines(t)
	ca, cb, _, _ := connPair(t, 1<<16, 16)
	for i := range 3 {
		ca.WriteTo(seq(i, 10), relay)
	}
	for i := range 3 {
		if got := read(t, cb); binary.BigEndian.Uint32(got) != uint32(i) {
			t.Fatalf("packet %d out of order", i)
		}
	}
	ca.Close()
	waitEnd(t, cb)
	if err := cb.Err(); err != io.EOF {
		t.Fatalf("Err %v, want io.EOF", err)
	}
}

func TestPeerResetEndsRead(t *testing.T) {
	checkGoroutines(t)
	ca, _, _, b := connPair(t, 1<<16, 16)
	if ca.Err() != nil {
		t.Fatal("Err before the end")
	}
	b.CancelWrite(7)
	waitEnd(t, ca)
	var ce *codeErr
	if !errors.As(ca.Err(), &ce) || ce.code != 7 {
		t.Fatalf("Err %v, want the reset with code 7", ca.Err())
	}
}

func TestBadFrameEndsRead(t *testing.T) {
	checkGoroutines(t)
	ca, _, _, b := connPair(t, 1<<16, 16)
	b.Write([]byte{0xad, 0x0b})
	waitEnd(t, ca)
	if !errors.Is(ca.Err(), wire.ErrProtocol) {
		t.Fatalf("Err %v, want ErrProtocol", ca.Err())
	}
}

func TestClose(t *testing.T) {
	checkGoroutines(t)
	ca, _, _, b := connPair(t, 1<<16, 16)
	errc := make(chan error, 1)
	go func() {
		_, _, err := ca.ReadFrom(make([]byte, 10))
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := ca.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked ReadFrom: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock ReadFrom")
	}
	if _, err := ca.WriteTo([]byte("x"), relay); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WriteTo after Close: %v", err)
	}
	if _, _, err := ca.ReadFrom(make([]byte, 10)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFrom after Close: %v", err)
	}
	if err := ca.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	b.SetWriteDeadline(time.Now().Add(5 * time.Second))
	var ce *codeErr
	if _, err := b.Write(make([]byte, 10)); !errors.As(err, &ce) || !ce.remote {
		t.Fatalf("peer write after Close: %v, want a stop", err)
	}
}

func TestCloseFlushIsBounded(t *testing.T) {
	checkGoroutines(t)
	// Nobody reads b, and its 500-byte buffer cannot take even the final 1002-byte frame, so the flush fails.
	a, b := streamPair(500)
	ca := New(a, localA, relay, 16)
	t.Cleanup(func() { ca.Close() })
	for i := range 16 {
		ca.WriteTo(seq(i, 1000), relay)
	}
	start := time.Now()
	ca.Close()
	if d := time.Since(start); d < FlushTimeout/2 || d > 2*FlushTimeout+time.Second {
		t.Fatalf("Close took %v, want about %v", d, FlushTimeout)
	}
	b.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := io.ReadAll(b)
	var ce *codeErr
	if !errors.As(err, &ce) || !ce.remote {
		t.Fatalf("peer read after a failed flush: %v, want a reset", err)
	}
}

func TestCloseAfterPeerStop(t *testing.T) {
	checkGoroutines(t)
	ca, _, _, b := connPair(t, 1<<16, 16)
	b.CancelRead(3)
	ca.WriteTo([]byte("lost"), relay)
	start := time.Now()
	ca.Close()
	// A Close that waited would take the whole FlushTimeout.
	if d := time.Since(start); d > FlushTimeout*9/10 {
		t.Fatalf("Close took %v after the peer stopped reading", d)
	}
}

func TestAddrAndBuffers(t *testing.T) {
	checkGoroutines(t)
	ca, _, _, _ := connPair(t, 1<<16, 16)
	if ca.LocalAddr().String() != localA.String() {
		t.Fatalf("LocalAddr %v", ca.LocalAddr())
	}
	if _, ok := ca.LocalAddr().(*net.UDPAddr); !ok {
		t.Fatal("LocalAddr is not a *net.UDPAddr")
	}
	if ca.SetReadBuffer(1<<20) != nil || ca.SetWriteBuffer(1<<20) != nil || ca.SetWriteDeadline(time.Now()) != nil {
		t.Fatal("buffer and write deadline setters must succeed")
	}
	var _ net.PacketConn = ca
}

func TestSourceIsUDPAddr(t *testing.T) {
	checkGoroutines(t)
	ca, cb, _, _ := connPair(t, 1<<16, 16)
	ca.WriteTo([]byte("x"), relay)
	cb.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, addr, err := cb.ReadFrom(make([]byte, 10))
	if err != nil {
		t.Fatal(err)
	}
	if ua, ok := addr.(*net.UDPAddr); !ok || ua.String() != relay.String() {
		t.Fatalf("source %#v", addr)
	}
}

func TestLastPacketBeforeEndIsDelivered(t *testing.T) {
	checkGoroutines(t)
	for i := range 20 {
		ca, cb, _, _ := connPair(t, 1<<16, 16)
		ca.WriteTo(seq(i, 10), relay)
		closed := make(chan struct{})
		go func() {
			ca.Close()
			close(closed)
		}()
		select {
		case <-cb.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("read side did not end")
		}
		if got := read(t, cb); binary.BigEndian.Uint32(got) != uint32(i) {
			t.Fatalf("round %d: wrong packet", i)
		}
		cb.Close()
		<-closed
	}
}

func TestCloseWaitsForPeerEnd(t *testing.T) {
	checkGoroutines(t)
	ca, cb, _, _ := connPair(t, 1<<16, 16)
	closed := make(chan struct{})
	go func() {
		ca.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close returned before the peer ended its side")
	case <-time.After(FlushTimeout / 4):
	}
	cb.Close()
	select {
	case <-closed:
	case <-time.After(FlushTimeout / 2):
		t.Fatal("Close did not return once the peer ended its side")
	}
}

func TestCloseLingerIsBounded(t *testing.T) {
	checkGoroutines(t)
	ca, _, _, _ := connPair(t, 1<<16, 16)
	start := time.Now()
	ca.Close()
	if d := time.Since(start); d < FlushTimeout*3/4 || d > 2*FlushTimeout+time.Second {
		t.Fatalf("Close took %v with a silent peer, want about %v", d, FlushTimeout)
	}
}

func TestFinalPacketKeptWhenFull(t *testing.T) {
	checkGoroutines(t)
	const queue = 8
	ca, cb, _, _ := connPair(t, 2048, queue)
	for i := range 100 {
		ca.WriteTo(seq(i, 1000), relay)
	}
	if ca.Dropped() == 0 {
		t.Fatal("queue never filled")
	}
	final := seq(1<<20, 50)
	ca.WriteTo(final, relay)
	go ca.Close()
	var last []byte
	p := make([]byte, wire.MaxPacketSize)
	for {
		select {
		case <-cb.Done():
			cb.SetReadDeadline(time.Now())
		default:
			cb.SetReadDeadline(time.Now().Add(5 * time.Second))
		}
		n, _, err := cb.ReadFrom(p)
		if err != nil {
			break
		}
		last = bytes.Clone(p[:n])
	}
	if !bytes.Equal(last, final) {
		t.Fatalf("last packet delivered is %d bytes, want the final 50-byte packet written after the queue was full", len(last))
	}
}

func TestReceived(t *testing.T) {
	checkGoroutines(t)
	ca, cb, _, _ := connPair(t, 1<<16, 16)
	ca.WriteTo(make([]byte, 100), relay)
	ca.WriteTo(make([]byte, 200), relay)
	read(t, cb)
	read(t, cb)
	if got := cb.Received(); got != 1+100+2+200 {
		t.Fatalf("Received %d, want 303 (frames with their length bytes)", got)
	}
}

func TestCloseSendsOnlyTheFinalPacket(t *testing.T) {
	checkGoroutines(t)
	ca, cb, _, _ := connPair(t, 2048, 64)
	for i := range 100 {
		ca.WriteTo(seq(i, 1000), relay)
	}
	final := seq(1<<20, 50)
	ca.WriteTo(final, relay)
	go ca.Close()
	// About 4 KiB/s: the 64 queued packets would take 16s, far beyond FlushTimeout.
	var last []byte
	p := make([]byte, wire.MaxPacketSize)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cb.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := cb.ReadFrom(p)
		if err != nil {
			select {
			case <-cb.Done():
				deadline = time.Now()
			default:
			}
			continue
		}
		last = bytes.Clone(p[:n])
		if bytes.Equal(last, final) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !bytes.Equal(last, final) {
		t.Fatalf("the final packet never arrived through a slow reader")
	}
}
