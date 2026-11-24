package pconn

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-relay/internal/wire"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// fakeDatagrams records the datagrams a Conn sends and answers each with err.
type fakeDatagrams struct {
	mu   sync.Mutex
	sent [][]byte
	err  error
}

func (f *fakeDatagrams) send(p []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, bytes.Clone(p))
	return nil
}

func (f *fakeDatagrams) packets(t *testing.T, id uint64) [][]byte {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]byte
	for _, d := range f.sent {
		gid, p, err := wire.DecodeDatagram(d)
		if err != nil || gid != id {
			t.Fatalf("datagram %x: ID %d, %v; want ID %d", d, gid, err, id)
		}
		out = append(out, p)
	}
	return out
}

// datagramPair returns a Conn with a datagram path and its stream-only peer.
func datagramPair(t *testing.T, f *fakeDatagrams, id uint64) (*Conn, *Conn) {
	t.Helper()
	a, b := streamPair(1 << 16)
	ca := New(a, localA, relay, 16, &Datagrams{Send: f.send, ID: id})
	cb := New(b, localB, relay, 16, nil)
	t.Cleanup(func() {
		ca.Close()
		cb.Close()
	})
	return ca, cb
}

func TestDatagramSend(t *testing.T) {
	checkGoroutines(t)
	f := &fakeDatagrams{}
	ca, cb := datagramPair(t, f, 300)
	for _, n := range []int{1, 1200, wire.MaxPacketSize} {
		if got, err := ca.WriteTo(bytes.Repeat([]byte{byte(n)}, n), relay); err != nil || got != n {
			t.Fatalf("WriteTo %d: %d %v", n, got, err)
		}
	}
	got := f.packets(t, 300)
	if len(got) != 3 || len(got[0]) != 1 || len(got[1]) != 1200 || len(got[2]) != wire.MaxPacketSize {
		t.Fatalf("sent %d datagrams", len(got))
	}
	if c := ca.Counts(); c.DatagramsSent != 3 || c.FramesSent != 0 {
		t.Fatalf("Counts %+v, want 3 datagrams and no frame", c)
	}
	cb.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, _, err := cb.ReadFrom(make([]byte, 10)); err == nil {
		t.Fatalf("a %d-byte packet sent as a datagram also arrived on the stream", n)
	}
}

func TestDatagramTooLargeTakesTheStream(t *testing.T) {
	checkGoroutines(t)
	f := &fakeDatagrams{err: fmt.Errorf("wrapped: %w", kolotransport.ErrDatagramTooLarge)}
	ca, cb := datagramPair(t, f, 1)
	p := bytes.Repeat([]byte{7}, 1200)
	if _, err := ca.WriteTo(p, relay); err != nil {
		t.Fatal(err)
	}
	if got := read(t, cb); !bytes.Equal(got, p) {
		t.Fatalf("got %d bytes on the stream, want the 1200-byte packet", len(got))
	}
	if c := ca.Counts(); c.FramesSent != 1 || c.DatagramsSent != 0 || ca.Dropped() != 0 {
		t.Fatalf("Counts %+v, Dropped %d; want one frame", c, ca.Dropped())
	}
}

func TestDatagramDroppedIsCounted(t *testing.T) {
	checkGoroutines(t)
	f := &fakeDatagrams{err: fmt.Errorf("wrapped: %w", kolotransport.ErrDatagramDropped)}
	ca, cb := datagramPair(t, f, 1)
	for range 3 {
		if n, err := ca.WriteTo([]byte("lost"), relay); err != nil || n != 4 {
			t.Fatalf("WriteTo: %d %v, want a silent drop", n, err)
		}
	}
	if ca.Dropped() != 3 {
		t.Fatalf("Dropped %d, want 3", ca.Dropped())
	}
	cb.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, _, err := cb.ReadFrom(make([]byte, 10)); err == nil {
		t.Fatalf("a dropped %d-byte packet arrived on the stream", n)
	}
}

func TestDeliver(t *testing.T) {
	checkGoroutines(t)
	ca, _, _, _ := connPair(t, 1<<16, 16)
	ca.Deliver([]byte("from a datagram"))
	if got := read(t, ca); string(got) != "from a datagram" {
		t.Fatalf("got %q", got)
	}
	if c := ca.Counts(); c.DatagramsReceived != 1 || c.FramesReceived != 0 {
		t.Fatalf("Counts %+v", c)
	}
	if got := ca.Received(); got != 16 {
		t.Fatalf("Received %d, want 16 (the packet as a frame, length byte included)", got)
	}
}

func TestDeliverIsBoundedAndKeepsFrames(t *testing.T) {
	checkGoroutines(t)
	ca, cb, _, _ := connPair(t, 1<<16, 64)
	const extra = 10
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range RecvQueue + extra {
			ca.Deliver(seq(i, 100))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Deliver blocked")
	}
	if ca.Dropped() != extra {
		t.Fatalf("Dropped %d, want %d", ca.Dropped(), extra)
	}
	const frames = 40
	for i := range frames {
		cb.WriteTo(seq(1000+i, 50), relay)
	}
	datagrams, got := 0, 0
	p := make([]byte, wire.MaxPacketSize)
	for datagrams+got < RecvQueue+frames {
		ca.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := ca.ReadFrom(p)
		if err != nil {
			t.Fatalf("after %d datagrams and %d frames: %v", datagrams, got, err)
		}
		if n == 50 {
			got++
		} else {
			datagrams++
		}
	}
	if datagrams != RecvQueue || got != frames {
		t.Fatalf("read %d datagrams and %d frames, want %d and %d", datagrams, got, RecvQueue, frames)
	}
	if c := ca.Counts(); c.FramesReceived != frames || c.DatagramsReceived != RecvQueue+extra {
		t.Fatalf("Counts %+v", c)
	}
}

func TestDeliverAfterClose(t *testing.T) {
	checkGoroutines(t)
	ca, cb, _, _ := connPair(t, 1<<16, 16)
	go cb.Close()
	ca.Close()
	for range RecvQueue + 1 {
		ca.Deliver([]byte("late"))
	}
	if _, _, err := ca.ReadFrom(make([]byte, 10)); err == nil {
		t.Fatal("ReadFrom after Close returned a packet")
	}
}

func TestCloseSendsTheLastDatagramOnTheStream(t *testing.T) {
	checkGoroutines(t)
	f := &fakeDatagrams{err: kolotransport.ErrDatagramTooLarge}
	ca, cb := datagramPair(t, f, 2)
	ca.WriteTo([]byte("older frame"), relay)
	final := []byte("connection close")
	f.mu.Lock()
	f.err = nil
	f.mu.Unlock()
	if _, err := ca.WriteTo(final, relay); err != nil {
		t.Fatal(err)
	}
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
		t.Fatalf("last packet on the stream is %q, want the final packet that went as a datagram", last)
	}
}
