// Package pconn carries the packets of an end-to-end QUIC connection as datagrams or frames on one stream to the relay.
package pconn

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ciranda-dev/kolo-relay/internal/wire"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// FlushTimeout bounds how long Close sends the packets still queued, and then how long it waits for the peer to end its side.
const FlushTimeout = time.Second

// RecvQueue is how many packets that arrived as datagrams wait for ReadFrom, as many as quic-go queues per connection.
const RecvQueue = 128

var errClosed = fmt.Errorf("kolorelay: packet conn closed: %w", net.ErrClosed)

// Stream is the part of a kolotransport.Stream that Conn uses.
type Stream interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
	CancelRead(code uint64) error
	CancelWrite(code uint64) error
	SetWriteDeadline(t time.Time) error
}

// Datagrams is the datagram path of a session: Send sends one datagram payload without blocking, and ID is the session's
// quarter stream ID on that connection.
type Datagrams struct {
	Send func(p []byte) error
	ID   uint64
}

// Counts are the packets a Conn sent and received on each path.
type Counts struct {
	FramesSent, FramesReceived, DatagramsSent, DatagramsReceived uint64
}

// Conn is a net.PacketConn whose packets travel as datagrams when it has a datagram path, else as frames on a Stream.
// WriteTo never blocks: a full queue drops its oldest packet, as UDP would, so the newest (such as a CONNECTION_CLOSE) is kept.
type Conn struct {
	s      Stream
	local  *net.UDPAddr
	remote *net.UDPAddr
	dg     *Datagrams

	mu       sync.Mutex
	isClosed bool
	out      chan []byte
	dbuf     []byte
	dgLast   bool

	in       chan []byte
	din      chan []byte
	closed   chan struct{}
	done     chan struct{}
	wdone    chan struct{}
	err      error
	flushed  bool
	dropped  atomic.Uint64
	received atomic.Uint64
	counts   struct{ framesSent, framesReceived, datagramsSent, datagramsReceived atomic.Uint64 }
	rdl      deadline
	once     sync.Once
}

// New returns a Conn on s that queues at most queue frames and reports remote as the source of every packet; dg, if not nil,
// is its datagram path.
func New(s Stream, local, remote *net.UDPAddr, queue int, dg *Datagrams) *Conn {
	c := &Conn{
		s:      s,
		local:  local,
		remote: remote,
		dg:     dg,
		out:    make(chan []byte, max(queue, 1)),
		in:     make(chan []byte, 1),
		din:    make(chan []byte, RecvQueue),
		closed: make(chan struct{}),
		done:   make(chan struct{}),
		wdone:  make(chan struct{}),
		rdl:    deadline{ch: make(chan struct{})},
	}
	go c.readLoop()
	go c.writeLoop()
	return c
}

func (c *Conn) readLoop() {
	defer close(c.done)
	r := wire.NewPacketReader(c.s)
	buf := make([]byte, wire.MaxPacketSize)
	for {
		n, err := r.Read(buf)
		if err != nil {
			c.err = err
			return
		}
		c.received.Add(uint64(wire.FrameSize(n)))
		c.counts.framesReceived.Add(1)
		// After Close, packets are read and dropped until the peer ends its side.
		select {
		case c.in <- bytes.Clone(buf[:n]):
		case <-c.closed:
		}
	}
}

func (c *Conn) writeLoop() {
	defer close(c.wdone)
	var w wire.PacketWriter
	failed := false
	for p := range c.out {
		if !failed {
			if w.Write(c.s, p) != nil {
				failed = true
			} else {
				c.counts.framesSent.Add(1)
			}
		}
	}
	if failed {
		c.s.CancelWrite(0)
		return
	}
	c.flushed = c.s.Close() == nil
}

// ReadFrom reads the next packet into p, truncating it if p is shorter; the source is always the relay address.
// It returns an error only after Close or once the read deadline passes.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, errClosed
	default:
	}
	select {
	case b := <-c.in:
		return copy(p, b), c.remote, nil
	case b := <-c.din:
		return copy(p, b), c.remote, nil
	default:
	}
	// quic-go closes the connection on a read error before it handles packets it already read, so the end of the
	// stream is not an error here.
	select {
	case b := <-c.in:
		return copy(p, b), c.remote, nil
	case b := <-c.din:
		return copy(p, b), c.remote, nil
	case <-c.closed:
		return 0, nil, errClosed
	case <-c.rdl.wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

// Deliver queues p, a packet that arrived as a datagram, for ReadFrom and keeps it; it never blocks and drops p when
// RecvQueue packets wait or after Close.
func (c *Conn) Deliver(p []byte) {
	c.received.Add(uint64(wire.FrameSize(len(p))))
	c.counts.datagramsReceived.Add(1)
	select {
	case <-c.closed:
		return
	default:
	}
	select {
	case c.din <- p:
	default:
		c.dropped.Add(1)
	}
}

// WriteTo sends p as a datagram if it can, else queues it as a frame, and ignores addr. A datagram that does not fit on
// the path goes as a frame; one the full datagram queue refuses is dropped. A full frame queue drops its oldest packet.
func (c *Conn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if len(p) == 0 || len(p) > wire.MaxPacketSize {
		return 0, wire.ErrPacketSize
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed {
		return 0, errClosed
	}
	if c.dg != nil && c.sendDatagram(p) {
		return len(p), nil
	}
	c.dgLast = false
	b := bytes.Clone(p)
	for {
		select {
		case c.out <- b:
			return len(p), nil
		default:
		}
		// mu keeps other writers out, so only the writer goroutine competes for the queue.
		select {
		case <-c.out:
			c.dropped.Add(1)
		default:
		}
	}
}

// sendDatagram sends p as a datagram and reports whether p is done with, sent or dropped; c.mu is held.
func (c *Conn) sendDatagram(p []byte) bool {
	var err error
	if c.dbuf, err = wire.AppendDatagram(c.dbuf[:0], c.dg.ID, p); err != nil {
		return false
	}
	switch err := c.dg.Send(c.dbuf); {
	case err == nil:
		c.counts.datagramsSent.Add(1)
	case errors.Is(err, kolotransport.ErrDatagramDropped):
		c.dropped.Add(1)
	default:
		return false
	}
	// Close sends this packet again as a frame, so the newest packet is not lost to a full datagram queue.
	c.dgLast = true
	return true
}

// Close drops every queued packet but the newest, sends that one for at most FlushTimeout and ends the send side.
// If that worked, it waits up to FlushTimeout more for the peer to end its side, so a reset does not discard the last
// packets, then stops reading.
// It is safe to call more than once.
func (c *Conn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.isClosed = true
		// Only the newest packet (normally the CONNECTION_CLOSE) is sent: older ones could not drain within FlushTimeout
		// behind a slow relay.
		var last []byte
		for drained := false; !drained; {
			select {
			case p := <-c.out:
				if last != nil {
					c.dropped.Add(1)
				}
				last = p
			default:
				drained = true
			}
		}
		if c.dgLast {
			if last != nil {
				c.dropped.Add(1)
			}
			_, p, _ := wire.DecodeDatagram(c.dbuf)
			last = bytes.Clone(p)
		}
		if last != nil {
			c.out <- last
		}
		close(c.out)
		c.mu.Unlock()
		close(c.closed)
		c.s.SetWriteDeadline(time.Now().Add(FlushTimeout))
		<-c.wdone
		if c.flushed {
			t := time.NewTimer(FlushTimeout)
			select {
			case <-c.done:
			case <-t.C:
			}
			t.Stop()
		}
		c.s.CancelRead(0)
		<-c.done
		c.rdl.stop()
	})
	return nil
}

// Done is closed once the stream's read side has ended, by the peer, the relay or Close.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err returns why the read side ended (io.EOF for a clean end), or nil while it is open.
func (c *Conn) Err() error {
	select {
	case <-c.done:
		return c.err
	default:
		return nil
	}
}

// Dropped returns the number of packets dropped because a queue was full, and those Close dropped to send only the newest.
func (c *Conn) Dropped() uint64 { return c.dropped.Load() }

// Received returns the bytes of the packets received on both paths, counted as frames with their length bytes.
func (c *Conn) Received() uint64 { return c.received.Load() }

// Counts returns the packets sent and received on each path.
func (c *Conn) Counts() Counts {
	return Counts{
		FramesSent:        c.counts.framesSent.Load(),
		FramesReceived:    c.counts.framesReceived.Load(),
		DatagramsSent:     c.counts.datagramsSent.Load(),
		DatagramsReceived: c.counts.datagramsReceived.Load(),
	}
}

// LocalAddr returns the local address given to New.
func (c *Conn) LocalAddr() net.Addr { return c.local }

// SetDeadline sets the read deadline; WriteTo never blocks.
func (c *Conn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

// SetReadDeadline makes ReadFrom return os.ErrDeadlineExceeded once t has passed; zero means no deadline.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.rdl.set(t)
	return nil
}

// SetWriteDeadline does nothing, since WriteTo never blocks.
func (c *Conn) SetWriteDeadline(time.Time) error { return nil }

// SetReadBuffer does nothing; it exists so quic-go does not warn about buffer sizes.
func (c *Conn) SetReadBuffer(int) error { return nil }

// SetWriteBuffer does nothing; it exists so quic-go does not warn about buffer sizes.
func (c *Conn) SetWriteBuffer(int) error { return nil }

// deadline is a channel closed once a time has passed, like net.Pipe's.
type deadline struct {
	mu    sync.Mutex
	timer *time.Timer
	gen   uint64
	ch    chan struct{}
}

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	// A stopped timer may already be running; the generation tells it it is stale.
	d.gen++
	expired := isClosed(d.ch)
	if t.IsZero() {
		if expired {
			d.ch = make(chan struct{})
		}
		return
	}
	wait := time.Until(t)
	if wait <= 0 {
		if !expired {
			close(d.ch)
		}
		return
	}
	if expired {
		d.ch = make(chan struct{})
	}
	gen := d.gen
	d.timer = time.AfterFunc(wait, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.gen == gen && !isClosed(d.ch) {
			close(d.ch)
		}
	})
}

func (d *deadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ch
}

func (d *deadline) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
	}
}

func isClosed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
