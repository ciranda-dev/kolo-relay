package splice

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ciranda-dev/kolo-relay/internal/wire"
	kolotransport "github.com/ciranda-dev/kolo-transport"
	"golang.org/x/time/rate"
)

// QueueSize is how many packets wait for one direction of a packet session, as many as quic-go queues datagrams to send.
const QueueSize = 32

// packetOverhead is what each packet costs the bucket on top of its frame: the per-packet overhead kolo-transport's
// datagram size check reserves, so small packets cannot multiply the relay's work per byte.
const packetOverhead = 37

// Leg is one client's side of a packet session: its stream, and its datagrams if it speaks version 1.
type Leg struct {
	stream Stream
	bucket *rate.Limiter
	send   func([]byte) error
	id     uint64
	q      chan []byte
	final  []byte
	sent   atomic.Int64
	s      atomic.Pointer[session]
	over   chan struct{}
}

// NewLeg returns the leg of a client on stream, whose packets bucket pays for if not nil.
// send, if not nil, sends a datagram payload to the client, and id is the leg's quarter stream ID.
func NewLeg(stream Stream, bucket *rate.Limiter, send func([]byte) error, id uint64) *Leg {
	return &Leg{stream: stream, bucket: bucket, send: send, id: id, q: make(chan []byte, QueueSize), over: make(chan struct{}, 1)}
}

// Deliver forwards p, a packet the leg's client sent as a datagram, and keeps it. It never blocks: p is dropped unless
// the session runs, the bucket can pay for it at once and the queue towards the other leg has room.
// Past MaxBytes it only signals the writer of this direction, so a direction that already ended cleanly stays so.
func (l *Leg) Deliver(p []byte) {
	s := l.s.Load()
	if s == nil {
		return
	}
	n := wire.FrameSize(len(p))
	if l.bucket != nil && !l.bucket.AllowN(time.Now(), n+packetOverhead) {
		return
	}
	s.touch()
	if !l.add(n, s.lim.MaxBytes) {
		select {
		case l.over <- struct{}{}:
		default:
		}
		return
	}
	select {
	case l.q <- p:
	default:
	}
}

// Packets forwards the packets of a and b, from frames and datagrams, until both clients end their streams (Done) or a
// limit ends the session, which cancels both streams with the returned code.
func Packets(ctx context.Context, a, b *Leg, lim Limits) uint64 {
	return run(ctx, a.stream, b.stream, lim, func(s *session, wctx context.Context, wg *sync.WaitGroup) {
		a.s.Store(s)
		b.s.Store(s)
		var work sync.WaitGroup
		work.Go(func() { s.readFrames(wctx, a) })
		work.Go(func() { s.readFrames(wctx, b) })
		work.Go(func() { s.writePackets(wctx, a, b) })
		work.Go(func() { s.writePackets(wctx, b, a) })
		done := make(chan struct{})
		wg.Go(func() {
			work.Wait()
			close(done)
		})
		wg.Go(func() { s.watchIdle(wctx, done) })
	})
}

// add adds n bytes to what l sent and reports whether that is still within max.
func (l *Leg) add(n int, max int64) bool { return l.sent.Add(int64(n)) <= max }

// readFrames queues the frames l's client sends; a full queue makes it wait, so the stream stays flow controlled.
// The end of the stream queues nil, after keeping the last packet in l.final.
func (s *session) readFrames(ctx context.Context, l *Leg) {
	r := wire.NewPacketReader(l.stream)
	buf := make([]byte, wire.MaxPacketSize)
	var last []byte
	for {
		n, err := r.Read(buf)
		if err != nil {
			if err == io.EOF {
				l.final = last
				select {
				case l.q <- nil:
				case <-ctx.Done():
				}
				return
			}
			s.fail(err)
			return
		}
		s.touch()
		if !l.add(wire.FrameSize(n), s.lim.MaxBytes) {
			s.end(EndBytes)
			return
		}
		if l.bucket != nil {
			s.waiting.Add(1)
			err := l.bucket.WaitN(ctx, wire.FrameSize(n)+packetOverhead)
			s.waiting.Add(-1)
			if err != nil {
				return
			}
			s.touch()
		}
		last = bytes.Clone(buf[:n])
		select {
		case l.q <- last:
		case <-ctx.Done():
			return
		}
	}
}

// writePackets sends what from's client sent to to's client: as a datagram when to speaks version 1 and it fits, else
// as a frame. Frames queued within Flush of the last write leave in one write of at most BufferSize. When from's stream
// ends, its last packet, normally a CONNECTION_CLOSE, also goes as a frame before the end, so a full datagram queue
// cannot lose it.
func (s *session) writePackets(ctx context.Context, from, to *Leg) {
	var frames, dbuf []byte
	var last time.Time
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	var flushAt <-chan time.Time
	flush := func() bool {
		flushAt = nil
		if len(frames) == 0 {
			return true
		}
		to.stream.SetWriteDeadline(time.Now().Add(s.lim.Idle))
		if _, err := to.stream.Write(frames); err != nil {
			s.fail(err)
			return false
		}
		frames, last = frames[:0], time.Now()
		s.touch()
		return true
	}
	// The buffer is allocated at its full size, so appends never grow it past BufferSize.
	add := func(p []byte) bool {
		if len(frames)+wire.FrameSize(len(p)) > BufferSize && !flush() {
			return false
		}
		if frames == nil {
			frames = make([]byte, 0, BufferSize)
		}
		frames, _ = wire.AppendFrame(frames, p)
		return true
	}
	for {
		select {
		case p := <-from.q:
			if p == nil {
				if to.send != nil && from.final != nil && !add(from.final) {
					return
				}
				if flush() {
					to.stream.Close()
				}
				return
			}
			if to.send != nil {
				dbuf, _ = wire.AppendDatagram(dbuf[:0], to.id, p)
				if err := to.send(dbuf); err == nil || errors.Is(err, kolotransport.ErrDatagramDropped) {
					continue
				}
			}
			if !add(p) {
				return
			}
			if len(frames) >= BufferSize || !time.Now().Before(last.Add(s.lim.Flush)) {
				if !flush() {
					return
				}
			} else if flushAt == nil {
				timer.Reset(time.Until(last.Add(s.lim.Flush)))
				flushAt = timer.C
			}
		case <-flushAt:
			if !flush() {
				return
			}
		case <-from.over:
			s.end(EndBytes)
			return
		case <-ctx.Done():
			return
		}
	}
}

// watchIdle ends the session once nothing has passed either way for Idle, unless a bucket is making a packet wait.
func (s *session) watchIdle(ctx context.Context, done <-chan struct{}) {
	t := time.NewTimer(s.lim.Idle)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-ctx.Done():
			return
		case <-done:
			return
		}
		idle := s.idleFor()
		if idle >= s.lim.Idle && s.waiting.Load() == 0 {
			s.end(EndIdle)
			return
		}
		t.Reset(max(s.lim.Idle-idle, time.Millisecond))
	}
}
