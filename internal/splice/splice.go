// Package splice copies the bytes of a relay session between two streams, within its limits.
package splice

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Codes that end a session, sent as the stream error code on both streams.
const (
	Done        = 0
	EndDuration = 1
	EndBytes    = 2
	EndIdle     = 3
	EndPeer     = 4
	EndClosing  = 5
)

// BufferSize is the copy buffer per direction.
const BufferSize = 64 << 10

// Stream is the part of a kolotransport.Stream that Run uses.
type Stream interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
	CancelRead(code uint64) error
	CancelWrite(code uint64) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// Limits bound one session.
type Limits struct {
	MaxDuration time.Duration
	MaxBytes    int64
	Idle        time.Duration
	// Flush is the shortest time between two writes of less than a full buffer; 0 writes every read at once.
	Flush time.Duration
}

type session struct {
	lim     Limits
	last    atomic.Int64
	waiting atomic.Int32
	once    sync.Once
	code    uint64
	a, b    Stream
	stop    context.CancelFunc
}

// Run copies between a and b until both send sides end (Done) or a limit ends the session, which cancels both streams with the returned code.
// ra and rb, if not nil, pace the bytes read from a and from b.
func Run(ctx context.Context, a, b Stream, ra, rb *rate.Limiter, lim Limits) uint64 {
	// WaitN fails at once if a wait would pass its context's deadline, so the buckets wait on wctx, which has none; end cancels it.
	wctx, stopWait := context.WithCancel(ctx)
	defer stopWait()
	s := &session{lim: lim, a: a, b: b, stop: stopWait}
	s.touch()
	dctx, cancel := context.WithTimeout(ctx, lim.MaxDuration)
	defer cancel()
	stop := context.AfterFunc(dctx, func() {
		if ctx.Err() != nil {
			s.end(EndClosing)
		} else {
			s.end(EndDuration)
		}
	})
	defer stop()
	var wg sync.WaitGroup
	wg.Go(func() { s.copy(wctx, b, a, ra) })
	wg.Go(func() { s.copy(wctx, a, b, rb) })
	wg.Wait()
	s.once.Do(func() {})
	return s.code
}

func (s *session) touch() { s.last.Store(time.Now().UnixNano()) }

func (s *session) idleFor() time.Duration {
	return time.Duration(time.Now().UnixNano() - s.last.Load())
}

func (s *session) end(code uint64) {
	s.once.Do(func() {
		s.code = code
		s.stop()
		for _, st := range []Stream{s.a, s.b} {
			st.CancelRead(code)
			st.CancelWrite(code)
		}
	})
}

func (s *session) copy(ctx context.Context, dst, src Stream, lim *rate.Limiter) {
	size := BufferSize
	if lim != nil {
		size = min(size, lim.Burst())
	}
	buf := make([]byte, size)
	var sent int64
	var last time.Time
	for {
		src.SetReadDeadline(time.Now().Add(s.lim.Idle))
		n, err := src.Read(buf)
		if n > 0 && err == nil {
			n, err = s.gather(src, buf, n, last)
		}
		if n > 0 {
			s.touch()
			over := int64(n) > s.lim.MaxBytes-sent
			if over {
				n = int(s.lim.MaxBytes - sent)
			}
			if n > 0 {
				if lim != nil {
					s.waiting.Add(1)
					err := lim.WaitN(ctx, n)
					s.waiting.Add(-1)
					if err != nil {
						return
					}
					s.touch()
				}
				dst.SetWriteDeadline(time.Now().Add(s.lim.Idle))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					s.fail(werr)
					return
				}
				last = time.Now()
				sent += int64(n)
				s.touch()
			}
			if over {
				s.end(EndBytes)
				return
			}
		}
		switch {
		case err == nil:
		case err == io.EOF:
			dst.Close()
			return
		case errors.Is(err, os.ErrDeadlineExceeded) && (s.idleFor() < s.lim.Idle || s.waiting.Load() > 0):
		default:
			s.fail(err)
			return
		}
	}
}

// gather reads until buf is full or Flush has passed since the last write, so small chunks leave in one write and quic-go keeps fewer packets.
func (s *session) gather(src Stream, buf []byte, n int, last time.Time) (int, error) {
	until := last.Add(s.lim.Flush)
	for n < len(buf) && time.Now().Before(until) {
		src.SetReadDeadline(until)
		m, err := src.Read(buf[n:])
		n += m
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func (s *session) fail(err error) {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		s.end(EndIdle)
		return
	}
	s.end(EndPeer)
}
