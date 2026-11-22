package splice

import (
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// codeErr is a stream reset or stop with its code, as kolotransport.Error would carry.
type codeErr struct {
	code   uint64
	remote bool
}

func (e *codeErr) Error() string { return "stream canceled, code " + strconv.FormatUint(e.code, 10) }

var errWriteClosed = errors.New("write on closed stream")

// half is one direction of an in-memory stream with a bounded buffer.
type half struct {
	mu      sync.Mutex
	wake    chan struct{}
	buf     []byte
	max     int
	closed  bool
	reset   *codeErr
	stopped *codeErr
	rdl     time.Time
	wdl     time.Time
	writes  int
	largest int
}

func (h *half) notify() {
	close(h.wake)
	h.wake = make(chan struct{})
}

// wait unlocks h until it changes or the deadline passes, then locks it again.
func (h *half) wait(dl time.Time) {
	wake := h.wake
	h.mu.Unlock()
	defer h.mu.Lock()
	if dl.IsZero() {
		<-wake
		return
	}
	t := time.NewTimer(time.Until(dl))
	defer t.Stop()
	select {
	case <-wake:
	case <-t.C:
	}
}

func expired(dl time.Time) bool { return !dl.IsZero() && !time.Now().Before(dl) }

// memStream is a test double for kolotransport.Stream: half-close, resets, stops, deadlines, flow control.
type memStream struct {
	in, out *half
}

func streamPair(max int) (*memStream, *memStream) {
	ab := &half{wake: make(chan struct{}), max: max}
	ba := &half{wake: make(chan struct{}), max: max}
	return &memStream{in: ba, out: ab}, &memStream{in: ab, out: ba}
}

func (s *memStream) Read(p []byte) (int, error) {
	h := s.in
	h.mu.Lock()
	defer h.mu.Unlock()
	for {
		switch {
		case h.stopped != nil:
			return 0, &codeErr{code: h.stopped.code}
		case h.reset != nil:
			return 0, &codeErr{code: h.reset.code, remote: true}
		case len(h.buf) > 0:
			n := copy(p, h.buf)
			h.buf = h.buf[n:]
			h.notify()
			return n, nil
		case h.closed:
			return 0, io.EOF
		case expired(h.rdl):
			return 0, os.ErrDeadlineExceeded
		}
		h.wait(h.rdl)
	}
}

func (s *memStream) Write(p []byte) (int, error) {
	h := s.out
	h.mu.Lock()
	defer h.mu.Unlock()
	h.writes++
	h.largest = max(h.largest, len(p))
	total := 0
	for len(p) > 0 {
		switch {
		case h.stopped != nil:
			return total, &codeErr{code: h.stopped.code, remote: true}
		case h.reset != nil:
			return total, &codeErr{code: h.reset.code}
		case h.closed:
			return total, errWriteClosed
		case expired(h.wdl):
			return total, os.ErrDeadlineExceeded
		}
		if space := h.max - len(h.buf); space > 0 {
			n := min(space, len(p))
			h.buf = append(h.buf, p[:n]...)
			p = p[n:]
			total += n
			h.notify()
			continue
		}
		h.wait(h.wdl)
	}
	return total, nil
}

// writesIn returns how many Write calls fed the data s reads.
func (s *memStream) writesIn() int {
	s.in.mu.Lock()
	defer s.in.mu.Unlock()
	return s.in.writes
}

// largestWriteIn returns the size of the largest Write that fed the data s reads.
func (s *memStream) largestWriteIn() int {
	s.in.mu.Lock()
	defer s.in.mu.Unlock()
	return s.in.largest
}

func (s *memStream) Close() error {
	s.out.mu.Lock()
	defer s.out.mu.Unlock()
	s.out.closed = true
	s.out.notify()
	return nil
}

func (s *memStream) CancelRead(code uint64) error {
	s.in.mu.Lock()
	defer s.in.mu.Unlock()
	if s.in.stopped == nil {
		s.in.stopped = &codeErr{code: code}
	}
	s.in.buf = nil
	s.in.notify()
	return nil
}

func (s *memStream) CancelWrite(code uint64) error {
	s.out.mu.Lock()
	defer s.out.mu.Unlock()
	if s.out.reset == nil && !s.out.closed {
		s.out.reset = &codeErr{code: code}
		s.out.buf = nil
	}
	s.out.notify()
	return nil
}

func (s *memStream) SetReadDeadline(t time.Time) error {
	s.in.mu.Lock()
	defer s.in.mu.Unlock()
	s.in.rdl = t
	s.in.notify()
	return nil
}

func (s *memStream) SetWriteDeadline(t time.Time) error {
	s.out.mu.Lock()
	defer s.out.mu.Unlock()
	s.out.wdl = t
	s.out.notify()
	return nil
}

// checkGoroutines fails the test if goroutines started during it outlive its cleanups.
func checkGoroutines(t *testing.T) {
	t.Helper()
	before := goroutines()
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for {
			var leaked []string
			for id, stack := range goroutines() {
				if _, ok := before[id]; !ok {
					leaked = append(leaked, stack)
				}
			}
			if len(leaked) == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("%d goroutines leaked:\n%s", len(leaked), strings.Join(leaked, "\n\n"))
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

func goroutines() map[string]string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	out := make(map[string]string)
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if id, _, ok := strings.Cut(strings.TrimPrefix(stack, "goroutine "), " "); ok {
			out[id] = stack
		}
	}
	return out
}
