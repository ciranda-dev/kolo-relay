package kolorelay

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	"github.com/ciranda-dev/kolo-relay/internal/limits"
	"github.com/ciranda-dev/kolo-relay/internal/splice"
	"github.com/ciranda-dev/kolo-relay/internal/wire"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
	"golang.org/x/time/rate"
)

// Server is a relay: peers reserve on it, and it joins other peers to them, copying bytes it cannot read.
type Server struct {
	sl     *kolosecure.Listener
	cfg    ServerConfig
	table  *limits.Table[*reservation]
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
	err    error

	// Accepting stops first, then sessions stop before connections close, so their streams carry code 5 (relay closing).
	acceptCtx    context.Context
	acceptCancel context.CancelFunc
	sessCtx      context.Context
	sessCancel   context.CancelFunc
	sessMu       sync.Mutex
	closing      bool
	sessions     sync.WaitGroup

	// hook lets tests stop the relay at a named point.
	hook atomic.Pointer[func(point string)]
}

func (s *Server) at(point string) {
	if h := s.hook.Load(); h != nil {
		(*h)(point)
	}
}

// Listen starts a relay on addr, such as "127.0.0.1:0", authenticated as id. Clients must know id's public key.
func Listen(ctx context.Context, addr string, id *koloid.Identity, cfg *ServerConfig) (*Server, error) {
	c, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	if id.PublicKey() == nil {
		return nil, errInvalidIdentity
	}
	if err := checkAddr("listen address", addr); err != nil {
		return nil, err
	}
	sl, err := kolosecure.Listen(ctx, addr, id, c.Secure)
	if err != nil {
		return nil, err
	}
	sctx, cancel := context.WithCancel(context.Background())
	sess, sessCancel := context.WithCancel(context.Background())
	acc, accCancel := context.WithCancel(context.Background())
	s := &Server{sl: sl, cfg: c, table: limits.New[*reservation](c.tableConfig()), ctx: sctx, cancel: cancel,
		acceptCtx: acc, acceptCancel: accCancel, sessCtx: sess, sessCancel: sessCancel}
	s.wg.Go(s.loop)
	if c.AllowReserve == nil {
		log := c.Logger
		if log == nil {
			log = slog.Default()
		}
		log.Warn("kolorelay: open relay: every key may reserve and hold sessions; set ServerConfig.AllowReserve before exposing it",
			"addr", s.Addr().String(), "max_reservations", c.MaxReservations, "max_sessions", c.MaxSessions)
	}
	return s, nil
}

// Addr returns the relay's local UDP address.
func (s *Server) Addr() net.Addr { return s.sl.Addr() }

// Close ends every session and reservation, closes every connection and waits for them. It is safe to call more than once.
func (s *Server) Close() error {
	s.once.Do(func() {
		s.acceptCancel()
		s.sessCancel()
		s.sessMu.Lock()
		s.closing = true
		s.sessMu.Unlock()
		s.sessions.Wait()
		s.at("close-conns")
		s.cancel()
		s.wg.Wait()
		s.err = s.sl.Close()
	})
	return s.err
}

func (s *Server) loop() {
	for {
		c, err := s.sl.Accept(s.acceptCtx)
		if err != nil {
			return
		}
		s.wg.Go(func() { s.serve(c) })
	}
}

func (s *Server) serve(c *kolosecure.Conn) { s.serveAs(c, c.RemotePublicKey()) }

// serveAs serves c, whose proved key is remote; a key that is not 32 bytes would make every such client one identity, so it ends the connection.
func (s *Server) serveAs(c *kolosecure.Conn, remote []byte) {
	stop := context.AfterFunc(s.ctx, func() { c.CloseWithError(codeClosing, "") })
	defer stop()
	defer func() {
		// A client whose request Close cut short learns that the relay closed, not a plain close.
		if s.sessCtx.Err() != nil {
			c.CloseWithError(codeClosing, "")
			return
		}
		c.Close()
	}()
	// Unread data on a unidirectional stream would stay in relay memory.
	s.wg.Go(func() {
		if _, err := c.AcceptUniStream(c.Context()); err == nil {
			c.CloseWithError(codeProtocol, "")
		}
	})
	key, ok := limits.KeyOf(remote)
	if !ok {
		c.CloseWithError(codeProtocol, "")
		return
	}
	st, m, ok := s.first(c)
	if !ok {
		return
	}
	s.wg.Go(func() {
		if _, err := c.AcceptStream(c.Context()); err == nil {
			c.CloseWithError(codeProtocol, "")
		}
	})
	switch m.Type {
	case wire.TypeReserve:
		s.reserve(c, st, key)
	case wire.TypeConnect:
		s.connect(c, st, key, m.Key)
	default:
		c.CloseWithError(codeProtocol, "")
	}
}

// first reads the client's one control message, within ControlTimeout.
func (s *Server) first(c *kolosecure.Conn) (*kolotransport.Stream, wire.Message, bool) {
	dl := time.Now().Add(s.cfg.ControlTimeout)
	ctx, cancel := context.WithDeadline(c.Context(), dl)
	defer cancel()
	st, err := c.AcceptStream(ctx)
	if err != nil {
		c.CloseWithError(codeProtocol, "")
		return nil, wire.Message{}, false
	}
	st.SetReadDeadline(dl)
	body, err := wire.ReadMessage(st)
	if err != nil {
		c.CloseWithError(codeProtocol, "")
		return nil, wire.Message{}, false
	}
	m, err := wire.Decode(body)
	switch {
	case errors.Is(err, wire.ErrUnsupportedVersion):
		s.refuse(c, st, wire.StatusUnsupportedVersion)
		return nil, wire.Message{}, false
	case err != nil:
		c.CloseWithError(codeProtocol, "")
		return nil, wire.Message{}, false
	}
	st.SetReadDeadline(time.Time{})
	return st, m, true
}

// refuse sends a status, stops reading and gives the client up to ControlTimeout to close the connection.
func (s *Server) refuse(c *kolosecure.Conn, st *kolotransport.Stream, code uint64) {
	s.at("refuse")
	if s.writeStatus(st, code) != nil {
		return
	}
	st.Close()
	st.CancelRead(code)
	t := time.NewTimer(s.cfg.ControlTimeout)
	defer t.Stop()
	select {
	case <-c.Context().Done():
	case <-s.sessCtx.Done():
	case <-t.C:
	}
}

func (s *Server) accept(c *kolosecure.Conn, st *kolotransport.Stream) bool {
	if s.writeStatus(st, wire.StatusOK) != nil {
		return false
	}
	st.SetWriteDeadline(time.Time{})
	return true
}

// writeStatus writes a status within ControlTimeout, or gives up when Close stops the sessions.
func (s *Server) writeStatus(st *kolotransport.Stream, code uint64) error {
	st.SetWriteDeadline(time.Now().Add(s.cfg.ControlTimeout))
	stop := context.AfterFunc(s.sessCtx, func() { st.SetWriteDeadline(time.Now()) })
	err := wire.WriteMessage(st, wire.EncodeStatus(code))
	if !stop() {
		st.CancelWrite(splice.EndClosing)
		st.CancelRead(splice.EndClosing)
		return context.Canceled
	}
	return err
}

func (s *Server) reserve(c *kolosecure.Conn, st *kolotransport.Stream, key limits.Key) {
	if f := s.cfg.AllowReserve; f != nil && !guard(func() bool { return f(bytes.Clone(key[:])) }) {
		s.refuse(c, st, wire.StatusNotAllowed)
		return
	}
	r := &reservation{conn: c, bucket: limits.Bucket(s.cfg.RateBytes, s.cfg.RateBurst), endc: make(chan uint64, 1), idle: make(chan struct{})}
	prev, replaced, err := s.table.Reserve(key, r)
	if err != nil {
		s.refuse(c, st, wire.StatusLimit)
		return
	}
	defer s.table.Unreserve(key, r)
	if replaced {
		prev.end(codeReplaced)
	}
	s.at("reserve-accept")
	if !s.accept(c, st) {
		return
	}
	ctl := make(chan struct{})
	s.wg.Go(func() {
		defer close(ctl)
		st.Read(make([]byte, 1))
	})
	t := time.NewTimer(s.cfg.ReservationLifetime)
	defer t.Stop()
	var code uint64
	select {
	case <-t.C:
		code = codeLifetime
	case code = <-r.endc:
	case <-ctl:
		c.CloseWithError(codeProtocol, "")
		return
	case <-c.Context().Done():
		return
	}
	// The reservation ends here, but sessions already open on this connection go on.
	r.stop()
	s.table.Unreserve(key, r)
	st.CancelWrite(code)
	st.CancelRead(code)
	select {
	case <-r.idle:
	case <-c.Context().Done():
		return
	}
	// Let the client read the code and close the connection itself.
	wait := time.NewTimer(s.cfg.ControlTimeout)
	defer wait.Stop()
	select {
	case <-c.Context().Done():
	case <-wait.C:
	}
}

func (s *Server) connect(c *kolosecure.Conn, st *kolotransport.Stream, from limits.Key, target []byte) {
	s.at("connect")
	s.sessMu.Lock()
	if s.closing {
		s.sessMu.Unlock()
		return
	}
	s.sessions.Add(1)
	s.sessMu.Unlock()
	defer s.sessions.Done()
	to, ok := limits.KeyOf(target)
	if !ok {
		c.CloseWithError(codeProtocol, "")
		return
	}
	if to == from {
		s.refuse(c, st, wire.StatusUnavailable)
		return
	}
	// session has released its slot before refuse waits for the client.
	if code, ran := s.session(c, st, from, to); !ran {
		s.refuse(c, st, code)
	}
}

// session holds a slot from OpenSession to the end of the splice; if the session did not start, it returns the status to refuse with.
func (s *Server) session(c *kolosecure.Conn, st *kolotransport.Stream, from, to limits.Key) (code uint64, ran bool) {
	// The limits come first, so a peer at its limit learns nothing about AllowConnect or a reservation.
	if s.table.AtLimit(from) != nil {
		return wire.StatusLimit, false
	}
	// AllowConnect runs with no slot held, so a slow or refusing call cannot keep one.
	if f := s.cfg.AllowConnect; f != nil && !guard(func() bool { return f(bytes.Clone(from[:]), bytes.Clone(to[:])) }) {
		// The limits may have filled during the call; a denied key gets the answer an allowed one would.
		if s.table.AtLimit(from) != nil {
			return wire.StatusLimit, false
		}
		return wire.StatusUnavailable, false
	}
	// A full target answers Unavailable, so ErrLimit says nothing about whether to has a reservation.
	release, err := s.table.OpenSession(from, to)
	switch {
	case errors.Is(err, limits.ErrTargetLimit):
		return wire.StatusUnavailable, false
	case err != nil:
		return wire.StatusLimit, false
	}
	defer release()
	r, ok := s.table.Lookup(to)
	if !ok || !r.addSession() {
		return wire.StatusUnavailable, false
	}
	defer r.doneSession()
	ts := s.announce(r, from)
	if ts == nil {
		return wire.StatusUnavailable, false
	}
	s.at("session-accept")
	if !s.accept(c, st) {
		code := uint64(splice.EndPeer)
		if s.sessCtx.Err() != nil {
			code = splice.EndClosing
		}
		ts.CancelWrite(code)
		ts.CancelRead(code)
		return 0, true
	}
	splice.Run(s.sessCtx, st, ts, limits.Bucket(s.cfg.RateBytes, s.cfg.RateBurst), r.bucket, s.cfg.spliceLimits())
	// Let the client read the session's end code and close the connection itself.
	t := time.NewTimer(endGrace)
	defer t.Stop()
	select {
	case <-c.Context().Done():
	case <-t.C:
	}
	return 0, true
}

// announce opens a stream to the target, sends Incoming and waits for its OK, within ConnectTimeout.
func (s *Server) announce(r *reservation, from limits.Key) *kolotransport.Stream {
	dl := time.Now().Add(s.cfg.ConnectTimeout)
	ctx, cancel := context.WithDeadline(r.conn.Context(), dl)
	defer cancel()
	stop := context.AfterFunc(s.sessCtx, cancel)
	defer stop()
	ts, err := r.conn.OpenStream(ctx)
	if err != nil {
		return nil
	}
	stopTS := context.AfterFunc(s.sessCtx, func() {
		ts.CancelWrite(splice.EndClosing)
		ts.CancelRead(splice.EndClosing)
	})
	defer stopTS()
	ts.SetDeadline(dl)
	ok := wire.WriteMessage(ts, wire.EncodeIncoming(from[:])) == nil
	if ok {
		body, err := wire.ReadMessage(ts)
		m, derr := wire.Decode(body)
		ok = err == nil && derr == nil && m.Type == wire.TypeStatus && m.Code == wire.StatusOK
	}
	if !ok {
		ts.CancelWrite(codeProtocol)
		ts.CancelRead(codeProtocol)
		return nil
	}
	ts.SetDeadline(time.Time{})
	return ts
}

// reservation is one reserved key on the relay, held by one client connection.
type reservation struct {
	conn   *kolosecure.Conn
	bucket *rate.Limiter
	endc   chan uint64

	mu       sync.Mutex
	stopped  bool
	sessions int
	idle     chan struct{}
}

func (r *reservation) end(code uint64) {
	select {
	case r.endc <- code:
	default:
	}
}

func (r *reservation) addSession() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return false
	}
	r.sessions++
	return true
}

func (r *reservation) doneSession() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions--
	if r.stopped && r.sessions == 0 {
		close(r.idle)
	}
}

func (r *reservation) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = true
	if r.sessions == 0 {
		close(r.idle)
	}
}
