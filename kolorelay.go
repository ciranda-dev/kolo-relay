package kolorelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	"github.com/ciranda-dev/kolo-relay/internal/pconn"
	"github.com/ciranda-dev/kolo-relay/internal/wire"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// endGrace is how long a Conn whose relay stream ended waits for quic-go to handle the last packets.
const endGrace = time.Second

var (
	errInvalidIdentity = fmt.Errorf("%w: nil or zero identity", ErrInvalidArgument)
	errNoAnswer        = fmt.Errorf("kolorelay: no answer from the relay within ControlTimeout: %w", os.ErrDeadlineExceeded)
)

// relayAddrs returns the relay's address and ours on rc, which kolo-transport reports as UDP addresses, as plain IPv4.
func relayAddrs(rc *kolosecure.Conn) (remote, local *net.UDPAddr, err error) {
	ra, ok1 := rc.RemoteAddr().(*net.UDPAddr)
	la, ok2 := rc.LocalAddr().(*net.UDPAddr)
	if !ok1 || !ok2 {
		return nil, nil, fmt.Errorf("%w: relay connection without UDP addresses", ErrProtocol)
	}
	remote, ok1 = plainIPv4(ra)
	local, ok2 = plainIPv4(la)
	if !ok1 || !ok2 {
		return nil, nil, fmt.Errorf("%w: relay connection without IPv4 addresses", ErrProtocol)
	}
	return remote, local, nil
}

// plainIPv4 returns a 4-byte copy of a, an address the OS reported (possibly v4-mapped), or false if a is not IPv4.
func plainIPv4(a *net.UDPAddr) (*net.UDPAddr, bool) {
	ap := a.AddrPort()
	ip := ap.Addr().Unmap()
	if !ip.Is4() {
		return nil, false
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, ap.Port())), true
}

// checkAddr refuses a caller's addr whose host is an IP literal other than plain IPv4, v4-mapped included, before anything is sent.
func checkAddr(name, addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	if ip, err := netip.ParseAddr(host); err == nil && !ip.Is4() {
		return fmt.Errorf("%w: %s %q is IPv6, which is refused", ErrInvalidArgument, name, addr)
	}
	return nil
}

// cloneUDP copies a, so no caller and no session shares quic-go's address.
func cloneUDP(a *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: slices.Clone(a.IP), Port: a.Port, Zone: a.Zone}
}

func checkKey(name string, k ed25519.PublicKey) error {
	if len(k) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: %s must be %d bytes", ErrInvalidArgument, name, ed25519.PublicKeySize)
	}
	return nil
}

// control opens the control stream on rc, sends msg and waits for the relay's status, within timeout.
func control(ctx context.Context, rc *kolosecure.Conn, msg []byte, timeout time.Duration) (*kolotransport.Stream, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	st, err := rc.OpenStream(cctx)
	if err != nil {
		return nil, ctxErr(ctx, cctx, err)
	}
	stop := context.AfterFunc(cctx, func() { st.SetDeadline(time.Now()) })
	err = wire.WriteMessage(st, msg)
	var body []byte
	if err == nil {
		body, err = wire.ReadMessage(st)
	}
	if !stop() {
		return nil, ctxErr(ctx, cctx, os.ErrDeadlineExceeded)
	}
	if err != nil {
		return nil, ctxErr(ctx, cctx, err)
	}
	m, err := wire.Decode(body)
	if err != nil {
		return nil, err
	}
	if m.Type != wire.TypeStatus {
		return nil, ErrProtocol
	}
	switch m.Code {
	case wire.StatusOK:
		return st, nil
	case wire.StatusUnavailable:
		return nil, ErrUnavailable
	case wire.StatusNotAllowed:
		return nil, ErrNotAllowed
	case wire.StatusLimit:
		return nil, ErrLimit
	}
	return nil, ErrUnsupportedVersion
}

func ctxErr(ctx, cctx context.Context, err error) error {
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case cctx.Err() != nil:
		return errNoAnswer
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return errNoAnswer
	}
	return err
}

// endWith returns a context that is also canceled when pc's stream ends, so a handshake does not wait for a session the relay ended.
// It waits endGrace first, so packets that arrived before the end, such as a proof, are still handled.
func endWith(ctx context.Context, pc *pconn.Conn) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-pc.Done():
		case <-ctx.Done():
			return
		}
		t := time.NewTimer(endGrace)
		defer t.Stop()
		select {
		case <-t.C:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// dialErr reports the end of the relay session instead of the handshake cancellation it caused.
// Any other error, such as a failed proof, and a caller's own cancellation are returned as they are.
func dialErr(ctx, hctx context.Context, end, err error) error {
	if ctx.Err() == nil && hctx.Err() != nil && end != nil && errors.Is(err, context.Canceled) {
		return fmt.Errorf("%w: the session ended during the handshake: %w", ErrUnavailable, end)
	}
	return err
}

// Dial connects to target through the relay at relayAddr, whose key is relayKey, and returns once target has proved its key end to end.
// The relay must hold a reservation for target. Nothing is tried directly: the connection always goes through the relay.
func Dial(ctx context.Context, relayAddr string, relayKey ed25519.PublicKey, id *koloid.Identity, target ed25519.PublicKey, cfg *Config) (*Conn, error) {
	c, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	local := id.PublicKey()
	if local == nil {
		return nil, errInvalidIdentity
	}
	if err := checkKey("relay key", relayKey); err != nil {
		return nil, err
	}
	if err := checkKey("target key", target); err != nil {
		return nil, err
	}
	if bytes.Equal(target, local) || bytes.Equal(target, relayKey) {
		return nil, fmt.Errorf("%w: target key is the local key or the relay's key", ErrInvalidArgument)
	}
	if err := checkAddr("relay address", relayAddr); err != nil {
		return nil, err
	}
	rc, err := kolosecure.Dial(ctx, relayAddr, id, relayKey, c.Relay)
	if err != nil {
		return nil, err
	}
	conn, err := dialThrough(ctx, rc, id, bytes.Clone(relayKey), bytes.Clone(target), c)
	if err != nil {
		rc.Close()
		return nil, err
	}
	return conn, nil
}

func dialThrough(ctx context.Context, rc *kolosecure.Conn, id *koloid.Identity, relayKey, target ed25519.PublicKey, c Config) (*Conn, error) {
	relay, local, err := relayAddrs(rc)
	if err != nil {
		return nil, err
	}
	st, err := control(ctx, rc, wire.EncodeConnect(target), c.ControlTimeout)
	if err != nil {
		return nil, err
	}
	pc := pconn.New(st, cloneUDP(local), cloneUDP(relay), c.SendQueue)
	hctx, cancel := endWith(ctx, pc)
	defer cancel()
	// When the relay or the target ends the stream, the handshake fails with hctx's error; report the session's end instead.
	fail := func(err error) (*Conn, error) {
		return nil, dialErr(ctx, hctx, pc.Err(), err)
	}
	tcfg, scfg := c.inner(false)
	tl, err := kolotransport.ListenConn(hctx, pc, tcfg)
	if err != nil {
		return fail(err)
	}
	sl, err := kolosecure.NewListener(tl, id, scfg)
	if err != nil {
		return fail(err)
	}
	ic, err := sl.Dial(hctx, relay.AddrPort(), target)
	if err != nil {
		conn, err := fail(err)
		sl.Close()
		return conn, err
	}
	return newConn(ic, sl, pc, rc, relayKey, relay, nil), nil
}

// Reservation makes this peer reachable through one relay and receives the connections other peers make to it there.
type Reservation struct {
	rc        *kolosecure.Conn
	ctl       *kolotransport.Stream
	id        *koloid.Identity
	cfg       Config
	relayKey  ed25519.PublicKey
	relay     *net.UDPAddr
	local     *net.UDPAddr
	slots     chan struct{}
	ready     chan *Conn
	ended     chan struct{}
	endErr    error
	closed    chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once

	mu      sync.Mutex
	active  int
	over    bool
	closing bool
	conns   map[*Conn]struct{}
}

// Reserve asks the relay at relayAddr, whose key is relayKey, to make id reachable there until the relay ends the reservation or Close.
func Reserve(ctx context.Context, relayAddr string, relayKey ed25519.PublicKey, id *koloid.Identity, cfg *Config) (*Reservation, error) {
	c, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	if id.PublicKey() == nil {
		return nil, errInvalidIdentity
	}
	if err := checkKey("relay key", relayKey); err != nil {
		return nil, err
	}
	if err := checkAddr("relay address", relayAddr); err != nil {
		return nil, err
	}
	rc, err := kolosecure.Dial(ctx, relayAddr, id, relayKey, c.Relay)
	if err != nil {
		return nil, err
	}
	relay, local, err := relayAddrs(rc)
	if err == nil {
		var st *kolotransport.Stream
		if st, err = control(ctx, rc, wire.EncodeReserve(), c.ControlTimeout); err == nil {
			return newReservation(rc, st, id, c, bytes.Clone(relayKey), relay, local), nil
		}
	}
	rc.Close()
	return nil, err
}

func newReservation(rc *kolosecure.Conn, st *kolotransport.Stream, id *koloid.Identity, c Config, relayKey ed25519.PublicKey, relay, local *net.UDPAddr) *Reservation {
	ctx, cancel := context.WithCancel(context.Background())
	r := &Reservation{
		rc: rc, ctl: st, id: id, cfg: c, relayKey: relayKey, relay: relay, local: local,
		slots:  make(chan struct{}, c.MaxPending),
		ready:  make(chan *Conn),
		ended:  make(chan struct{}),
		closed: make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
		conns:  make(map[*Conn]struct{}),
	}
	r.wg.Go(r.watch)
	r.wg.Go(r.loop)
	return r
}

// watch ends the reservation when the relay resets the control stream or the connection is lost.
func (r *Reservation) watch() {
	_, err := r.ctl.Read(make([]byte, 1))
	if err == nil {
		err = ErrProtocol
	}
	r.endErr = fmt.Errorf("%w: %w", ErrReservationEnded, err)
	close(r.ended)
	r.cancel()
	r.mu.Lock()
	r.over = true
	idle := r.active == 0
	r.mu.Unlock()
	if idle {
		r.rc.Close()
	}
}

func (r *Reservation) loop() {
	for {
		ts, err := r.rc.AcceptStream(r.ctx)
		if err != nil {
			return
		}
		select {
		case r.slots <- struct{}{}:
			r.wg.Go(func() {
				defer func() { <-r.slots }()
				r.serve(ts)
			})
		default:
			ts.CancelWrite(codeProtocol)
			ts.CancelRead(codeProtocol)
		}
	}
}

func (r *Reservation) addActive() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.over {
		return false
	}
	r.active++
	return true
}

func (r *Reservation) doneActive() {
	r.mu.Lock()
	r.active--
	idle := r.over && r.active == 0
	r.mu.Unlock()
	if idle {
		r.rc.Close()
	}
}

// serve answers one Incoming from the relay and runs the target side of the end-to-end handshake.
func (r *Reservation) serve(ts *kolotransport.Stream) {
	ts.SetDeadline(time.Now().Add(r.cfg.ControlTimeout))
	body, err := wire.ReadMessage(ts)
	var m wire.Message
	if err == nil {
		m, err = wire.Decode(body)
	}
	if err != nil || m.Type != wire.TypeIncoming {
		ts.CancelWrite(codeProtocol)
		ts.CancelRead(codeProtocol)
		return
	}
	initiator := ed25519.PublicKey(m.Key)
	if f := r.cfg.AllowFunc; (f != nil && !guard(func() bool { return f(bytes.Clone(initiator)) })) || !r.addActive() {
		wire.WriteMessage(ts, wire.EncodeStatus(wire.StatusUnavailable))
		ts.Close()
		ts.CancelRead(0)
		return
	}
	handed := false
	defer func() {
		if !handed {
			r.doneActive()
		}
	}()
	if wire.WriteMessage(ts, wire.EncodeStatus(wire.StatusOK)) != nil {
		ts.CancelRead(codeProtocol)
		return
	}
	ts.SetDeadline(time.Time{})
	conn := r.handshake(ts, initiator)
	if conn == nil {
		return
	}
	handed = true
	select {
	case <-r.closed:
		conn.Close()
		return
	default:
	}
	select {
	case r.ready <- conn:
	case <-conn.ic.Context().Done():
		conn.Close()
	case <-r.closed:
		conn.Close()
	}
}

func (r *Reservation) handshake(ts *kolotransport.Stream, initiator ed25519.PublicKey) *Conn {
	ctx, cancel := context.WithTimeout(r.ctx, r.cfg.innerWait())
	defer cancel()
	pc := pconn.New(ts, cloneUDP(r.local), cloneUDP(r.relay), r.cfg.SendQueue)
	ctx, cancel2 := endWith(ctx, pc)
	defer cancel2()
	tcfg, scfg := r.cfg.inner(true)
	tl, err := kolotransport.ListenConn(ctx, pc, tcfg)
	if err != nil {
		return nil
	}
	sl, err := kolosecure.NewListener(tl, r.id, scfg)
	if err != nil {
		return nil
	}
	ic, err := sl.Accept(ctx)
	if err != nil {
		sl.Close()
		return nil
	}
	// The relay named the initiator; only the end-to-end proof counts.
	if !bytes.Equal(ic.RemotePublicKey(), initiator) {
		ic.CloseWithError(codeUnexpectedPeer, "")
		sl.Close()
		return nil
	}
	return r.adopt(func() *Conn { return newConn(ic, sl, pc, nil, r.relayKey, cloneUDP(r.relay), r.release) }, func() {
		ic.Close()
		sl.Close()
	})
}

// adopt registers the Conn that newc returns, or calls drop if the reservation is closing.
// drop runs without r.mu, since closing a connection can take seconds and other Conns release through r.mu.
func (r *Reservation) adopt(newc func() *Conn, drop func()) *Conn {
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		drop()
		return nil
	}
	defer r.mu.Unlock()
	conn := newc()
	r.conns[conn] = struct{}{}
	return conn
}

// release forgets a closed Conn of the reservation.
func (r *Reservation) release(c *Conn) {
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
	r.doneActive()
}

// Accept waits for the next peer that connected through the relay and proved its key end to end.
// After the relay ends the reservation it returns an error wrapping ErrReservationEnded; connections already returned keep working.
func (r *Reservation) Accept(ctx context.Context) (*Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case c := <-r.ready:
		return c, nil
	case <-r.closed:
		return nil, ErrClosed
	default:
	}
	select {
	case c := <-r.ready:
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.closed:
		return nil, ErrClosed
	case <-r.ended:
		return nil, r.endErr
	}
}

// Close ends the reservation and closes its connection to the relay, with every connection Accept returned. It is safe to call more than once.
func (r *Reservation) Close() error {
	r.closeOnce.Do(func() {
		close(r.closed)
		r.cancel()
		r.mu.Lock()
		r.closing = true
		conns := slices.Collect(maps.Keys(r.conns))
		r.mu.Unlock()
		// The Conns close first, while the relay connection still carries their close code to the peers.
		var wg sync.WaitGroup
		for _, c := range conns {
			wg.Go(func() { c.Close() })
		}
		wg.Wait()
		r.rc.Close()
		r.wg.Wait()
	})
	return nil
}

// Conn is a connection to a peer through a relay; the peer proved RemotePublicKey end to end, and the relay only sees ciphertext.
type Conn struct {
	ic        *kolosecure.Conn
	sl        *kolosecure.Listener
	pc        *pconn.Conn
	rc        *kolosecure.Conn
	relayKey  ed25519.PublicKey
	relayAddr *net.UDPAddr
	release   func(*Conn)
	stop      chan struct{}
	stopOnce  sync.Once
	downOnce  sync.Once
	wg        sync.WaitGroup
}

func newConn(ic *kolosecure.Conn, sl *kolosecure.Listener, pc *pconn.Conn, rc *kolosecure.Conn, relayKey ed25519.PublicKey, relayAddr *net.UDPAddr, release func(*Conn)) *Conn {
	c := &Conn{ic: ic, sl: sl, pc: pc, rc: rc, relayKey: relayKey, relayAddr: relayAddr, release: release, stop: make(chan struct{})}
	c.wg.Go(func() {
		select {
		case <-ic.Context().Done():
		case <-c.stop:
		case <-pc.Done():
			// Give quic-go time to handle the last packets, such as the peer's close.
			t := time.NewTimer(endGrace)
			select {
			case <-ic.Context().Done():
			case <-c.stop:
			case <-t.C:
			}
			t.Stop()
		}
		c.shutdown()
	})
	return c
}

func (c *Conn) shutdown() {
	c.downOnce.Do(func() {
		c.sl.Close()
		// kolo-transport cancels the context right after the connection ends; Close returns only after that.
		<-c.ic.Context().Done()
		if c.rc != nil {
			c.rc.Close()
		}
		if c.release != nil {
			c.release(c)
		}
	})
}

// RemotePublicKey returns a copy of the peer's kolo-id public key, proved end to end.
func (c *Conn) RemotePublicKey() ed25519.PublicKey { return c.ic.RemotePublicKey() }

// Stats returns the transport statistics of the end-to-end connection, which crosses the relay: its round trip time is
// the whole path. It is the zero value after the connection has ended.
func (c *Conn) Stats() kolotransport.ConnStats { return c.ic.Stats() }

// RelayPublicKey returns a copy of the key of the relay this connection goes through.
func (c *Conn) RelayPublicKey() ed25519.PublicKey { return bytes.Clone(c.relayKey) }

// RelayAddr returns the UDP address of the relay this connection goes through.
func (c *Conn) RelayAddr() net.Addr { return cloneUDP(c.relayAddr) }

// OpenStream opens a bidirectional stream, as kolosecure.Conn.OpenStream.
func (c *Conn) OpenStream(ctx context.Context) (*kolotransport.Stream, error) {
	return c.ic.OpenStream(ctx)
}

// AcceptStream waits for the next bidirectional stream opened by the peer.
func (c *Conn) AcceptStream(ctx context.Context) (*kolotransport.Stream, error) {
	return c.ic.AcceptStream(ctx)
}

// OpenUniStream opens a unidirectional stream, as kolosecure.Conn.OpenUniStream.
func (c *Conn) OpenUniStream(ctx context.Context) (*kolotransport.SendStream, error) {
	return c.ic.OpenUniStream(ctx)
}

// AcceptUniStream waits for the next unidirectional stream opened by the peer.
func (c *Conn) AcceptUniStream(ctx context.Context) (*kolotransport.ReceiveStream, error) {
	return c.ic.AcceptUniStream(ctx)
}

// Context is canceled when the connection ends, also when the relay ends the session; its context.Cause is a kolo-transport error.
func (c *Conn) Context() context.Context { return c.ic.Context() }

// Close closes the connection with code 0 and releases its resources.
func (c *Conn) Close() error { return c.CloseWithError(0, "") }

// CloseWithError closes the connection, sending code and msg to the peer, as kolosecure.Conn.CloseWithError.
func (c *Conn) CloseWithError(code uint64, msg string) error {
	err := c.ic.CloseWithError(code, msg)
	c.stopOnce.Do(func() { close(c.stop) })
	c.wg.Wait()
	return err
}
