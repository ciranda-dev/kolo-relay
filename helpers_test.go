package kolorelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	koloid "github.com/ciranda-dev/kolo-id"
	"github.com/ciranda-dev/kolo-relay/internal/pconn"
	"github.com/ciranda-dev/kolo-relay/internal/splice"
	"github.com/ciranda-dev/kolo-relay/internal/wire"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// The warning of an open relay would print for every relay a test starts; the tests that look at it pass their own Logger.
func init() { slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil))) }

// checkGoroutines fails the test if goroutines started during it outlive its cleanups.
func checkGoroutines(t *testing.T) {
	t.Helper()
	before := goroutines()
	t.Cleanup(func() {
		deadline := time.Now().Add(10 * time.Second)
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

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func newID(t *testing.T) *koloid.Identity {
	t.Helper()
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type testRelay struct {
	s    *Server
	id   *koloid.Identity
	addr string
	key  ed25519.PublicKey
}

func startRelay(t *testing.T, cfg *ServerConfig) *testRelay {
	t.Helper()
	id := newID(t)
	s, err := Listen(testCtx(t), "127.0.0.1:0", id, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return &testRelay{s: s, id: id, addr: s.Addr().String(), key: id.PublicKey()}
}

func reserve(t *testing.T, r *testRelay, id *koloid.Identity, cfg *Config) *Reservation {
	t.Helper()
	res, err := Reserve(testCtx(t), r.addr, r.key, id, cfg)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	t.Cleanup(func() { res.Close() })
	return res
}

func dial(t *testing.T, r *testRelay, id *koloid.Identity, target ed25519.PublicKey, cfg *Config) *Conn {
	t.Helper()
	c, err := Dial(testCtx(t), r.addr, r.key, id, target, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func accept(t *testing.T, res *Reservation) *Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := res.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// serveEcho echoes every bidirectional stream c's peer opens, until c ends.
func serveEcho(c *Conn) {
	go func() {
		for {
			s, err := c.AcceptStream(context.Background())
			if err != nil {
				return
			}
			go func() {
				io.Copy(s, s)
				s.Close()
			}()
		}
	}()
}

func echo(t *testing.T, c *Conn, msg []byte) {
	t.Helper()
	ctx := testCtx(t)
	s, err := c.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	s.SetDeadline(time.Now().Add(20 * time.Second))
	go func() {
		s.Write(msg)
		s.Close()
	}()
	got, err := io.ReadAll(s)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo: got %d bytes, %v", len(got), err)
	}
}

// pair reserves target on r, dials it from initiator and returns both ends; the target end echoes.
func pair(t *testing.T, r *testRelay, cfg *Config) (initiator, target *Conn, res *Reservation) {
	t.Helper()
	tid, iid := newID(t), newID(t)
	res = reserve(t, r, tid, cfg)
	initiator = dial(t, r, iid, tid.PublicKey(), cfg)
	target = accept(t, res)
	serveEcho(target)
	return initiator, target, res
}

func waitDone(t *testing.T, ctx context.Context, within time.Duration) error {
	t.Helper()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-time.After(within):
		t.Fatalf("connection still open after %v", within)
		return nil
	}
}

func closeCode(err error) (uint64, bool) {
	var te *kolotransport.Error
	if errors.As(err, &te) {
		return te.Code, true
	}
	return 0, false
}

// rawClient is a kolo-secure connection to the relay that speaks the protocol by hand.
func rawClient(t *testing.T, r *testRelay) *kolosecure.Conn {
	t.Helper()
	c, _ := rawClientID(t, r)
	return c
}

func rawClientID(t *testing.T, r *testRelay) (*kolosecure.Conn, ed25519.PublicKey) {
	t.Helper()
	id := newID(t)
	c, err := kolosecure.Dial(testCtx(t), r.addr, id, r.key, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, id.PublicKey()
}

func rawSend(t *testing.T, c *kolosecure.Conn, body []byte) *kolotransport.Stream {
	t.Helper()
	st, err := c.OpenStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteMessage(st, body); err != nil {
		t.Fatal(err)
	}
	return st
}

func rawStatus(t *testing.T, st *kolotransport.Stream) uint64 {
	t.Helper()
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	body, err := wire.ReadMessage(st)
	if err != nil {
		t.Fatalf("reading status: %v", err)
	}
	m, err := wire.Decode(body)
	if err != nil || m.Type != wire.TypeStatus {
		t.Fatalf("status %x: %v", body, err)
	}
	return m.Code
}

// Fake relay modes: a test double that speaks the protocol but misbehaves.
const (
	fakeRecord     = iota // forwards honestly and records what it forwards
	fakeLie               // announces a wrong initiator key to the target
	fakeMITM              // terminates both end-to-end sessions with its own key
	fakeReset             // answers OK to Connect, then resets the session stream
	fakeForward           // terminates both sessions and forwards the target's own proof to the dialer
	fakeForwardEnd        // as fakeForward, then ends the session stream right after the proof
	fakeVersion0          // offers datagrams but, as kolo-relay v0.1.0, answers every version but 0 with UnsupportedVersion
	fakeNoVersion         // offers datagrams and answers every request with UnsupportedVersion
)

type fakeRelay struct {
	t    *testing.T
	sl   *kolosecure.Listener
	id   *koloid.Identity
	mid  *koloid.Identity
	mode int
	addr string
	key  ed25519.PublicKey

	conns     atomic.Int64
	refused   atomic.Int64
	forwarded atomic.Int64 // datagrams relayed in version 1
	dg        bool         // speaks version 1: relays datagrams between datagram clients

	mu      sync.Mutex
	targets map[string]*kolosecure.Conn
	seen    bytes.Buffer
	results chan error
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
}

func startFake(t *testing.T, mode int) *fakeRelay { return startFakeWith(t, mode, false) }

// startFakeWith starts a fake relay; with datagrams it offers them and carries the session in version 1, as clients
// built with datagramClient ask for.
func startFakeWith(t *testing.T, mode int, datagrams bool) *fakeRelay {
	t.Helper()
	id := newID(t)
	var cfg *kolosecure.Config
	if mode == fakeVersion0 || mode == fakeNoVersion || datagrams {
		cfg = &kolosecure.Config{Transport: &kolotransport.Config{Datagrams: true}}
	}
	sl, err := kolosecure.Listen(testCtx(t), "127.0.0.1:0", id, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeRelay{t: t, sl: sl, id: id, mid: newID(t), mode: mode, dg: datagrams, addr: sl.Addr().String(), key: id.PublicKey(),
		targets: make(map[string]*kolosecure.Conn), results: make(chan error, 4), ctx: ctx, cancel: cancel}
	f.wg.Go(f.loop)
	t.Cleanup(func() {
		cancel()
		sl.Close()
		f.wg.Wait()
	})
	return f
}

func (f *fakeRelay) relay() *testRelay {
	return &testRelay{id: f.id, addr: f.addr, key: f.key}
}

func (f *fakeRelay) loop() {
	for {
		c, err := f.sl.Accept(f.ctx)
		if err != nil {
			return
		}
		f.wg.Go(func() { f.handle(c) })
	}
}

func (f *fakeRelay) handle(c *kolosecure.Conn) {
	f.conns.Add(1)
	st, err := c.AcceptStream(f.ctx)
	if err != nil {
		return
	}
	body, err := wire.ReadMessage(st)
	if err != nil {
		return
	}
	m, err := wire.Decode(body)
	if err != nil {
		return
	}
	if f.mode == fakeNoVersion || (f.mode == fakeVersion0 && m.Version != wire.Version0) {
		f.refused.Add(1)
		wire.WriteMessage(st, wire.EncodeStatus(wire.StatusUnsupportedVersion))
		select {
		case <-c.Context().Done():
		case <-f.ctx.Done():
		}
		c.Close()
		return
	}
	switch m.Type {
	case wire.TypeReserve:
		f.mu.Lock()
		f.targets[string(c.RemotePublicKey())] = c
		f.mu.Unlock()
		wire.WriteMessage(st, wire.EncodeStatus(wire.StatusOK))
		select {
		case <-c.Context().Done():
		case <-f.ctx.Done():
		}
	case wire.TypeConnect:
		f.connect(c, st, m.Key)
	}
	c.Close()
}

// open announces announce to target and returns the session stream and the target's relay connection.
func (f *fakeRelay) open(target []byte, announce []byte) (*kolotransport.Stream, *kolosecure.Conn) {
	f.mu.Lock()
	tc := f.targets[string(target)]
	f.mu.Unlock()
	if tc == nil {
		return nil, nil
	}
	ts, err := tc.OpenStream(f.ctx)
	if err != nil {
		return nil, nil
	}
	version := uint64(wire.Version0)
	if f.dg {
		version = wire.Version1
	}
	wire.WriteMessage(ts, wire.EncodeIncoming(version, announce))
	body, err := wire.ReadMessage(ts)
	if m, derr := wire.Decode(body); err != nil || derr != nil || m.Code != wire.StatusOK {
		return nil, nil
	}
	return ts, tc
}

// pump moves the datagrams of session stream fromID on from to session stream toID on to, and records their packets.
func (f *fakeRelay) pump(ctx context.Context, from, to *kolosecure.Conn, fromID, toID uint64) {
	for {
		b, err := from.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		id, p, err := wire.DecodeDatagram(b)
		if err != nil || id != fromID {
			continue
		}
		f.mu.Lock()
		f.seen.Write(p)
		f.mu.Unlock()
		if out, err := wire.AppendDatagram(nil, toID, p); err == nil && to.SendDatagram(out) == nil {
			f.forwarded.Add(1)
		}
	}
}

func (f *fakeRelay) connect(c *kolosecure.Conn, st *kolotransport.Stream, target []byte) {
	announce := c.RemotePublicKey()
	if f.mode == fakeLie {
		announce = newID(f.t).PublicKey()
	}
	switch f.mode {
	case fakeMITM:
		f.mitm(c, st, target, announce)
		return
	case fakeForward, fakeForwardEnd:
		f.forward(c, st, target, announce)
		return
	case fakeReset:
		wire.WriteMessage(st, wire.EncodeStatus(wire.StatusOK))
		time.Sleep(50 * time.Millisecond)
		st.CancelWrite(9)
		st.CancelRead(9)
		<-c.Context().Done()
		return
	}
	ts, tc := f.open(target, announce)
	if ts == nil {
		return
	}
	if f.dg {
		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()
		f.wg.Go(func() { f.pump(ctx, c, tc, quarterID(st), quarterID(ts)) })
		f.wg.Go(func() { f.pump(ctx, tc, c, quarterID(ts), quarterID(st)) })
	}
	wire.WriteMessage(st, wire.EncodeStatus(wire.StatusOK))
	var wg sync.WaitGroup
	copyRec := func(dst, src *kolotransport.Stream) {
		buf := make([]byte, 4096)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				f.mu.Lock()
				f.seen.Write(buf[:n])
				f.mu.Unlock()
				if _, err := dst.Write(buf[:n]); err != nil {
					break
				}
			}
			if err != nil {
				if err == io.EOF {
					dst.Close()
					return
				}
				break
			}
		}
		dst.CancelWrite(0)
		src.CancelRead(0)
	}
	wg.Go(func() { copyRec(ts, st) })
	wg.Go(func() { copyRec(st, ts) })
	stop := context.AfterFunc(f.ctx, func() {
		st.CancelRead(0)
		ts.CancelRead(0)
	})
	wg.Wait()
	stop()
}

// mitm runs its own end-to-end sessions: as the listener towards the dialer, and as a dialer claiming the initiator's key towards the target.
func (f *fakeRelay) mitm(c *kolosecure.Conn, st *kolotransport.Stream, target, initiator []byte) {
	ts, trc := f.open(target, initiator)
	if ts == nil {
		return
	}
	wire.WriteMessage(st, wire.EncodeStatus(wire.StatusOK))
	ra, la, err := relayAddrs(c)
	if err != nil {
		f.results <- err
		return
	}
	var rtd, rtt *router
	if f.dg {
		if rtd, rtt = newRouter(c), newRouter(trc); rtd == nil || rtt == nil {
			f.results <- errors.New("no datagrams")
			return
		}
		go rtd.run()
		go rtt.run()
	}
	ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
	defer cancel()

	towardDialer, err := kolotransport.ListenConn(ctx, sessionConn(st, rtd, c, la, ra, 64), &kolotransport.Config{MaxConns: 1})
	if err != nil {
		f.results <- err
		return
	}
	sd, err := kolosecure.NewListener(towardDialer, f.mid, nil)
	if err != nil {
		f.results <- err
		return
	}
	defer sd.Close()
	deny := &kolotransport.Config{MaxConns: 1, AcceptFunc: func(netip.AddrPort) bool { return false }}
	towardTarget, err := kolotransport.ListenConn(ctx, sessionConn(ts, rtt, trc, la, ra, 64), deny)
	if err != nil {
		f.results <- err
		return
	}
	stt, err := kolosecure.NewListener(towardTarget, f.mid, nil)
	if err != nil {
		f.results <- err
		return
	}
	defer stt.Close()
	go sd.Accept(ctx)
	tc, err := stt.Dial(ctx, ra.AddrPort(), target)
	if err != nil {
		f.results <- err
		return
	}
	select {
	case <-tc.Context().Done():
		f.results <- context.Cause(tc.Context())
	case <-ctx.Done():
		f.results <- ctx.Err()
	}
	// The dialer gives its verdict on the proof before the session goes: closing it as soon as the target hangs up
	// races the dialer's handshake, which would then see the close instead of the key. Dial closes its relay connection
	// when it returns.
	select {
	case <-c.Context().Done():
	case <-ctx.Done():
	}
}

func (f *fakeRelay) recorded() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return bytes.Clone(f.seen.Bytes())
}

// forward runs kolo-secure's dialer side towards the target by hand, claiming the initiator's key,
// and replays the target's proof to the dialer, whose own session has another exporter.
func (f *fakeRelay) forward(c *kolosecure.Conn, st *kolotransport.Stream, target, initiator []byte) {
	ts, _ := f.open(target, initiator)
	if ts == nil {
		return
	}
	wire.WriteMessage(st, wire.EncodeStatus(wire.StatusOK))
	ra, la, err := relayAddrs(c)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
	defer cancel()
	sig := &signalStream{Stream: st, writes: make(chan struct{}, 1)}
	towardDialer, err := kolotransport.ListenConn(ctx, pconn.New(sig, la, ra, 64, nil), &kolotransport.Config{MaxConns: 1})
	if err != nil {
		return
	}
	defer towardDialer.Close()
	deny := &kolotransport.Config{MaxConns: 1, AcceptFunc: func(netip.AddrPort) bool { return false }}
	towardTarget, err := kolotransport.ListenConn(ctx, pconn.New(ts, la, ra, 64, nil), deny)
	if err != nil {
		return
	}
	defer towardTarget.Close()
	dc, err := towardDialer.Accept(ctx)
	if err != nil {
		return
	}
	ds, err := dc.AcceptStream(ctx)
	if err != nil {
		return
	}
	if _, err := readSecureFrame(ds); err != nil {
		return
	}
	tc, err := towardTarget.Dial(ctx, ra.AddrPort())
	if err != nil {
		return
	}
	tsec, err := tc.OpenStream(ctx)
	if err != nil {
		return
	}
	var hello kolocodec.Encoder
	hello.PutUvarint(1)
	hello.PutUvarint(0)
	hello.PutFixed(initiator)
	writeSecureFrame(tsec, hello.Bytes())
	proof, err := readSecureFrame(tsec)
	if err != nil {
		return
	}
	if f.mode == fakeForwardEnd {
		// The session stream ends right behind the packet that ends the handshake stream: wait for the proof's write, then for the FIN's.
		select {
		case <-sig.writes:
		default:
		}
		writeSecureFrame(ds, proof)
		select {
		case <-sig.writes:
		case <-ctx.Done():
		}
		ds.Close()
		select {
		case <-sig.writes:
		case <-ctx.Done():
		}
		st.Close()
	} else {
		writeSecureFrame(ds, proof)
		ds.Close()
	}
	select {
	case <-dc.Context().Done():
	case <-ctx.Done():
	}
}

func writeSecureFrame(w io.Writer, body []byte) {
	var e kolocodec.Encoder
	e.PutBytes(body)
	w.Write(e.Bytes())
}

func readSecureFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:1]); err != nil {
		return nil, err
	}
	n := 1
	if hdr[0] >= 0x80 {
		if _, err := io.ReadFull(r, hdr[1:]); err != nil {
			return nil, err
		}
		n = 2
	}
	size, err := kolocodec.NewDecoder(hdr[:n]).UvarintMax(256)
	if err != nil {
		return nil, err
	}
	body := make([]byte, size)
	_, err = io.ReadFull(r, body)
	return body, err
}

// signalStream signals after every Write, so a test can end the stream right behind a given frame.
type signalStream struct {
	*kolotransport.Stream
	writes chan struct{}
}

func (s *signalStream) Write(p []byte) (int, error) {
	n, err := s.Stream.Write(p)
	select {
	case s.writes <- struct{}{}:
	default:
	}
	return n, err
}

// eachTransport runs f with the default clients against a version 0 fake relay, then with datagram clients against a
// version 1 one.
func eachTransport(t *testing.T, f func(t *testing.T, datagrams bool, cfg *Config)) {
	t.Helper()
	for _, c := range []struct {
		name      string
		datagrams bool
		cfg       *Config
	}{{"frames", false, nil}, {"datagrams", true, datagramClient()}} {
		t.Run(c.name, func(t *testing.T) {
			checkGoroutines(t)
			f(t, c.datagrams, c.cfg)
		})
	}
}

// hookAt makes the relay call f at the named point (see Server.at) for the rest of the test.
func hookAt(t *testing.T, s *Server, point string, f func()) {
	t.Helper()
	h := func(p string) {
		if p == point {
			f()
		}
	}
	s.hook.Store(&h)
	t.Cleanup(func() { s.hook.Store(nil) })
}

// untilClosing blocks until Server.Close has stopped the sessions and set its closing flag.
func untilClosing(s *Server) {
	<-s.sessCtx.Done()
	for {
		s.sessMu.Lock()
		closing := s.closing
		s.sessMu.Unlock()
		if closing {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// closeCodeOf reads st to its end and reports the stream or connection code it ended with.
func closeCodeOf(t *testing.T, st *kolotransport.Stream) error {
	t.Helper()
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err := io.ReadAll(st)
	return err
}

// relayClosed checks that err is stream code 5 or connection code 4, the two ways a client learns that the relay closed.
func relayClosed(t *testing.T, what string, err error) {
	t.Helper()
	code, ok := closeCode(err)
	switch {
	case errors.Is(err, kolotransport.ErrStreamReset) && ok && code == splice.EndClosing:
	case errors.Is(err, kolotransport.ErrPeerClosed) && ok && code == codeClosing:
	default:
		t.Fatalf("%s ended with %v, want stream code %d or connection code %d", what, err, splice.EndClosing, codeClosing)
	}
}
