package kolorelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-relay/internal/pconn"
	"github.com/ciranda-dev/kolo-relay/internal/splice"
	"github.com/ciranda-dev/kolo-relay/internal/wire"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// datagramClient is a client Config whose connection to the relay offers datagrams, so it speaks version 1 to a relay that does.
func datagramClient() *Config {
	return &Config{Relay: &kolosecure.Config{Transport: &kolotransport.Config{KeepAlivePeriod: 5 * time.Second, Datagrams: true}}}
}

// relayWithoutDatagrams is the default relay listener with datagrams off.
func relayWithoutDatagrams(t *testing.T) *testRelay {
	t.Helper()
	sec := relaySecure()
	sec.Transport.Datagrams = false
	return startRelay(t, &ServerConfig{Secure: sec})
}

// pairWith is pair with a Config for each end.
func pairWith(t *testing.T, r *testRelay, icfg, tcfg *Config) (initiator, target *Conn, res *Reservation) {
	t.Helper()
	tid := newID(t)
	res = reserve(t, r, tid, tcfg)
	initiator = dial(t, r, newID(t), tid.PublicKey(), icfg)
	target = accept(t, res)
	serveEcho(target)
	return initiator, target, res
}

func counts(c *Conn) pconn.Counts { return c.pc.Counts() }

func TestDatagramSession(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	ic, tc, _ := pair(t, r, datagramClient())
	echo(t, ic, []byte("warm up"))
	before := [2]pconn.Counts{counts(ic), counts(tc)}
	echo(t, ic, bytes.Repeat([]byte("0123456789abcdef"), 1<<16))
	for i, c := range []*Conn{ic, tc} {
		got := counts(c)
		dSent, fSent := got.DatagramsSent-before[i].DatagramsSent, got.FramesSent-before[i].FramesSent
		dRecv, fRecv := got.DatagramsReceived-before[i].DatagramsReceived, got.FramesReceived-before[i].FramesReceived
		if dSent <= fSent || dRecv <= fRecv {
			t.Errorf("end %d sent %d datagrams and %d frames, received %d datagrams and %d frames; want mostly datagrams", i, dSent, fSent, dRecv, fRecv)
		}
	}
}

// interop checks that a session connects and moves data, and which ends sent datagrams.
func interop(t *testing.T, r *testRelay, icfg, tcfg *Config, iDatagrams, tDatagrams bool) {
	t.Helper()
	ic, tc, _ := pairWith(t, r, icfg, tcfg)
	echo(t, ic, []byte("warm up"))
	echo(t, ic, bytes.Repeat([]byte("0123456789abcdef"), 1<<14))
	for _, end := range []struct {
		name      string
		c         *Conn
		datagrams bool
	}{{"initiator", ic, iDatagrams}, {"target", tc, tDatagrams}} {
		got := counts(end.c)
		if (got.DatagramsSent > 0) != end.datagrams || (got.DatagramsReceived > 0) != end.datagrams {
			t.Errorf("%s: %+v, want datagrams %v", end.name, got, end.datagrams)
		}
		if got.FramesReceived == 0 && !end.datagrams {
			t.Errorf("%s received no frame", end.name)
		}
	}
}

func TestInteropVersion0Initiator(t *testing.T) {
	checkGoroutines(t)
	interop(t, startRelay(t, nil), nil, datagramClient(), false, true)
}

func TestInteropVersion0Target(t *testing.T) {
	checkGoroutines(t)
	interop(t, startRelay(t, nil), datagramClient(), nil, true, false)
}

func TestInteropRelayWithoutDatagrams(t *testing.T) {
	checkGoroutines(t)
	interop(t, relayWithoutDatagrams(t), datagramClient(), datagramClient(), false, false)
}

// The default clients against the default relay, which offers datagrams, speak version 0.
func TestInteropDefaultClients(t *testing.T) {
	checkGoroutines(t)
	interop(t, startRelay(t, nil), nil, nil, false, false)
}

func TestInteropDatagramClients(t *testing.T) {
	checkGoroutines(t)
	interop(t, startRelay(t, nil), datagramClient(), datagramClient(), true, true)
}

// rawDatagramClient is rawClient with datagrams on.
func rawDatagramClient(t *testing.T, r *testRelay) *kolosecure.Conn {
	t.Helper()
	c, _ := rawDatagramClientID(t, r)
	return c
}

func rawDatagramClientID(t *testing.T, r *testRelay) (*kolosecure.Conn, ed25519.PublicKey) {
	t.Helper()
	id := newID(t)
	c, err := kolosecure.Dial(testCtx(t), r.addr, id, r.key, &kolosecure.Config{Transport: &kolotransport.Config{Datagrams: true}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, id.PublicKey()
}

func TestVersion1NeedsDatagrams(t *testing.T) {
	checkGoroutines(t)
	r := relayFor(t, ServerConfig{})
	tid := newID(t)
	reserve(t, r, tid, nil)
	for name, body := range map[string][]byte{
		"reserve": wire.EncodeReserve(wire.Version1),
		"connect": wire.EncodeConnect(wire.Version1, tid.PublicKey()),
	} {
		if code := rawStatus(t, rawSend(t, rawClient(t, r), body)); code != wire.StatusUnsupportedVersion {
			t.Errorf("%s in version 1 without datagrams: status %d, want UnsupportedVersion", name, code)
		}
	}
	if code := rawStatus(t, rawSend(t, rawDatagramClient(t, r), []byte{1, 2})); code != wire.StatusUnsupportedVersion {
		t.Errorf("version 2 with datagrams: status %d, want UnsupportedVersion", code)
	}
	if code := rawStatus(t, rawSend(t, rawDatagramClient(t, r), wire.EncodeReserve(wire.Version0))); code != wire.StatusOK {
		t.Errorf("version 0 with datagrams: status %d, want OK", code)
	}
}

func TestUnroutableDatagramsAreDropped(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	tid := newID(t)
	res := reserve(t, r, tid, nil)
	raw := rawDatagramClient(t, r)
	st := rawSend(t, raw, wire.EncodeConnect(wire.Version1, tid.PublicKey()))
	if code := rawStatus(t, st); code != wire.StatusOK {
		t.Fatalf("Connect status %d", code)
	}
	id := st.ID() / 4
	flood := func() {
		for i := range 500 {
			for _, d := range [][]byte{{0x80}, {byte(id)}, {0x81, 0x00, 1}} {
				raw.SendDatagram(d)
			}
			junk, _ := wire.AppendDatagram(nil, id+1+uint64(i), make([]byte, 1000))
			raw.SendDatagram(junk)
			mine, _ := wire.AppendDatagram(nil, id, make([]byte, 100))
			raw.SendDatagram(mine)
		}
	}
	flood()
	// The target never sees a handshake, so the relay ends the session when the initiator resets its stream.
	st.CancelWrite(9)
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadAll(st); err == nil {
		t.Fatal("the session did not end")
	}
	flood()
	select {
	case <-raw.Context().Done():
		t.Fatalf("datagrams for no session closed the connection: %v", context.Cause(raw.Context()))
	case <-time.After(500 * time.Millisecond):
	}
	ic := dial(t, r, newID(t), tid.PublicKey(), nil)
	serveEcho(accept(t, res))
	echo(t, ic, []byte("the reservation still works"))
}

func TestDatagramRate(t *testing.T) {
	checkGoroutines(t)
	const rateBytes, burst, total = 64 << 10, 16 << 10, 192 << 10
	r := startRelay(t, &ServerConfig{RateBytes: rateBytes, RateBurst: burst})
	ic, tc, _ := pair(t, r, datagramClient())
	before := ic.pc.Received() + tc.pc.Received()
	dBefore := counts(ic).DatagramsReceived + counts(tc).DatagramsReceived
	begin := time.Now()
	echo(t, ic, make([]byte, total))
	d := time.Since(begin).Seconds()
	egress := float64(ic.pc.Received() + tc.pc.Received() - before)
	if bound := 2*rateBytes*d + 2*burst; egress > bound {
		t.Fatalf("relay sent %.0f bytes in %.2fs, above 2 × RateBytes × t + 2 × RateBurst = %.0f", egress, d, bound)
	}
	if got := counts(ic).DatagramsReceived + counts(tc).DatagramsReceived - dBefore; got == 0 {
		t.Fatal("no datagram crossed the relay; the test does not cover the datagram path")
	}
}

func TestDatagramMaxSessionBytes(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, &ServerConfig{MaxSessionBytes: 64 << 10})
	ic, tc, _ := pair(t, r, datagramClient())
	s, err := ic.OpenStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	s.SetWriteDeadline(time.Now().Add(20 * time.Second))
	go s.Write(make([]byte, 1<<20))
	sessionEndCode(t, ic, 20*time.Second, splice.EndBytes)
	if got := counts(tc).DatagramsReceived; got == 0 {
		t.Fatal("the target received no datagram; the test does not cover the datagram path")
	}
	if got := tc.pc.Received(); got > 64<<10 {
		t.Fatalf("the target received %d bytes, above MaxSessionBytes", got)
	}
}

func TestDatagramSessionIdle(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, &ServerConfig{SessionIdleTimeout: time.Second})
	ic, tc, _ := pair(t, r, datagramClient())
	echo(t, ic, []byte("only a little"))
	if counts(ic).DatagramsReceived == 0 || counts(tc).DatagramsReceived == 0 {
		t.Fatalf("no datagrams: %+v %+v", counts(ic), counts(tc))
	}
	sessionEndCode(t, ic, 10*time.Second, splice.EndIdle)
}

func TestServerCloseEndsVersion1Sessions(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	tid := newID(t)
	res := reserve(t, r, tid, datagramClient())
	go func() {
		if c, err := res.Accept(context.Background()); err == nil {
			c.Close()
		}
	}()
	raw := rawDatagramClient(t, r)
	st := rawSend(t, raw, wire.EncodeConnect(wire.Version1, tid.PublicKey()))
	if code := rawStatus(t, st); code != wire.StatusOK {
		t.Fatalf("Connect status %d", code)
	}
	closed := make(chan struct{})
	go func() {
		r.s.Close()
		close(closed)
	}()
	err := closeCodeOf(t, st)
	if code, ok := closeCode(err); !errors.Is(err, kolotransport.ErrStreamReset) || !ok || code != splice.EndClosing {
		t.Fatalf("version 1 session stream after Server.Close: %v, want a reset with code %d", err, splice.EndClosing)
	}
	raw.Close()
	<-closed
}

func TestDefaultsDatagrams(t *testing.T) {
	c, err := (*Config)(nil).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if tr := c.Relay.Transport; tr.Datagrams || tr.KeepAlivePeriod != 5*time.Second {
		t.Fatalf("default Relay transport %+v, want no datagrams and a 5s keep-alive", tr)
	}
	if !relaySecure().Transport.Datagrams {
		t.Fatal("the default relay listener does not offer datagrams")
	}
	for _, on := range []bool{false, true} {
		mine := &kolosecure.Config{Transport: &kolotransport.Config{Datagrams: on}}
		if c, _ := (&Config{Relay: mine}).withDefaults(); c.Relay.Transport.Datagrams != on {
			t.Fatalf("a non-nil Relay with Datagrams %v was changed", on)
		}
	}
}

func TestCloseCodeDuringDatagramTransfer(t *testing.T) {
	checkGoroutines(t)
	// The relay's bucket drops datagrams, and the close still reaches the target on the stream.
	r := relayFor(t, ServerConfig{RateBytes: 512 << 10, RateBurst: 16 << 10})
	ic, tc, _ := pair(t, r, datagramClient())
	s, err := ic.OpenStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	go s.Write(make([]byte, 4<<20))
	s.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(s, make([]byte, 256<<10)); err != nil {
		t.Fatalf("echo: %v", err)
	}
	if counts(ic).DatagramsSent == 0 {
		t.Fatal("the dialer sent no datagram; the test does not cover the datagram path")
	}
	ic.CloseWithError(42, "")
	err = waitDone(t, tc.Context(), 10*time.Second)
	if code, ok := closeCode(err); !errors.Is(err, kolotransport.ErrPeerClosed) || !ok || code != 42 {
		t.Fatalf("target saw %v in the middle of a transfer, want the peer's code 42", err)
	}
}

func TestIncomingInTheTargetsVersion(t *testing.T) {
	checkGoroutines(t)
	r := relayFor(t, ServerConfig{})
	for _, c := range []struct {
		datagrams bool
		version   uint64
	}{{true, wire.Version1}, {true, wire.Version0}, {false, wire.Version0}} {
		target, key := rawClientID(t, r)
		if c.datagrams {
			target, key = rawDatagramClientID(t, r)
		}
		if code := rawStatus(t, rawSend(t, target, wire.EncodeReserve(c.version))); code != wire.StatusOK {
			t.Fatalf("Reserve status %d", code)
		}
		st := rawSend(t, rawDatagramClient(t, r), wire.EncodeConnect(wire.Version1, key))
		ts, err := target.AcceptStream(testCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		ts.SetReadDeadline(time.Now().Add(10 * time.Second))
		body, err := wire.ReadMessage(ts)
		if err != nil {
			t.Fatal(err)
		}
		if m, err := wire.Decode(body); err != nil || m.Type != wire.TypeIncoming || m.Version != c.version {
			t.Errorf("target reserved in version %d got Incoming %+v, %v", c.version, m, err)
		}
		wire.WriteMessage(ts, wire.EncodeStatus(wire.StatusUnavailable))
		if code := rawStatus(t, st); code != wire.StatusUnavailable {
			t.Fatalf("Connect status %d, want Unavailable", code)
		}
	}
}

func TestVersion0FallbackOnARelayThatOffersDatagrams(t *testing.T) {
	checkGoroutines(t)
	f := startFake(t, fakeVersion0)
	ic, tc, _ := pair(t, f.relay(), datagramClient())
	echo(t, ic, []byte("through a relay that offers datagrams and speaks version 0 only"))
	if got := f.refused.Load(); got != 2 {
		t.Fatalf("the relay refused %d version 1 requests, want 2: the Reserve and the Connect", got)
	}
	if counts(ic).DatagramsSent != 0 || counts(tc).DatagramsSent != 0 {
		t.Fatalf("datagrams sent in version 0: %+v %+v", counts(ic), counts(tc))
	}
}

func TestUnsupportedVersionIsRetriedOnce(t *testing.T) {
	checkGoroutines(t)
	f := startFake(t, fakeNoVersion)
	r := f.relay()
	target := newID(t).PublicKey()
	for _, c := range []struct {
		name  string
		cfg   *Config
		conns int64
	}{{"datagrams", datagramClient(), 2}, {"stream only", nil, 1}} {
		calls := map[string]func() error{
			"Reserve": func() error {
				_, err := Reserve(testCtx(t), r.addr, r.key, newID(t), c.cfg)
				return err
			},
			"Dial": func() error {
				_, err := Dial(testCtx(t), r.addr, r.key, newID(t), target, c.cfg)
				return err
			},
		}
		for name, call := range calls {
			before := f.conns.Load()
			if err := call(); !errors.Is(err, ErrUnsupportedVersion) {
				t.Fatalf("%s, %s: %v, want ErrUnsupportedVersion", name, c.name, err)
			}
			if got := f.conns.Load() - before; got != c.conns {
				t.Fatalf("%s, %s: %d relay connections, want %d", name, c.name, got, c.conns)
			}
		}
	}
}

func TestTargetListenerFailureFreesTheSession(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	for name, peer := range map[string]*kolosecure.Config{
		"transport": {Transport: &kolotransport.Config{MaxIncomingStreams: 1001}},
		"secure":    {MaxPending: 1001},
	} {
		tid := newID(t)
		res := reserve(t, r, tid, &Config{Relay: datagramClient().Relay, Peer: peer})
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		_, err := Dial(ctx, r.addr, r.key, newID(t), tid.PublicKey(), nil)
		cancel()
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s: Dial %v, want ErrUnavailable once the target's session ends", name, err)
		}
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			res.router.mu.Lock()
			n := len(res.router.legs)
			res.router.mu.Unlock()
			if n == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: %d sessions still routed on the reservation", name, n)
			}
		}
	}
}

func TestSessionIDsAreSeparatePerConnection(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	tid := newID(t)
	res := reserve(t, r, tid, datagramClient())
	c, err := datagramClient().withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	var ics, tcs []*Conn
	var ids []uint64
	for range 2 {
		id := newID(t)
		rc, err := request(testCtx(t), r.addr, r.key, id, c, func(v uint64) []byte { return wire.EncodeConnect(v, tid.PublicKey()) })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { rc.rc.Close() })
		if rc.version != wire.Version1 {
			t.Fatalf("initiator session in version %d", rc.version)
		}
		ids = append(ids, quarterID(rc.st))
		ic, err := dialThrough(testCtx(t), rc, id, r.key, tid.PublicKey(), c)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ic.Close() })
		tc := accept(t, res)
		serveEcho(tc)
		ics, tcs = append(ics, ic), append(tcs, tc)
	}
	if ids[0] != ids[1] {
		t.Fatalf("quarter stream IDs %v; the test needs both initiators to tag their datagrams alike", ids)
	}
	var wg sync.WaitGroup
	for i, ic := range ics {
		wg.Go(func() {
			msg := bytes.Repeat([]byte{byte('a' + i)}, 1<<18)
			s, err := ic.OpenStream(testCtx(t))
			if err != nil {
				t.Errorf("session %d: %v", i, err)
				return
			}
			s.SetDeadline(time.Now().Add(20 * time.Second))
			go func() {
				s.Write(msg)
				s.Close()
			}()
			if got, err := io.ReadAll(s); err != nil || !bytes.Equal(got, msg) {
				t.Errorf("session %d: echo of %d bytes came back as %d bytes, %v", i, len(msg), len(got), err)
			}
		})
	}
	wg.Wait()
	for i := range ics {
		if counts(ics[i]).DatagramsSent == 0 || counts(tcs[i]).DatagramsReceived == 0 {
			t.Fatalf("session %d: %+v %+v; the test does not cover the datagram path", i, counts(ics[i]), counts(tcs[i]))
		}
	}
}
