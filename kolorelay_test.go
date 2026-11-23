package kolorelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	"github.com/ciranda-dev/kolo-relay/internal/limits"
	"github.com/ciranda-dev/kolo-relay/internal/pconn"
	"github.com/ciranda-dev/kolo-relay/internal/splice"
	"github.com/ciranda-dev/kolo-relay/internal/wire"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func TestRelayedStats(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	tid, iid := newID(t), newID(t)
	res := reserve(t, r, tid, nil)
	ic := dial(t, r, iid, tid.PublicKey(), nil)
	tc := accept(t, res)
	serveEcho(tc)
	echo(t, ic, bytes.Repeat([]byte("0123456789abcdef"), 1<<12))

	s := ic.Stats()
	if s.PacketsSent == 0 || s.BytesSent == 0 || s.CongestionWindow == 0 || s.CongestionController == "" {
		t.Fatalf("Stats of a used relayed connection = %+v", s)
	}
	ic.Close()
	if got := ic.Stats(); got != (kolotransport.ConnStats{}) {
		t.Fatalf("Stats after close = %+v, want the zero value", got)
	}
}

func TestRelayedEcho(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	tid, iid := newID(t), newID(t)
	res := reserve(t, r, tid, nil)
	ic := dial(t, r, iid, tid.PublicKey(), nil)
	tc := accept(t, res)
	serveEcho(tc)

	if !bytes.Equal(ic.RemotePublicKey(), tid.PublicKey()) || !bytes.Equal(tc.RemotePublicKey(), iid.PublicKey()) {
		t.Fatal("RemotePublicKey is not the peer's key")
	}
	if !bytes.Equal(ic.RelayPublicKey(), r.key) || !bytes.Equal(tc.RelayPublicKey(), r.key) {
		t.Fatal("RelayPublicKey is not the relay's key")
	}
	if ic.RelayAddr().String() != r.addr {
		t.Fatalf("RelayAddr %v, want %v", ic.RelayAddr(), r.addr)
	}
	echo(t, ic, []byte("hello kolo"))
	echo(t, ic, bytes.Repeat([]byte("0123456789abcdef"), 1<<14))

	us, err := tc.OpenUniStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	us.Write([]byte("one way"))
	us.Close()
	rs, err := ic.AcceptUniStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	rs.SetReadDeadline(time.Now().Add(10 * time.Second))
	if got, err := io.ReadAll(rs); err != nil || string(got) != "one way" {
		t.Fatalf("uni stream: %q %v", got, err)
	}

	ic.Close()
	waitDone(t, tc.Context(), 10*time.Second)
}

func TestManySessions(t *testing.T) {
	checkGoroutines(t)
	// Every test peer comes from 127.0.0.1, which the default MaxConnsPerIP of 4 would refuse.
	sec := relaySecure()
	sec.Transport.MaxConns, sec.Transport.MaxConnsPerIP = 16, 16
	r := startRelay(t, &ServerConfig{Secure: sec, MaxSessions: 4})
	tid := newID(t)
	res := reserve(t, r, tid, nil)
	go func() {
		for {
			c, err := res.Accept(context.Background())
			if err != nil {
				return
			}
			serveEcho(c)
			t.Cleanup(func() { c.Close() })
		}
	}()
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			c, err := Dial(testCtx(t), r.addr, r.key, newID(t), tid.PublicKey(), nil)
			if err != nil {
				t.Errorf("Dial %d: %v", i, err)
				return
			}
			defer c.Close()
			echo(t, c, bytes.Repeat([]byte{byte(i)}, 10000))
		})
	}
	wg.Wait()
}

func TestRelaySeesOnlyCiphertext(t *testing.T) {
	eachTransport(t, func(t *testing.T, datagrams bool, cfg *Config) {
		f := startFakeWith(t, fakeRecord, datagrams)
		r := f.relay()
		ic, _, _ := pair(t, r, cfg)
		secret := []byte("kolo-relay secret marker that must stay end to end")
		echo(t, ic, bytes.Repeat(secret, 100))
		seen := f.recorded()
		if len(seen) < 100*len(secret) {
			t.Fatalf("relay forwarded only %d bytes", len(seen))
		}
		if datagrams && f.forwarded.Load() == 0 {
			t.Fatal("the relay forwarded no datagram")
		}
		if bytes.Contains(seen, secret[:16]) {
			t.Fatal("the relay saw plaintext")
		}
	})
}

func TestLyingRelayIsDetected(t *testing.T) {
	eachTransport(t, func(t *testing.T, datagrams bool, cfg *Config) {
		f := startFakeWith(t, fakeLie, datagrams)
		r := f.relay()
		tid, iid := newID(t), newID(t)
		res := reserve(t, r, tid, cfg)
		ic, err := Dial(testCtx(t), r.addr, r.key, iid, tid.PublicKey(), cfg)
		if err == nil {
			defer ic.Close()
			err = waitDone(t, ic.Context(), 10*time.Second)
		}
		if code, ok := closeCode(err); !errors.Is(err, kolotransport.ErrPeerClosed) || !ok || code != codeUnexpectedPeer {
			t.Fatalf("dialer: %v, want the target to close with code %d", err, codeUnexpectedPeer)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if c, err := res.Accept(ctx); err == nil {
			c.Close()
			t.Fatal("the target accepted a peer the relay misnamed")
		}
	})
}

func TestMITMRelayIsDetected(t *testing.T) {
	eachTransport(t, func(t *testing.T, datagrams bool, cfg *Config) {
		f := startFakeWith(t, fakeMITM, datagrams)
		r := f.relay()
		tid, iid := newID(t), newID(t)
		res := reserve(t, r, tid, cfg)
		_, err := Dial(testCtx(t), r.addr, r.key, iid, tid.PublicKey(), cfg)
		if !errors.Is(err, kolosecure.ErrUnexpectedPeer) {
			t.Fatalf("dialer: %v, want kolosecure.ErrUnexpectedPeer", err)
		}
		select {
		case err := <-f.results:
			if code, ok := closeCode(err); !errors.Is(err, kolotransport.ErrPeerClosed) || !ok || code != codeUnexpectedPeer {
				t.Fatalf("target side: %v, want the target to close with code %d", err, codeUnexpectedPeer)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("the man in the middle never finished its session with the target")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if c, err := res.Accept(ctx); err == nil {
			c.Close()
			t.Fatal("the target accepted the man in the middle")
		}
	})
}

func TestWrongRelayKey(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	other := newID(t).PublicKey()
	if _, err := Reserve(testCtx(t), r.addr, other, newID(t), nil); !errors.Is(err, kolosecure.ErrUnexpectedPeer) {
		t.Fatalf("Reserve: %v", err)
	}
	if _, err := Dial(testCtx(t), r.addr, other, newID(t), newID(t).PublicKey(), nil); !errors.Is(err, kolosecure.ErrUnexpectedPeer) {
		t.Fatalf("Dial: %v", err)
	}
}

func TestUnavailable(t *testing.T) {
	checkGoroutines(t)
	deny := newID(t)
	r := startRelay(t, &ServerConfig{AllowConnect: func(from, to ed25519.PublicKey) bool { return !bytes.Equal(to, deny.PublicKey()) }})
	reserve(t, r, deny, nil)
	picky := newID(t)
	reserve(t, r, picky, &Config{AllowFunc: func(ed25519.PublicKey) bool { return false }})
	panicky := newID(t)
	reserve(t, r, panicky, &Config{AllowFunc: func(ed25519.PublicKey) bool { panic("boom") }})
	for name, target := range map[string]ed25519.PublicKey{
		"no reservation": newID(t).PublicKey(),
		"AllowConnect":   deny.PublicKey(),
		"target refuses": picky.PublicKey(),
		"target panics":  panicky.PublicKey(),
	} {
		if _, err := Dial(testCtx(t), r.addr, r.key, newID(t), target, nil); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: %v, want ErrUnavailable", name, err)
		}
	}
}

func TestNotAllowed(t *testing.T) {
	checkGoroutines(t)
	ok := newID(t)
	r := startRelay(t, &ServerConfig{AllowReserve: func(k ed25519.PublicKey) bool { return bytes.Equal(k, ok.PublicKey()) }})
	reserve(t, r, ok, nil)
	if _, err := Reserve(testCtx(t), r.addr, r.key, newID(t), nil); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("Reserve: %v, want ErrNotAllowed", err)
	}
	p := startRelay(t, &ServerConfig{AllowReserve: func(ed25519.PublicKey) bool { panic("boom") }})
	if _, err := Reserve(testCtx(t), p.addr, p.key, newID(t), nil); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("panicking AllowReserve: %v, want ErrNotAllowed", err)
	}
}

func TestInvalidArguments(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	id := newID(t)
	ctx := testCtx(t)
	cases := map[string]func() error{
		"nil identity Dial":    func() error { _, err := Dial(ctx, r.addr, r.key, nil, newID(t).PublicKey(), nil); return err },
		"nil identity Reserve": func() error { _, err := Reserve(ctx, r.addr, r.key, nil, nil); return err },
		"short target":         func() error { _, err := Dial(ctx, r.addr, r.key, id, make([]byte, 31), nil); return err },
		"target is self":       func() error { _, err := Dial(ctx, r.addr, r.key, id, id.PublicKey(), nil); return err },
		"target is relay":      func() error { _, err := Dial(ctx, r.addr, r.key, id, r.key, nil); return err },
		"short relay key":      func() error { _, err := Reserve(ctx, r.addr, r.key[:31], id, nil); return err },
		"nil identity Listen":  func() error { _, err := Listen(ctx, "127.0.0.1:0", nil, nil); return err },
	}
	for name, f := range cases {
		if err := f(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v, want ErrInvalidArgument", name, err)
		}
	}
	if _, err := Dial(ctx, r.addr, r.key, id, newID(t).PublicKey(), &Config{SendQueue: 1}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("bad Config: %v", err)
	}
	if _, err := Listen(ctx, "127.0.0.1:0", id, &ServerConfig{MaxSessions: -1}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("bad ServerConfig: %v", err)
	}
}

func TestContext(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	res := reserve(t, r, newID(t), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Dial(ctx, r.addr, r.key, newID(t), newID(t).PublicKey(), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial: %v", err)
	}
	if _, err := Reserve(ctx, r.addr, r.key, newID(t), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Reserve: %v", err)
	}
	if _, err := res.Accept(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Accept: %v", err)
	}
	short, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if _, err := res.Accept(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Accept: %v", err)
	}
}

func TestMaxReservations(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, &ServerConfig{MaxReservations: 1})
	reserve(t, r, newID(t), nil)
	if _, err := Reserve(testCtx(t), r.addr, r.key, newID(t), nil); !errors.Is(err, ErrLimit) {
		t.Fatalf("second key: %v, want ErrLimit", err)
	}
}

func TestReservationsFollowConns(t *testing.T) {
	checkGoroutines(t)
	sec := relaySecure()
	sec.Transport.MaxConns, sec.Transport.MaxConnsPerIP = 10, 10
	r := startRelay(t, &ServerConfig{Secure: sec, MaxSessions: 2})
	for range 4 {
		reserve(t, r, newID(t), nil)
	}
	if _, err := Reserve(testCtx(t), r.addr, r.key, newID(t), nil); !errors.Is(err, ErrLimit) {
		t.Fatalf("fifth key: %v, want ErrLimit at (10 - 2) / 2 = 4", err)
	}
}

func TestReservationReplaced(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, &ServerConfig{MaxReservations: 1})
	tid := newID(t)
	first := reserve(t, r, tid, nil)
	second := reserve(t, r, tid, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := first.Accept(ctx)
	if code, ok := closeCode(err); !errors.Is(err, ErrReservationEnded) || !ok || code != codeReplaced {
		t.Fatalf("first Accept: %v, want ErrReservationEnded with code %d", err, codeReplaced)
	}
	ic := dial(t, r, newID(t), tid.PublicKey(), nil)
	serveEcho(accept(t, second))
	echo(t, ic, []byte("to the new one"))
}

func TestReservationLifetime(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, &ServerConfig{ReservationLifetime: 2 * time.Second})
	ic, _, res := pair(t, r, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := res.Accept(ctx)
	if code, ok := closeCode(err); !errors.Is(err, ErrReservationEnded) || !ok || code != codeLifetime {
		t.Fatalf("Accept: %v, want ErrReservationEnded with code %d", err, codeLifetime)
	}
	echo(t, ic, []byte("the session outlives its reservation"))
	if _, err := Dial(testCtx(t), r.addr, r.key, newID(t), ic.RemotePublicKey(), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Dial after the end: %v, want ErrUnavailable", err)
	}
}

func TestSessionLimits(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, &ServerConfig{MaxSessions: 2, MaxSessionsPerPeer: 1, MaxSessionsPerTarget: 1})
	a, b := newID(t), newID(t)
	resA := reserve(t, r, a, nil)
	reserve(t, r, b, nil)
	iid := newID(t)
	first := dial(t, r, iid, a.PublicKey(), nil)
	accept(t, resA)
	if _, err := Dial(testCtx(t), r.addr, r.key, iid, b.PublicKey(), nil); !errors.Is(err, ErrLimit) {
		t.Fatalf("second session of one peer: %v, want ErrLimit", err)
	}
	if _, err := Dial(testCtx(t), r.addr, r.key, newID(t), a.PublicKey(), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("second session to one target: %v, want ErrUnavailable", err)
	}
	first.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := Dial(testCtx(t), r.addr, r.key, iid, a.PublicKey(), nil)
		if err == nil {
			c.Close()
			break
		}
		if !errors.Is(err, ErrLimit) || time.Now().After(deadline) {
			t.Fatalf("slot not freed after Close: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestMaxSessions(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, &ServerConfig{MaxSessions: 1})
	a, b := newID(t), newID(t)
	resA := reserve(t, r, a, nil)
	reserve(t, r, b, nil)
	dial(t, r, newID(t), a.PublicKey(), nil)
	accept(t, resA)
	if _, err := Dial(testCtx(t), r.addr, r.key, newID(t), b.PublicKey(), nil); !errors.Is(err, ErrLimit) {
		t.Fatalf("over MaxSessions: %v, want ErrLimit", err)
	}
}

func TestMaxPending(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	tid := newID(t)
	reserve(t, r, tid, &Config{MaxPending: 1})
	dial(t, r, newID(t), tid.PublicKey(), nil)
	if _, err := Dial(testCtx(t), r.addr, r.key, newID(t), tid.PublicKey(), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("over MaxPending: %v, want ErrUnavailable", err)
	}
}

// sessionEndCode waits for c to end and checks the stream code the relay ended its session with.
func sessionEndCode(t *testing.T, c *Conn, within time.Duration, want uint64) {
	t.Helper()
	waitDone(t, c.Context(), within)
	if code, ok := closeCode(c.pc.Err()); !errors.Is(c.pc.Err(), kolotransport.ErrStreamReset) || !ok || code != want {
		t.Fatalf("relay stream ended with %v, want a reset with code %d", c.pc.Err(), want)
	}
}

func TestMaxSessionDuration(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, &ServerConfig{MaxSessionDuration: time.Second})
	ic, tc, _ := pair(t, r, nil)
	begin := time.Now()
	sessionEndCode(t, ic, 10*time.Second, splice.EndDuration)
	sessionEndCode(t, tc, 10*time.Second, splice.EndDuration)
	if d := time.Since(begin); d > 15*time.Second {
		t.Fatalf("session ended after %v, MaxSessionDuration is 1s", d)
	}
}

func TestMaxSessionBytes(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, &ServerConfig{MaxSessionBytes: 64 << 10})
	ic, _, _ := pair(t, r, nil)
	s, err := ic.OpenStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	s.SetWriteDeadline(time.Now().Add(20 * time.Second))
	go s.Write(make([]byte, 1<<20))
	sessionEndCode(t, ic, 20*time.Second, splice.EndBytes)
}

func TestSessionIdle(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, &ServerConfig{SessionIdleTimeout: time.Second})
	ic, _, _ := pair(t, r, nil)
	sessionEndCode(t, ic, 10*time.Second, splice.EndIdle)
}

func TestRate(t *testing.T) {
	checkGoroutines(t)
	const rateBytes, burst, total = 64 << 10, 16 << 10, 192 << 10
	r := startRelay(t, &ServerConfig{RateBytes: rateBytes, RateBurst: burst})
	ic, _, _ := pair(t, r, nil)
	begin := time.Now()
	echo(t, ic, make([]byte, total))
	min := time.Duration(float64(total-burst) / rateBytes * float64(time.Second))
	if d := time.Since(begin); d < min*9/10 {
		t.Fatalf("%d bytes each way in %v, faster than %d B/s", total, d, rateBytes)
	}
}

func TestControlTimeout(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, &ServerConfig{ControlTimeout: time.Second})
	c := rawClient(t, r)
	err := waitDone(t, c.Context(), 10*time.Second)
	if code, ok := closeCode(err); !ok || code != codeProtocol {
		t.Fatalf("silent client: %v, want code %d", err, codeProtocol)
	}
}

func TestConnectTimeout(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, &ServerConfig{ConnectTimeout: time.Second})
	target, key := rawClientID(t, r)
	if code := rawStatus(t, rawSend(t, target, wire.EncodeReserve(wire.Version0))); code != wire.StatusOK {
		t.Fatalf("Reserve status %d", code)
	}
	begin := time.Now()
	if _, err := Dial(testCtx(t), r.addr, r.key, newID(t), key, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Dial to a silent target: %v, want ErrUnavailable", err)
	}
	// The relay's deadline starts after the client began timing, so the answer cannot come sooner.
	if d := time.Since(begin); d < time.Second || d > 15*time.Second {
		t.Fatalf("Dial took %v, want the relay's ConnectTimeout of 1s", d)
	}
}

func TestProtocolViolations(t *testing.T) {
	checkGoroutines(t)
	// A long ControlTimeout, so every close below comes from the violation itself.
	r := startRelay(t, &ServerConfig{ControlTimeout: time.Minute})
	cases := map[string]func(c *kolosecure.Conn){
		"garbage": func(c *kolosecure.Conn) { rawSend(t, c, []byte{9, 9, 9}) },
		"status from client": func(c *kolosecure.Conn) {
			rawSend(t, c, wire.EncodeStatus(wire.StatusOK))
		},
		"second stream": func(c *kolosecure.Conn) {
			rawStatus(t, rawSend(t, c, wire.EncodeReserve(wire.Version0)))
			rawSend(t, c, wire.EncodeReserve(wire.Version0))
		},
		"bytes after Reserve": func(c *kolosecure.Conn) {
			st := rawSend(t, c, wire.EncodeReserve(wire.Version0))
			rawStatus(t, st)
			st.Write([]byte{0})
		},
		"uni stream": func(c *kolosecure.Conn) {
			rawStatus(t, rawSend(t, c, wire.EncodeReserve(wire.Version0)))
			rawUni(t, c)
		},
		"uni stream first": func(c *kolosecure.Conn) { rawUni(t, c) },
	}
	for name, f := range cases {
		c := rawClient(t, r)
		f(c)
		err := waitDone(t, c.Context(), 5*time.Second)
		if code, ok := closeCode(err); !ok || code != codeProtocol {
			t.Errorf("%s: %v, want code %d", name, err, codeProtocol)
		}
	}
}

func TestUnsupportedVersion(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	c := rawClient(t, r)
	if code := rawStatus(t, rawSend(t, c, []byte{1, 1})); code != wire.StatusUnsupportedVersion {
		t.Fatalf("status %d, want UnsupportedVersion", code)
	}
}

func TestServerClose(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	ic, tc, res := pair(t, r, nil)
	if err := r.s.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := res.Accept(ctx)
	if code, ok := closeCode(err); !errors.Is(err, ErrReservationEnded) || !ok || code != codeClosing {
		t.Fatalf("Accept after Server.Close: %v, want ErrReservationEnded with code %d", err, codeClosing)
	}
	waitDone(t, ic.Context(), 10*time.Second)
	waitDone(t, tc.Context(), 10*time.Second)
	if err := r.s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestReservationClose(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	ic, _, res := pair(t, r, nil)
	res.Close()
	if _, err := res.Accept(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Accept after Close: %v, want ErrClosed", err)
	}
	waitDone(t, ic.Context(), 10*time.Second)
	res.Close()
}

func TestConnCloseWithError(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	ic, tc, _ := pair(t, r, nil)
	ic.CloseWithError(42, "")
	err := waitDone(t, tc.Context(), 10*time.Second)
	if code, ok := closeCode(err); !errors.Is(err, kolotransport.ErrPeerClosed) || !ok || code != 42 {
		t.Fatalf("target saw %v, want the peer's code 42", err)
	}
}

func TestRelayThatNeverAnswers(t *testing.T) {
	checkGoroutines(t)
	id := newID(t)
	sl, err := kolosecure.Listen(testCtx(t), "127.0.0.1:0", id, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sl.Close()
	go func() {
		for {
			c, err := sl.Accept(context.Background())
			if err != nil {
				return
			}
			go c.AcceptStream(context.Background())
		}
	}()
	begin := time.Now()
	_, err = Reserve(testCtx(t), sl.Addr().String(), id.PublicKey(), newID(t), &Config{ControlTimeout: time.Second})
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Reserve: %v, want a deadline error", err)
	}
	if d := time.Since(begin); d > 15*time.Second {
		t.Fatalf("Reserve took %v with a 1s ControlTimeout", d)
	}
}

func TestSilentInitiatorFreesItsSlot(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	tid := newID(t)
	fast := &kolosecure.Config{HandshakeTimeout: time.Second, Transport: &kolotransport.Config{HandshakeTimeout: time.Second}}
	res := reserve(t, r, tid, &Config{MaxPending: 1, ControlTimeout: time.Second, Peer: fast})
	raw := rawClient(t, r)
	if code := rawStatus(t, rawSend(t, raw, wire.EncodeConnect(wire.Version0, tid.PublicKey()))); code != wire.StatusOK {
		t.Fatalf("Connect status %d", code)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		c, err := Dial(testCtx(t), r.addr, r.key, newID(t), tid.PublicKey(), nil)
		if err == nil {
			defer c.Close()
			break
		}
		if !errors.Is(err, ErrUnavailable) || time.Now().After(deadline) {
			t.Fatalf("slot of a silent initiator not freed: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	accept(t, res)
}

func rawUni(t *testing.T, c *kolosecure.Conn) {
	t.Helper()
	us, err := c.OpenUniStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := us.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
}

// relayFor returns a relay that lets many test peers in from 127.0.0.1.
func relayFor(t *testing.T, cfg ServerConfig) *testRelay {
	t.Helper()
	sec := relaySecure()
	sec.Transport.MaxConns, sec.Transport.MaxConnsPerIP = 32, 32
	cfg.Secure = sec
	return startRelay(t, &cfg)
}

func TestCloseCodeDuringTransfer(t *testing.T) {
	checkGoroutines(t)
	// A slow relay and a small queue keep the dialer's queue full, so the close must replace a queued packet; a
	// version 0 dialer puts every packet in that queue.
	r := relayFor(t, ServerConfig{RateBytes: 512 << 10, RateBurst: 16 << 10})
	tid, iid := newID(t), newID(t)
	res := reserve(t, r, tid, datagramClient())
	cfg := &Config{SendQueue: 8}
	ic := dial(t, r, iid, tid.PublicKey(), cfg)
	tc := accept(t, res)
	serveEcho(tc)
	s, err := ic.OpenStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	go s.Write(make([]byte, 4<<20))
	s.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(s, make([]byte, 256<<10)); err != nil {
		t.Fatalf("echo: %v", err)
	}
	if ic.pc.Dropped() == 0 {
		t.Fatal("the dialer's queue never filled; the test does not cover a full queue")
	}
	ic.CloseWithError(42, "")
	err = waitDone(t, tc.Context(), 10*time.Second)
	if code, ok := closeCode(err); !errors.Is(err, kolotransport.ErrPeerClosed) || !ok || code != 42 {
		t.Fatalf("target saw %v in the middle of a transfer, want the peer's code 42", err)
	}
}

func TestRefusedClientIsStopped(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, &ServerConfig{ControlTimeout: time.Minute})
	c := rawClient(t, r)
	st := rawSend(t, c, wire.EncodeConnect(wire.Version0, newID(t).PublicKey()))
	if code := rawStatus(t, st); code != wire.StatusUnavailable {
		t.Fatalf("status %d, want Unavailable", code)
	}
	st.SetWriteDeadline(time.Now().Add(10 * time.Second))
	begin := time.Now()
	var werr error
	for werr == nil && time.Since(begin) < 30*time.Second {
		_, werr = st.Write(make([]byte, 64<<10))
	}
	if !errors.Is(werr, kolotransport.ErrStreamReset) {
		t.Fatalf("writes after a refusal: %v, want the relay to stop the stream", werr)
	}
	if d := time.Since(begin); d > 15*time.Second {
		t.Fatalf("stopped after %v", d)
	}
}

func TestNoReservationOracle(t *testing.T) {
	checkGoroutines(t)
	r := relayFor(t, ServerConfig{MaxSessionsPerPeer: 1})
	a, b := newID(t), newID(t)
	resA := reserve(t, r, a, nil)
	reserve(t, r, b, &Config{AllowFunc: func(ed25519.PublicKey) bool { return false }})
	iid := newID(t)
	dial(t, r, iid, a.PublicKey(), nil)
	accept(t, resA)
	_, toB := Dial(testCtx(t), r.addr, r.key, iid, b.PublicKey(), nil)
	_, toNone := Dial(testCtx(t), r.addr, r.key, iid, newID(t).PublicKey(), nil)
	if toB == nil || toNone == nil || errors.Is(toB, ErrLimit) != errors.Is(toNone, ErrLimit) || errors.Is(toB, ErrUnavailable) != errors.Is(toNone, ErrUnavailable) {
		t.Fatalf("reserved target: %v; unreserved key: %v; want the same answer", toB, toNone)
	}
}

func TestEgressBound(t *testing.T) {
	checkGoroutines(t)
	const rateBytes, burst, total = 64 << 10, 16 << 10, 192 << 10
	r := startRelay(t, &ServerConfig{RateBytes: rateBytes, RateBurst: burst})
	ic, tc, _ := pair(t, r, nil)
	before := ic.pc.Received() + tc.pc.Received()
	begin := time.Now()
	echo(t, ic, make([]byte, total))
	d := time.Since(begin).Seconds()
	egress := float64(ic.pc.Received() + tc.pc.Received() - before)
	if bound := 2*rateBytes*d + 2*burst; egress > bound {
		t.Fatalf("relay sent %.0f bytes in %.2fs, above 2 × RateBytes × t + 2 × RateBurst = %.0f", egress, d, bound)
	}
	if egress < 2*total {
		t.Fatalf("relay sent %.0f bytes for a %d-byte echo, want at least both directions", egress, total)
	}
}

func TestSessionEndedDuringHandshake(t *testing.T) {
	checkGoroutines(t)
	f := startFake(t, fakeReset)
	r := f.relay()
	tid := newID(t)
	reserve(t, r, tid, nil)
	_, err := Dial(testCtx(t), r.addr, r.key, newID(t), tid.PublicKey(), nil)
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, context.Canceled) {
		t.Fatalf("Dial: %v, want ErrUnavailable and no context error", err)
	}
}

func TestRelayAddrIsCopied(t *testing.T) {
	checkGoroutines(t)
	r := relayFor(t, ServerConfig{})
	tid := newID(t)
	res := reserve(t, r, tid, nil)
	dial(t, r, newID(t), tid.PublicKey(), nil)
	first := accept(t, res)
	ua := first.RelayAddr().(*net.UDPAddr)
	ua.IP[0], ua.Port = 99, 1
	if first.RelayAddr().String() != r.addr {
		t.Fatalf("RelayAddr changed to %v", first.RelayAddr())
	}
	ic := dial(t, r, newID(t), tid.PublicKey(), nil)
	second := accept(t, res)
	serveEcho(second)
	echo(t, ic, []byte("still reachable"))
	if second.RelayAddr().String() != r.addr {
		t.Fatalf("second RelayAddr %v", second.RelayAddr())
	}
}

func TestServerCloseSessionCode(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	tid := newID(t)
	res := reserve(t, r, tid, nil)
	go func() {
		if c, err := res.Accept(context.Background()); err == nil {
			c.Close()
		}
	}()
	raw := rawClient(t, r)
	st := rawSend(t, raw, wire.EncodeConnect(wire.Version0, tid.PublicKey()))
	if code := rawStatus(t, st); code != wire.StatusOK {
		t.Fatalf("Connect status %d", code)
	}
	closed := make(chan struct{})
	go func() {
		r.s.Close()
		close(closed)
	}()
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err := io.ReadAll(st)
	if code, ok := closeCode(err); !errors.Is(err, kolotransport.ErrStreamReset) || !ok || code != splice.EndClosing {
		t.Fatalf("session stream after Server.Close: %v, want a reset with code %d", err, splice.EndClosing)
	}
	raw.Close()
	<-closed
}

func TestReservationCloseClosesConns(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	_, tc, res := pair(t, r, nil)
	res.Close()
	if tc.Context().Err() == nil {
		t.Fatal("a Conn of the reservation is still open after Close returned")
	}
}

func TestMITMForwardedProof(t *testing.T) {
	checkGoroutines(t)
	f := startFake(t, fakeForward)
	r := f.relay()
	tid := newID(t)
	reserve(t, r, tid, nil)
	_, err := Dial(testCtx(t), r.addr, r.key, newID(t), tid.PublicKey(), nil)
	if !errors.Is(err, kolosecure.ErrAuthentication) {
		t.Fatalf("Dial through a relay forwarding the target's proof: %v, want kolosecure.ErrAuthentication", err)
	}
}

func TestAllowConnectProtectsSessions(t *testing.T) {
	cases := map[string]struct {
		cfg        ServerConfig
		unreserved bool
	}{
		"MaxSessions":             {cfg: ServerConfig{MaxSessions: 2}},
		"MaxSessionsPerTarget":    {cfg: ServerConfig{MaxSessionsPerTarget: 2}},
		"unreserved, MaxSessions": {cfg: ServerConfig{MaxSessions: 2}, unreserved: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			good := newID(t)
			cfg := tc.cfg
			cfg.ControlTimeout = time.Minute
			if !tc.unreserved {
				cfg.AllowConnect = func(from, _ ed25519.PublicKey) bool { return bytes.Equal(from, good.PublicKey()) }
			}
			r := relayFor(t, cfg)
			tid := newID(t)
			res := reserve(t, r, tid, nil)
			for range 2 {
				// Refused clients that keep their connection open must not keep a session slot.
				target := tid.PublicKey()
				if tc.unreserved {
					target = newID(t).PublicKey()
				}
				raw := rawClient(t, r)
				if code := rawStatus(t, rawSend(t, raw, wire.EncodeConnect(wire.Version0, target))); code != wire.StatusUnavailable {
					t.Fatalf("refused client got status %d, want Unavailable", code)
				}
			}
			dial(t, r, good, tid.PublicKey(), nil)
			accept(t, res)
		})
	}
}

func TestServerCloseDuringAnnounce(t *testing.T) {
	checkGoroutines(t)
	r := relayFor(t, ServerConfig{ConnectTimeout: 30 * time.Second})
	target, key := rawClientID(t, r)
	if code := rawStatus(t, rawSend(t, target, wire.EncodeReserve(wire.Version0))); code != wire.StatusOK {
		t.Fatalf("Reserve status %d", code)
	}
	initiator := rawClient(t, r)
	st := rawSend(t, initiator, wire.EncodeConnect(wire.Version0, key))
	// The relay has announced the session once the target sees its stream, and the target never answers.
	if _, err := target.AcceptStream(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	r.s.Close()
	if d := time.Since(begin); d > 15*time.Second {
		t.Fatalf("Server.Close took %v while a target did not answer", d)
	}
	// The Connect being set up must learn that the relay closed: stream code 5 or connection code 4.
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err := io.ReadAll(st)
	code, ok := closeCode(err)
	switch {
	case errors.Is(err, kolotransport.ErrStreamReset) && ok && code == splice.EndClosing:
	case errors.Is(err, kolotransport.ErrPeerClosed) && ok && code == codeClosing:
	default:
		t.Fatalf("Connect during Server.Close ended with %v, want stream code %d or connection code %d", err, splice.EndClosing, codeClosing)
	}
}

func TestAllowConnectNoOracle(t *testing.T) {
	cases := map[string]struct {
		cfg  ServerConfig
		want uint64
	}{
		"MaxSessions":        {ServerConfig{MaxSessions: 1}, wire.StatusLimit},
		"MaxSessionsPerPeer": {ServerConfig{MaxSessionsPerPeer: 1}, wire.StatusLimit},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			a, tid, k1, k2 := newID(t), newID(t), newID(t), newID(t)
			allowed := map[string]bool{string(tid.PublicKey()): true, string(k1.PublicKey()): true}
			cfg := tc.cfg
			cfg.AllowConnect = func(from, to ed25519.PublicKey) bool {
				return bytes.Equal(from, a.PublicKey()) && allowed[string(to)]
			}
			r := relayFor(t, cfg)
			res := reserve(t, r, tid, nil)
			dial(t, r, a, tid.PublicKey(), nil)
			accept(t, res)
			toK1, toK2 := rawConnect(t, r, a, k1.PublicKey()), rawConnect(t, r, a, k2.PublicKey())
			if toK1 != tc.want || toK2 != tc.want {
				t.Fatalf("at its limit, A gets %d for an allowed key and %d for a denied one, want %d for both", toK1, toK2, tc.want)
			}
		})
	}
	t.Run("MaxSessionsPerTarget", func(t *testing.T) {
		checkGoroutines(t)
		a, b, tid, t2 := newID(t), newID(t), newID(t), newID(t)
		r := relayFor(t, ServerConfig{MaxSessionsPerTarget: 1, AllowConnect: func(from, to ed25519.PublicKey) bool {
			return !bytes.Equal(to, t2.PublicKey())
		}})
		res := reserve(t, r, tid, nil)
		reserve(t, r, t2, nil)
		dial(t, r, a, tid.PublicKey(), nil)
		accept(t, res)
		full, denied, none := rawConnect(t, r, b, tid.PublicKey()), rawConnect(t, r, b, t2.PublicKey()), rawConnect(t, r, b, newID(t).PublicKey())
		if full != wire.StatusUnavailable || denied != wire.StatusUnavailable || none != wire.StatusUnavailable {
			t.Fatalf("full target %d, denied target %d, unreserved key %d; want Unavailable for all", full, denied, none)
		}
	})
	t.Run("limit filled during AllowConnect", func(t *testing.T) {
		checkGoroutines(t)
		a, b, tid, k1, k2 := newID(t), newID(t), newID(t), newID(t), newID(t)
		release := make(chan struct{})
		entered := make(chan struct{}, 2)
		r := relayFor(t, ServerConfig{MaxSessions: 1, AllowConnect: func(from, to ed25519.PublicKey) bool {
			if bytes.Equal(from, b.PublicKey()) {
				entered <- struct{}{}
				<-release
				return bytes.Equal(to, k1.PublicKey())
			}
			return true
		}})
		var once sync.Once
		free := func() { once.Do(func() { close(release) }) }
		t.Cleanup(free)
		res := reserve(t, r, tid, nil)
		var sts []*kolotransport.Stream
		for _, to := range []ed25519.PublicKey{k1.PublicKey(), k2.PublicKey()} {
			c, err := kolosecure.Dial(testCtx(t), r.addr, b, r.key, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close() })
			sts = append(sts, rawSend(t, c, wire.EncodeConnect(wire.Version0, to)))
			<-entered
		}
		dial(t, r, a, tid.PublicKey(), nil)
		accept(t, res)
		free()
		if allowed, denied := rawStatus(t, sts[0]), rawStatus(t, sts[1]); allowed != wire.StatusLimit || denied != wire.StatusLimit {
			t.Fatalf("the relay filled during AllowConnect: allowed key %d, denied key %d, want Limit for both", allowed, denied)
		}
	})
}

// rawConnect sends Connect(target) as id on a new connection and returns the relay's status.
func rawConnect(t *testing.T, r *testRelay, id *koloid.Identity, target ed25519.PublicKey) uint64 {
	t.Helper()
	c, err := kolosecure.Dial(testCtx(t), r.addr, id, r.key, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return rawStatus(t, rawSend(t, c, wire.EncodeConnect(wire.Version0, target)))
}

func TestDeniedKeyLearnsFullRelay(t *testing.T) {
	checkGoroutines(t)
	a, outsider, tid := newID(t), newID(t), newID(t)
	r := relayFor(t, ServerConfig{MaxSessions: 1, AllowConnect: func(from, _ ed25519.PublicKey) bool {
		return bytes.Equal(from, a.PublicKey())
	}})
	res := reserve(t, r, tid, nil)
	if got := rawConnect(t, r, outsider, tid.PublicKey()); got != wire.StatusUnavailable {
		t.Fatalf("denied key on an empty relay: %d, want Unavailable", got)
	}
	ic := dial(t, r, a, tid.PublicKey(), nil)
	accept(t, res)
	if got := rawConnect(t, r, outsider, tid.PublicKey()); got != wire.StatusLimit {
		t.Fatalf("denied key on a full relay: %d, want Limit (documented: ErrLimit tells any key the relay is full)", got)
	}
	ic.Close()
}

func TestSlowAllowConnectHoldsNoSlot(t *testing.T) {
	for name, cfg := range map[string]ServerConfig{
		"MaxSessions":          {MaxSessions: 1},
		"MaxSessionsPerTarget": {MaxSessionsPerTarget: 1},
	} {
		t.Run(name, func(t *testing.T) {
			checkGoroutines(t)
			good, bad, tid := newID(t), newID(t), newID(t)
			release := make(chan struct{})
			called := make(chan struct{}, 1)
			cfg.AllowConnect = func(from, _ ed25519.PublicKey) bool {
				if bytes.Equal(from, bad.PublicKey()) {
					called <- struct{}{}
					<-release
					return false
				}
				return true
			}
			r := relayFor(t, cfg)
			// Cleanups run last first: release the blocked call before the relay closes, since Close waits for it.
			t.Cleanup(func() { close(release) })
			res := reserve(t, r, tid, nil)
			c, err := kolosecure.Dial(testCtx(t), r.addr, bad, r.key, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close() })
			rawSend(t, c, wire.EncodeConnect(wire.Version0, tid.PublicKey()))
			<-called
			dial(t, r, good, tid.PublicKey(), nil)
			accept(t, res)
		})
	}
}

func TestCloseCodePaths(t *testing.T) {
	t.Run("Connect after closing", func(t *testing.T) {
		checkGoroutines(t)
		var asked atomic.Bool
		r := relayFor(t, ServerConfig{AllowConnect: func(_, _ ed25519.PublicKey) bool {
			asked.Store(true)
			return true
		}})
		tid := newID(t)
		reserve(t, r, tid, nil)
		arrived := make(chan struct{})
		hookAt(t, r.s, "connect", func() {
			close(arrived)
			untilClosing(r.s)
		})
		raw := rawClient(t, r)
		st := rawSend(t, raw, wire.EncodeConnect(wire.Version0, tid.PublicKey()))
		<-arrived
		closed := make(chan struct{})
		go func() {
			r.s.Close()
			close(closed)
		}()
		relayClosed(t, "a Connect that arrived while closing", closeCodeOf(t, st))
		<-closed
		if asked.Load() {
			t.Fatal("a Connect that arrived while closing reached AllowConnect")
		}
	})
	t.Run("Connect OK cut short", func(t *testing.T) {
		checkGoroutines(t)
		r := relayFor(t, ServerConfig{})
		target, key := rawClientID(t, r)
		if code := rawStatus(t, rawSend(t, target, wire.EncodeReserve(wire.Version0))); code != wire.StatusOK {
			t.Fatalf("Reserve status %d", code)
		}
		incoming := make(chan *kolotransport.Stream, 1)
		go func() {
			ts, err := target.AcceptStream(context.Background())
			if err != nil {
				return
			}
			wire.ReadMessage(ts)
			wire.WriteMessage(ts, wire.EncodeStatus(wire.StatusOK))
			incoming <- ts
		}()
		arrived := make(chan struct{})
		targetRead := make(chan error, 1)
		hook := func(p string) {
			switch p {
			case "session-accept":
				close(arrived)
				<-r.s.sessCtx.Done()
			case "close-conns":
				// Keep the target's connection open until it has read its stream's end code.
				select {
				case <-targetRead:
				case <-time.After(5 * time.Second):
				}
			}
		}
		r.s.hook.Store(&hook)
		t.Cleanup(func() { r.s.hook.Store(nil) })
		raw := rawClient(t, r)
		st := rawSend(t, raw, wire.EncodeConnect(wire.Version0, key))
		<-arrived
		ts := <-incoming
		go r.s.Close()
		err := closeCodeOf(t, ts)
		targetRead <- err
		if code, ok := closeCode(err); !errors.Is(err, kolotransport.ErrStreamReset) || !ok || code != splice.EndClosing {
			t.Fatalf("the target's session stream ended with %v, want a reset with code %d", err, splice.EndClosing)
		}
		relayClosed(t, "the initiator's Connect", closeCodeOf(t, st))
	})
	t.Run("Reserve cut short", func(t *testing.T) {
		checkGoroutines(t)
		r := relayFor(t, ServerConfig{})
		arrived := make(chan struct{})
		hookAt(t, r.s, "reserve-accept", func() {
			close(arrived)
			<-r.s.sessCtx.Done()
		})
		raw := rawClient(t, r)
		st := rawSend(t, raw, wire.EncodeReserve(wire.Version0))
		<-arrived
		go r.s.Close()
		relayClosed(t, "a Reserve being set up", closeCodeOf(t, st))
	})
	t.Run("refusal cut short", func(t *testing.T) {
		checkGoroutines(t)
		r := relayFor(t, ServerConfig{})
		arrived := make(chan struct{})
		hookAt(t, r.s, "refuse", func() {
			close(arrived)
			<-r.s.sessCtx.Done()
		})
		raw := rawClient(t, r)
		st := rawSend(t, raw, wire.EncodeConnect(wire.Version0, newID(t).PublicKey()))
		<-arrived
		go r.s.Close()
		relayClosed(t, "a refusal", closeCodeOf(t, st))
	})
}

func TestAdoptDoesNotHoldTheLock(t *testing.T) {
	r := &Reservation{conns: make(map[*Conn]struct{}), closing: true}
	dropping := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.adopt(func() *Conn { t.Error("adopted while closing"); return nil }, func() {
			close(dropping)
			time.Sleep(500 * time.Millisecond)
		})
	}()
	<-dropping
	begin := time.Now()
	r.mu.Lock()
	d := time.Since(begin)
	r.mu.Unlock()
	if d > 400*time.Millisecond { // the refused handshake holds out for 500ms
		t.Fatalf("another Conn's release waited %v for a refused handshake to close", d)
	}
	<-done
}

func TestForwardedProofThenEnd(t *testing.T) {
	checkGoroutines(t)
	f := startFake(t, fakeForwardEnd)
	r := f.relay()
	tid := newID(t)
	reserve(t, r, tid, nil)
	for i := range 20 {
		_, err := Dial(testCtx(t), r.addr, r.key, newID(t), tid.PublicKey(), nil)
		if !errors.Is(err, kolosecure.ErrAuthentication) {
			t.Fatalf("round %d: %v, want kolosecure.ErrAuthentication even though the stream ended", i, err)
		}
	}
}

func TestBucketChurn(t *testing.T) {
	checkGoroutines(t)
	const rateBytes, burst, each, sessions = 64 << 10, 64 << 10, 16 << 10, 20
	r := relayFor(t, ServerConfig{RateBytes: rateBytes, RateBurst: burst})
	target, key := rawClientID(t, r)
	if code := rawStatus(t, rawSend(t, target, wire.EncodeReserve(wire.Version0))); code != wire.StatusOK {
		t.Fatalf("Reserve status %d", code)
	}
	got := make(chan int64, 1)
	go func() {
		for {
			ts, err := target.AcceptStream(context.Background())
			if err != nil {
				return
			}
			if _, err := wire.ReadMessage(ts); err != nil {
				return
			}
			wire.WriteMessage(ts, wire.EncodeStatus(wire.StatusOK))
			ts.SetReadDeadline(time.Now().Add(20 * time.Second))
			n, _ := io.Copy(io.Discard, ts)
			ts.Close()
			got <- n
		}
	}()
	begin := time.Now()
	var total int64
	for range sessions {
		raw := rawClient(t, r)
		st := rawSend(t, raw, wire.EncodeConnect(wire.Version0, key))
		if code := rawStatus(t, st); code != wire.StatusOK {
			t.Fatalf("Connect status %d", code)
		}
		st.Write(make([]byte, each))
		st.Close()
		select {
		case n := <-got:
			total += n
		case <-time.After(20 * time.Second):
			t.Fatal("target never got the session's bytes")
		}
		raw.Close()
	}
	d := time.Since(begin).Seconds()
	if total != each*sessions {
		t.Fatalf("target got %d bytes, want %d", total, each*sessions)
	}
	// Sessions run one after another, so one initiator bucket at a time paces this direction.
	if bound := 1.25*rateBytes*d + 16<<10; float64(total) > bound {
		t.Fatalf("%d bytes in %.2fs through new sessions, above RateBytes × t (%.0f with margin): new buckets must start empty", total, d, bound)
	}
}

func TestReservationCloseSendsCode0(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	ic, _, res := pair(t, r, nil)
	res.Close()
	err := waitDone(t, ic.Context(), 10*time.Second)
	if code, ok := closeCode(err); !errors.Is(err, kolotransport.ErrPeerClosed) || !ok || code != 0 {
		t.Fatalf("initiator saw %v after the target's Reservation.Close, want the peer's code 0", err)
	}
}

func TestDialErr(t *testing.T) {
	live := context.Background()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	ended := kolotransport.ErrStreamReset
	cases := []struct {
		name      string
		ctx, hctx context.Context
		end, err  error
		want      error
	}{
		{"session ended, handshake canceled", live, canceled, ended, context.Canceled, ErrUnavailable},
		{"session ended after a failed proof", live, canceled, ended, kolosecure.ErrAuthentication, kolosecure.ErrAuthentication},
		{"session ended after a wrong key", live, canceled, ended, kolosecure.ErrUnexpectedPeer, kolosecure.ErrUnexpectedPeer},
		{"failed proof, session open", live, live, nil, kolosecure.ErrAuthentication, kolosecure.ErrAuthentication},
		{"caller canceled", canceled, canceled, ended, context.Canceled, context.Canceled},
		{"handshake not canceled", live, live, ended, context.Canceled, context.Canceled},
	}
	for _, c := range cases {
		got := dialErr(c.ctx, c.hctx, c.end, c.err)
		if !errors.Is(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
		if c.want != ErrUnavailable && errors.Is(got, ErrUnavailable) {
			t.Errorf("%s: %v must not be ErrUnavailable", c.name, got)
		}
	}
}

// endedStream is a session stream the relay has already ended.
type endedStream struct{}

func (endedStream) Read([]byte) (int, error)         { return 0, io.EOF }
func (endedStream) Write(p []byte) (int, error)      { return len(p), nil }
func (endedStream) Close() error                     { return nil }
func (endedStream) CancelRead(uint64) error          { return nil }
func (endedStream) CancelWrite(uint64) error         { return nil }
func (endedStream) SetWriteDeadline(time.Time) error { return nil }

func TestEndWithGrace(t *testing.T) {
	checkGoroutines(t)
	pc := pconn.New(endedStream{}, &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 1}, &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 2}, 8, nil)
	defer pc.Close()
	<-pc.Done()
	ctx, cancel := endWith(context.Background(), pc)
	defer cancel()
	select {
	case <-ctx.Done():
		t.Fatal("the handshake context ended with the stream; packets that came first would not be handled")
	case <-time.After(endGrace / 2):
	}
	select {
	case <-ctx.Done():
	case <-time.After(endGrace + time.Second):
		t.Fatal("the handshake context never ended after the stream")
	}
}

func TestIPv6Refused(t *testing.T) {
	checkGoroutines(t)
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	port := strconv.Itoa(sink.LocalAddr().(*net.UDPAddr).Port)
	ctx := testCtx(t)
	id, relayKey := newID(t), newID(t).PublicKey()
	for _, host := range []string{"::1", "::ffff:127.0.0.1", "::"} {
		addr := net.JoinHostPort(host, port)
		calls := map[string]func() error{
			"Dial":    func() error { _, err := Dial(ctx, addr, relayKey, id, newID(t).PublicKey(), nil); return err },
			"Reserve": func() error { _, err := Reserve(ctx, addr, relayKey, id, nil); return err },
			"Listen": func() error {
				s, err := Listen(ctx, net.JoinHostPort(host, "0"), id, nil)
				if err == nil {
					s.Close()
				}
				return err
			},
		}
		for name, f := range calls {
			if err := f(); !errors.Is(err, ErrInvalidArgument) || !strings.HasPrefix(err.Error(), "kolorelay: ") || !strings.Contains(err.Error(), "IPv6") {
				t.Errorf("%s %s: %v, want ErrInvalidArgument naming IPv6", name, addr, err)
			}
		}
	}
	sink.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, _, err := sink.ReadFrom(make([]byte, 1500)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a packet reached the refused address: %v", err)
	}
}

func TestRelayAddrIsIPv4(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	ic, tc, _ := pair(t, r, nil)
	for name, c := range map[string]*Conn{"initiator": ic, "target": tc} {
		ua := c.RelayAddr().(*net.UDPAddr)
		if len(ua.IP) != net.IPv4len || ua.String() != r.addr {
			t.Errorf("%s RelayAddr %v (%d-byte IP), want %s as a 4-byte IPv4", name, ua, len(ua.IP), r.addr)
		}
	}
	echo(t, ic, []byte("plain IPv4"))
}

func TestPlainIPv4(t *testing.T) {
	got, ok := plainIPv4(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7})
	if !ok {
		t.Fatal("plainIPv4 refused a 16-byte IPv4 address")
	}
	if len(got.IP) != net.IPv4len || got.String() != "127.0.0.1:7" {
		t.Fatalf("plainIPv4 = %v (%d-byte IP), want 127.0.0.1:7 as a 4-byte IPv4", got, len(got.IP))
	}
	if got, ok := plainIPv4(&net.UDPAddr{IP: net.IPv6loopback, Port: 7}); ok {
		t.Fatalf("plainIPv4 accepted IPv6 as %v", got)
	}
}

func TestKeepAliveAlwaysOn(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, &ServerConfig{SessionIdleTimeout: 2 * time.Second})
	short := func() *kolosecure.Config {
		return &kolosecure.Config{Transport: &kolotransport.Config{IdleTimeout: 2 * time.Second}}
	}
	cfg := &Config{Relay: short(), Peer: short()}
	tid := newID(t)
	res := reserve(t, r, tid, cfg)
	ic := dial(t, r, newID(t), tid.PublicKey(), cfg)
	serveEcho(accept(t, res))
	select {
	case <-ic.Context().Done():
		t.Fatalf("an idle session ended: %v", context.Cause(ic.Context()))
	case <-time.After(3 * time.Second):
	}
	echo(t, ic, []byte("still up"))
	again := dial(t, r, newID(t), tid.PublicKey(), cfg)
	serveEcho(accept(t, res))
	echo(t, again, []byte("reservation still up"))
}

// A Dial with the default ControlTimeout waits for a target that answers after the relay's default ConnectTimeout.
// The relay here waits longer than the default, so its deadline, which starts before the target hears of the
// connection, is not part of the race: the margin is the 5s between the two defaults.
func TestDialOutlastsConnectTimeout(t *testing.T) {
	checkGoroutines(t)
	srv, err := (&ServerConfig{}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := (&Config{}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	// AllowConnect takes 100ms, as a lookup elsewhere might.
	r := relayFor(t, ServerConfig{ConnectTimeout: time.Minute, AllowConnect: func(_, _ ed25519.PublicKey) bool {
		time.Sleep(100 * time.Millisecond)
		return true
	}})
	tid := newID(t)
	rc, err := kolosecure.Dial(testCtx(t), r.addr, tid, r.key, cfg.Relay)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rc.Close() })
	if code := rawStatus(t, rawSend(t, rc, wire.EncodeReserve(wire.Version0))); code != wire.StatusOK {
		t.Fatalf("Reserve status %d", code)
	}
	relay, local, err := relayAddrs(rc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// A target that answers when the default ConnectTimeout has passed, then runs the real handshake.
	res := &Reservation{rc: rc, id: tid, cfg: cfg, relayKey: r.key, relay: relay, local: local, ctx: ctx, cancel: cancel,
		closed: make(chan struct{}), conns: make(map[*Conn]struct{})}
	got := make(chan *Conn, 1)
	go func() {
		ts, err := rc.AcceptStream(ctx)
		if err != nil {
			got <- nil
			return
		}
		body, err := wire.ReadMessage(ts)
		m, derr := wire.Decode(body)
		if err != nil || derr != nil {
			got <- nil
			return
		}
		time.Sleep(srv.ConnectTimeout)
		if wire.WriteMessage(ts, wire.EncodeStatus(wire.StatusOK)) != nil || !res.addActive() {
			got <- nil
			return
		}
		got <- res.handshake(pconn.New(ts, cloneUDP(local), cloneUDP(relay), cfg.SendQueue, nil), m.Key)
	}()
	dctx, dcancel := context.WithTimeout(context.Background(), time.Minute)
	defer dcancel()
	c, err := Dial(dctx, r.addr, r.key, newID(t), tid.PublicKey(), nil)
	if err != nil {
		t.Fatalf("Dial to a target that answers %v after the announce: %v", srv.ConnectTimeout, err)
	}
	c.Close()
	if tc := <-got; tc != nil {
		tc.Close()
	}
}

// securePair returns a client connection and the server's end of it, from a listener of the test's own.
func securePair(t *testing.T) (client, server *kolosecure.Conn) {
	t.Helper()
	id := newID(t)
	l, err := kolosecure.Listen(testCtx(t), "127.0.0.1:0", id, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	accepted := make(chan *kolosecure.Conn, 1)
	go func() {
		if c, err := l.Accept(testCtx(t)); err == nil {
			accepted <- c
		}
	}()
	client, err = kolosecure.Dial(testCtx(t), l.Addr().String(), newID(t), id.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server = <-accepted
	t.Cleanup(func() { server.Close() })
	return client, server
}

// A key that is not 32 bytes would make every such client the one zero key, sharing a reservation and a session count:
// the relay ends the connection instead. kolo-secure and the wire decoder only give 32 bytes today, so the checks are
// called with the key they would see otherwise.
func TestAKeyOfTheWrongLengthEndsTheConnection(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	wantClosed := func(t *testing.T, client *kolosecure.Conn) {
		t.Helper()
		_, err := client.AcceptStream(testCtx(t))
		if code, ok := closeCode(err); !ok || code != codeProtocol {
			t.Fatalf("the connection ended with %v, want a close with code %d", err, codeProtocol)
		}
	}
	t.Run("serve", func(t *testing.T) {
		client, server := securePair(t)
		go r.s.serveAs(server, make([]byte, 31))
		wantClosed(t, client)
	})
	t.Run("connect", func(t *testing.T) {
		client, server := securePair(t)
		rawSend(t, client, wire.EncodeConnect(wire.Version0, make([]byte, 32)))
		sst, err := server.AcceptStream(testCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		go r.s.connect(&caller{conn: server, st: sst, key: limits.Key{1}}, make([]byte, 31))
		wantClosed(t, client)
	})
}

// A Peer config sized for the application's own listener, as kolo-swarm passes it, still makes relayed sessions.
func TestPeerMaxPendingAboveOne(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	ic, _, _ := pair(t, r, &Config{Peer: &kolosecure.Config{MaxPending: 16}})
	echo(t, ic, []byte("a session with the application's MaxPending"))
}
