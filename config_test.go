package kolorelay

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"math"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func TestServerConfigDefaults(t *testing.T) {
	for _, cfg := range []*ServerConfig{nil, {}} {
		c, err := cfg.withDefaults()
		if err != nil {
			t.Fatal(err)
		}
		want := ServerConfig{
			MaxReservations:      64,
			MaxSessions:          16,
			MaxSessionsPerPeer:   4,
			MaxSessionsPerTarget: 8,
			ReservationLifetime:  time.Hour,
			MaxSessionDuration:   time.Hour,
			MaxSessionBytes:      1 << 30,
			SessionIdleTimeout:   time.Minute,
			ConnectTimeout:       15 * time.Second,
			ControlTimeout:       15 * time.Second,
			RateBytes:            1 << 20,
			RateBurst:            256 << 10,
			FlushInterval:        time.Millisecond,
		}
		if c.AllowReserve != nil || c.AllowConnect != nil {
			t.Fatal("allow funcs set by default")
		}
		if !reflect.DeepEqual(c.Secure, relaySecure()) {
			t.Fatalf("Secure %+v, want the relay defaults", c.Secure)
		}
		wantT := kolotransport.Config{
			MaxConns:               128,
			MaxConnsPerIP:          4,
			MaxDialed:              1,
			MaxIncomingStreams:     2,
			MaxStreamReceiveWindow: 64 << 10,
			MaxConnReceiveWindow:   256 << 10,
			Datagrams:              true,
		}
		if got := *c.Secure.Transport; !reflect.DeepEqual(got, wantT) || c.Secure.HandshakeTimeout != 0 || c.Secure.MaxPending != 0 {
			t.Fatalf("relay listener %+v, transport %+v, want transport %+v", c.Secure, got, wantT)
		}
		c.Secure = nil
		if !reflect.DeepEqual(c, want) {
			t.Fatalf("defaults\n got %+v\nwant %+v", c, want)
		}
	}
}

func TestServerConfigPerPeerDefaultsFollowMaxSessions(t *testing.T) {
	for _, c := range []struct{ sessions, peer, target int }{{1, 1, 1}, {2, 2, 2}, {6, 4, 6}, {16, 4, 8}, {10000, 4, 8}} {
		got, err := (&ServerConfig{MaxSessions: c.sessions}).withDefaults()
		if err != nil {
			t.Fatal(err)
		}
		if got.MaxSessionsPerPeer != c.peer || got.MaxSessionsPerTarget != c.target {
			t.Errorf("MaxSessions %d: per peer %d, per target %d, want %d and %d", c.sessions, got.MaxSessionsPerPeer, got.MaxSessionsPerTarget, c.peer, c.target)
		}
	}
}

func TestServerConfigRanges(t *testing.T) {
	cases := []struct {
		name string
		cfg  ServerConfig
	}{
		{"MaxReservations", ServerConfig{MaxReservations: 100001}},
		{"MaxReservations", ServerConfig{MaxReservations: -1}},
		{"MaxSessions", ServerConfig{MaxSessions: 10001}},
		{"MaxSessionsPerPeer", ServerConfig{MaxSessions: 4, MaxSessionsPerPeer: 5}},
		{"MaxSessionsPerTarget", ServerConfig{MaxSessions: 4, MaxSessionsPerTarget: 5}},
		{"MaxSessionsPerPeer", ServerConfig{MaxSessionsPerPeer: -1}},
		{"ReservationLifetime", ServerConfig{ReservationLifetime: time.Millisecond}},
		{"ReservationLifetime", ServerConfig{ReservationLifetime: 25 * time.Hour}},
		{"MaxSessionDuration", ServerConfig{MaxSessionDuration: 999 * time.Millisecond}},
		{"MaxSessionDuration", ServerConfig{MaxSessionDuration: 25 * time.Hour}},
		{"MaxSessionBytes", ServerConfig{MaxSessionBytes: 64<<10 - 1}},
		{"MaxSessionBytes", ServerConfig{MaxSessionBytes: 1<<40 + 1}},
		{"SessionIdleTimeout", ServerConfig{SessionIdleTimeout: 11 * time.Minute}},
		{"ConnectTimeout", ServerConfig{ConnectTimeout: 61 * time.Second}},
		{"ControlTimeout", ServerConfig{ControlTimeout: -time.Second}},
		{"RateBytes", ServerConfig{RateBytes: 16<<10 - 1}},
		{"RateBytes", ServerConfig{RateBytes: 1<<30 + 1}},
		{"RateBurst", ServerConfig{RateBurst: 16<<10 - 1}},
		{"RateBurst", ServerConfig{RateBurst: 64<<20 + 1}},
		{"RateBurst", ServerConfig{RateBurst: math.MaxInt64}},
		{"FlushInterval", ServerConfig{FlushInterval: 99 * time.Microsecond}},
		{"FlushInterval", ServerConfig{FlushInterval: 100*time.Millisecond + 1}},
		{"FlushInterval", ServerConfig{FlushInterval: -time.Millisecond}},
	}
	for _, c := range cases {
		_, err := c.cfg.withDefaults()
		if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), c.name) {
			t.Errorf("%+v: got %v, want ErrInvalidConfig naming %s", c.cfg, err, c.name)
		}
	}
}

func TestServerConfigBounds(t *testing.T) {
	low := ServerConfig{
		MaxReservations: 1, MaxSessions: 1, MaxSessionsPerPeer: 1, MaxSessionsPerTarget: 1,
		ReservationLifetime: time.Second, MaxSessionDuration: time.Second, MaxSessionBytes: 64 << 10,
		SessionIdleTimeout: time.Second, ConnectTimeout: time.Second, ControlTimeout: time.Second,
		RateBytes: 16 << 10, RateBurst: 16 << 10, FlushInterval: 100 * time.Microsecond,
	}
	high := ServerConfig{
		MaxReservations: 100000, MaxSessions: 10000, MaxSessionsPerPeer: 10000, MaxSessionsPerTarget: 10000,
		ReservationLifetime: 24 * time.Hour, MaxSessionDuration: 24 * time.Hour, MaxSessionBytes: 1 << 40,
		SessionIdleTimeout: 10 * time.Minute, ConnectTimeout: time.Minute, ControlTimeout: time.Minute,
		RateBytes: 1 << 30, RateBurst: 64 << 20, FlushInterval: 100 * time.Millisecond,
	}
	for _, cfg := range []ServerConfig{low, high} {
		got, err := cfg.withDefaults()
		if err != nil {
			t.Fatalf("%+v: %v", cfg, err)
		}
		got.Secure = nil
		if !reflect.DeepEqual(got, cfg) {
			t.Fatalf("changed a valid config:\n got %+v\nwant %+v", got, cfg)
		}
	}
}

func TestServerConfigKeepsAllowFuncs(t *testing.T) {
	called := 0
	cfg := &ServerConfig{
		AllowReserve: func(ed25519.PublicKey) bool { called++; return true },
		AllowConnect: func(from, to ed25519.PublicKey) bool { called++; return true },
	}
	c, err := cfg.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	c.AllowReserve(nil)
	c.AllowConnect(nil, nil)
	if called != 2 {
		t.Fatal("allow funcs not kept")
	}
}

func TestServerConfigInternal(t *testing.T) {
	c, err := (&ServerConfig{}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	l := c.tableConfig()
	if l.MaxReservations != 64 || l.MaxSessions != 16 || l.MaxSessionsPerPeer != 4 || l.MaxSessionsPerTarget != 8 {
		t.Fatalf("table config %+v", l)
	}
	s := c.spliceLimits()
	if s.MaxDuration != time.Hour || s.MaxBytes != 1<<30 || s.Idle != time.Minute || s.Flush != time.Millisecond {
		t.Fatalf("splice limits %+v", s)
	}
}

func TestConfigDefaultsAndRanges(t *testing.T) {
	for _, cfg := range []*Config{nil, {}} {
		c, err := cfg.withDefaults()
		if err != nil {
			t.Fatal(err)
		}
		if c.MaxPending != 16 || c.SendQueue != 512 || c.ControlTimeout != 20*time.Second || c.AllowFunc != nil || c.Peer != nil {
			t.Fatalf("defaults %+v", c)
		}
		if c.Relay == nil || c.Relay.Transport == nil || c.Relay.Transport.KeepAlivePeriod != 5*time.Second {
			t.Fatalf("Relay default %+v, want a 5s keep-alive", c.Relay)
		}
	}
	for _, cfg := range []Config{{MaxPending: 1, SendQueue: 8}, {MaxPending: 256, SendQueue: 1024}} {
		if c, err := cfg.withDefaults(); err != nil || c.MaxPending != cfg.MaxPending || c.SendQueue != cfg.SendQueue {
			t.Fatalf("%+v: %+v %v", cfg, c, err)
		}
	}
	cases := []struct {
		name string
		cfg  Config
	}{
		{"MaxPending", Config{MaxPending: 257}},
		{"MaxPending", Config{MaxPending: -1}},
		{"SendQueue", Config{SendQueue: 7}},
		{"SendQueue", Config{SendQueue: 1025}},
		{"ControlTimeout", Config{ControlTimeout: 999 * time.Millisecond}},
		{"ControlTimeout", Config{ControlTimeout: 61 * time.Second}},
	}
	for _, c := range cases {
		if _, err := c.cfg.withDefaults(); !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), c.name) {
			t.Errorf("%+v: got %v", c.cfg, err)
		}
	}
}

func TestServerConfigSecureKept(t *testing.T) {
	mine := &kolosecure.Config{MaxPending: 3}
	c, err := (&ServerConfig{Secure: mine}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if c.Secure != mine {
		t.Fatal("a non-nil Secure was replaced")
	}
}

func TestConfigRelayKept(t *testing.T) {
	mine := &kolosecure.Config{}
	c, err := (&Config{Relay: mine}).withDefaults()
	if err != nil || c.Relay != mine {
		t.Fatalf("a non-nil Relay was replaced: %v", err)
	}
}

func TestConfigInner(t *testing.T) {
	user := &kolosecure.Config{
		HandshakeTimeout: 3 * time.Second,
		MaxPending:       5,
		Transport:        &kolotransport.Config{MaxConns: 50, IdleTimeout: 7 * time.Second, Datagrams: true, AcceptFunc: func(netip.AddrPort) bool { return true }},
	}
	c, err := (&Config{Peer: user, ControlTimeout: 2 * time.Second}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	for _, accept := range []bool{true, false} {
		tc, sc := c.inner(accept)
		if sc.Transport != nil || sc.HandshakeTimeout != 3*time.Second || sc.MaxPending != 5 {
			t.Fatalf("secure config %+v", sc)
		}
		if tc.MaxConns != 1 || tc.MaxConnsPerIP != 1 || tc.MaxDialed != 1 || tc.IdleTimeout != 7*time.Second || tc.HandshakeTimeout != 10*time.Second || tc.Datagrams {
			t.Fatalf("transport config %+v", tc)
		}
		ap := netip.MustParseAddrPort("127.0.0.1:1")
		if got := tc.AcceptFunc == nil || tc.AcceptFunc(ap); got != accept {
			t.Fatalf("accept %v: AcceptFunc allows %v", accept, got)
		}
	}
	if user.Transport.MaxConns != 50 || user.Transport.AcceptFunc == nil || !user.Transport.Datagrams {
		t.Fatal("inner changed the caller's config")
	}
	if w := c.innerWait(); w != 2*time.Second+10*time.Second+3*time.Second {
		t.Fatalf("innerWait %v", w)
	}
	d, _ := (&Config{}).withDefaults()
	if w := d.innerWait(); w != 40*time.Second {
		t.Fatalf("default innerWait %v, want 40s", w)
	}
}

func TestConfigNetworkIPv4Only(t *testing.T) {
	sec := func(network string) *kolosecure.Config {
		return &kolosecure.Config{Transport: &kolotransport.Config{Network: network}}
	}
	for _, n := range []string{"udp", "udp6", "ip"} {
		checks := map[string]func() error{
			"Relay.Transport.Network":  func() error { _, err := (&Config{Relay: sec(n)}).withDefaults(); return err },
			"Peer.Transport.Network":   func() error { _, err := (&Config{Peer: sec(n)}).withDefaults(); return err },
			"Secure.Transport.Network": func() error { _, err := (&ServerConfig{Secure: sec(n)}).withDefaults(); return err },
		}
		for field, f := range checks {
			if err := f(); !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), field) || !strings.Contains(err.Error(), "IPv6") {
				t.Errorf("%s %q: %v, want ErrInvalidConfig", field, n, err)
			}
		}
	}
	for _, n := range []string{"", "udp4"} {
		if _, err := (&Config{Relay: sec(n), Peer: sec(n)}).withDefaults(); err != nil {
			t.Errorf("Config with Network %q: %v", n, err)
		}
		if _, err := (&ServerConfig{Secure: sec(n)}).withDefaults(); err != nil {
			t.Errorf("ServerConfig with Network %q: %v", n, err)
		}
	}
}

// An open relay says so when it starts, and a relay with a say over who reserves does not.
func TestListenWarnsAboutAnOpenRelay(t *testing.T) {
	checkGoroutines(t)
	var log bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&log, nil))
	startRelay(t, &ServerConfig{Logger: logger})
	for _, want := range []string{`"level":"WARN"`, "open relay", "AllowReserve"} {
		if !strings.Contains(log.String(), want) {
			t.Fatalf("no warning for an open relay (missing %q):\n%s", want, log.String())
		}
	}
	if n := strings.Count(log.String(), "\n"); n != 1 {
		t.Fatalf("%d log lines, want one:\n%s", n, log.String())
	}

	log.Reset()
	startRelay(t, &ServerConfig{Logger: logger, AllowReserve: func(ed25519.PublicKey) bool { return true }})
	if log.Len() != 0 {
		t.Fatalf("a relay with AllowReserve logged:\n%s", log.String())
	}
}

// Without a Logger the warning goes to slog's default logger.
func TestListenWarnsOnTheDefaultLogger(t *testing.T) {
	var log bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&log, nil)))
	defer slog.SetDefault(old)
	startRelay(t, nil)
	if !strings.Contains(log.String(), "level=WARN") || !strings.Contains(log.String(), "AllowReserve") {
		t.Fatalf("no warning on the default logger:\n%s", log.String())
	}
}
