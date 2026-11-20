package kolorelay

import (
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/ciranda-dev/kolo-relay/internal/limits"
	"github.com/ciranda-dev/kolo-relay/internal/splice"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// ServerConfig sets the limits of a relay. A zero field takes its default.
type ServerConfig struct {
	// Secure configures the relay's listener. Nil means the relay defaults in the README; a non-nil value is used as given.
	Secure *kolosecure.Config
	// MaxReservations caps the reserved keys. Default 64, from 1 to 100000.
	MaxReservations int
	// MaxSessions caps the sessions being set up or open. Default 16, from 1 to 10000.
	MaxSessions int
	// MaxSessionsPerPeer caps the sessions one key has started. Default 4 or MaxSessions if lower, at most MaxSessions.
	MaxSessionsPerPeer int
	// MaxSessionsPerTarget caps the sessions to one reserved key; beyond it the relay answers Unavailable.
	// Default 8 or MaxSessions if lower, at most MaxSessions.
	MaxSessionsPerTarget int
	// ReservationLifetime ends a reservation; the peer must reserve again. Default 1h, from 1s to 24h.
	ReservationLifetime time.Duration
	// MaxSessionDuration ends a session. Default 1h, from 1s to 24h.
	MaxSessionDuration time.Duration
	// MaxSessionBytes ends a session once this many bytes went one way. Default 1 GiB, from 64 KiB to 1 TiB.
	MaxSessionBytes int64
	// SessionIdleTimeout ends a session with no byte either way. Default 60s, from 1s to 10m.
	// Keep-alive is always on, so it ends a session between live peers only if it is not above their KeepAlivePeriod (5s by default).
	SessionIdleTimeout time.Duration
	// ConnectTimeout bounds how long the target may take to accept a session. Default 15s, from 1s to 60s.
	// Default clients wait 20s for the answer, so above about 15s they need a longer ControlTimeout.
	ConnectTimeout time.Duration
	// ControlTimeout bounds how long a client may take to send its first message. Default 15s, from 1s to 60s.
	ControlTimeout time.Duration
	// RateBytes is the read rate per client connection, in bytes per second. Default 1 MiB, from 16 KiB to 1 GiB.
	RateBytes int64
	// RateBurst is the most a client connection may send at once above RateBytes. Default 256 KiB, from 16 KiB to 64 MiB.
	RateBurst int64
	// FlushInterval is the shortest time between two writes of less than a full buffer in one direction of a session.
	// Default 1ms, from 100µs to 100ms.
	FlushInterval time.Duration
	// AllowReserve says whether a key may reserve. Nil allows every key, which Listen reports with a warning; a panic refuses.
	AllowReserve func(key ed25519.PublicKey) bool
	// AllowConnect says whether from may reach to. Nil allows every pair; a panic refuses.
	// It must be fast: Server.Close waits for calls in progress.
	AllowConnect func(from, to ed25519.PublicKey) bool
	// Logger receives the warning Listen logs when AllowReserve is nil. Nil means slog.Default().
	Logger *slog.Logger
}

// Config sets the limits of a peer that reserves on a relay or dials through one. A zero field takes its default.
type Config struct {
	// Relay configures the connection to the relay. Nil means kolo-secure's defaults with a 5s keep-alive; a non-nil value is used as given.
	Relay *kolosecure.Config
	// Peer configures the end-to-end connection. Nil means the defaults; kolorelay sets the listener-only transport fields.
	Peer *kolosecure.Config
	// ControlTimeout bounds each exchange with the relay and the wait for a relayed peer's handshake.
	// Default 20s, 5s above the relay's default ConnectTimeout; from 1s to 60s.
	ControlTimeout time.Duration
	// MaxPending caps the incoming sessions not yet returned by Accept. Default 16, from 1 to 256.
	MaxPending int
	// SendQueue is how many packets a session queues before it drops the oldest. Default 512, from 8 to 1024.
	SendQueue int
	// AllowFunc says whether an initiator may reach this reservation. Nil allows every key; a panic refuses.
	AllowFunc func(initiator ed25519.PublicKey) bool
}

type limit[T int | int64 | time.Duration] struct {
	name          string
	def, min, max T
}

func (l limit[T]) apply(v *T) error {
	switch {
	case *v == 0:
		*v = l.def
	case *v < l.min || *v > l.max:
		return fmt.Errorf("%w: %s must be between %v and %v", ErrInvalidConfig, l.name, l.min, l.max)
	}
	return nil
}

func (c *ServerConfig) withDefaults() (ServerConfig, error) {
	var out ServerConfig
	if c != nil {
		out = *c
	}
	if err := (limit[int]{"MaxSessions", 16, 1, 10000}).apply(&out.MaxSessions); err != nil {
		return ServerConfig{}, err
	}
	errs := []error{
		limit[int]{"MaxReservations", 64, 1, 100000}.apply(&out.MaxReservations),
		limit[int]{"MaxSessionsPerPeer", min(4, out.MaxSessions), 1, out.MaxSessions}.apply(&out.MaxSessionsPerPeer),
		limit[int]{"MaxSessionsPerTarget", min(8, out.MaxSessions), 1, out.MaxSessions}.apply(&out.MaxSessionsPerTarget),
		limit[time.Duration]{"ReservationLifetime", time.Hour, time.Second, 24 * time.Hour}.apply(&out.ReservationLifetime),
		limit[time.Duration]{"MaxSessionDuration", time.Hour, time.Second, 24 * time.Hour}.apply(&out.MaxSessionDuration),
		limit[int64]{"MaxSessionBytes", 1 << 30, 64 << 10, 1 << 40}.apply(&out.MaxSessionBytes),
		limit[time.Duration]{"SessionIdleTimeout", time.Minute, time.Second, 10 * time.Minute}.apply(&out.SessionIdleTimeout),
		limit[time.Duration]{"ConnectTimeout", defaultConnectTimeout, time.Second, time.Minute}.apply(&out.ConnectTimeout),
		limit[time.Duration]{"ControlTimeout", 15 * time.Second, time.Second, time.Minute}.apply(&out.ControlTimeout),
		limit[int64]{"RateBytes", 1 << 20, 16 << 10, 1 << 30}.apply(&out.RateBytes),
		// A burst below splice.BufferSize shrinks the reads, so a read never waits longer than the bucket allows.
		limit[int64]{"RateBurst", 256 << 10, 16 << 10, 64 << 20}.apply(&out.RateBurst),
		limit[time.Duration]{"FlushInterval", time.Millisecond, 100 * time.Microsecond, 100 * time.Millisecond}.apply(&out.FlushInterval),
	}
	for _, err := range errs {
		if err != nil {
			return ServerConfig{}, err
		}
	}
	if err := checkNetwork("Secure", out.Secure); err != nil {
		return ServerConfig{}, err
	}
	if out.Secure == nil {
		out.Secure = relaySecure()
	}
	return out, nil
}

// relaySecure is the relay's listener when ServerConfig.Secure is nil.
func relaySecure() *kolosecure.Config {
	return &kolosecure.Config{Transport: &kolotransport.Config{
		MaxConns:               128,
		MaxConnsPerIP:          4,
		MaxDialed:              1,
		MaxIncomingStreams:     2,
		MaxStreamReceiveWindow: 64 << 10,
		MaxConnReceiveWindow:   256 << 10,
	}}
}

func (c ServerConfig) tableConfig() limits.Config {
	return limits.Config{
		MaxReservations:      c.MaxReservations,
		MaxSessions:          c.MaxSessions,
		MaxSessionsPerPeer:   c.MaxSessionsPerPeer,
		MaxSessionsPerTarget: c.MaxSessionsPerTarget,
	}
}

func (c ServerConfig) spliceLimits() splice.Limits {
	return splice.Limits{MaxDuration: c.MaxSessionDuration, MaxBytes: c.MaxSessionBytes, Idle: c.SessionIdleTimeout, Flush: c.FlushInterval}
}

func (c *Config) withDefaults() (Config, error) {
	var out Config
	if c != nil {
		out = *c
	}
	errs := []error{
		limit[int]{"MaxPending", 16, 1, 256}.apply(&out.MaxPending),
		// A Connect waits for the target's answer, so the client waits longer than the relay does.
		limit[time.Duration]{"ControlTimeout", defaultConnectTimeout + 5*time.Second, time.Second, time.Minute}.apply(&out.ControlTimeout),
		limit[int]{"SendQueue", 512, 8, 1024}.apply(&out.SendQueue),
	}
	for _, err := range errs {
		if err != nil {
			return Config{}, err
		}
	}
	if err := checkNetwork("Relay", out.Relay); err != nil {
		return Config{}, err
	}
	if err := checkNetwork("Peer", out.Peer); err != nil {
		return Config{}, err
	}
	if out.Relay == nil {
		out.Relay = &kolosecure.Config{Transport: &kolotransport.Config{KeepAlivePeriod: 5 * time.Second}}
	}
	return out, nil
}

// checkNetwork refuses a kolo-transport Network other than "udp4", so no field selects IPv6.
func checkNetwork(name string, s *kolosecure.Config) error {
	if s != nil && s.Transport != nil && s.Transport.Network != "" && s.Transport.Network != "udp4" {
		return fmt.Errorf("%w: %s.Transport.Network must be \"udp4\"; IPv6 is refused", ErrInvalidConfig, name)
	}
	return nil
}

// inner returns the configs of a session's end-to-end connection; the dialing side (accept false) refuses every incoming attempt.
func (c Config) inner(accept bool) (*kolotransport.Config, *kolosecure.Config) {
	var s kolosecure.Config
	if c.Peer != nil {
		s = *c.Peer
	}
	var t kolotransport.Config
	if s.Transport != nil {
		t = *s.Transport
	}
	s.Transport = nil
	if s.HandshakeTimeout == 0 {
		s.HandshakeTimeout = defaultHandshake
	}
	if t.HandshakeTimeout == 0 {
		t.HandshakeTimeout = defaultHandshake
	}
	t.MaxConns, t.MaxConnsPerIP, t.MaxDialed, t.AcceptFunc = 1, 1, 1, nil
	if !accept {
		t.AcceptFunc = func(netip.AddrPort) bool { return false }
	}
	return &t, &s
}

// innerWait bounds how long a target waits for the initiator's end-to-end handshake.
func (c Config) innerWait() time.Duration {
	t, s := c.inner(true)
	return c.ControlTimeout + t.HandshakeTimeout + s.HandshakeTimeout
}

const defaultConnectTimeout = 15 * time.Second

// defaultHandshake is kolo-transport's and kolo-secure's default, set here so innerWait knows it.
const defaultHandshake = 10 * time.Second
