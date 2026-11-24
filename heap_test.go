package kolorelay

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	"github.com/ciranda-dev/kolo-relay/internal/splice"
	"github.com/ciranda-dev/kolo-relay/internal/wire"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

const (
	heapEnv      = "KOLORELAY_HEAP"
	heapChildEnv = "KOLORELAY_HEAP_CHILD"
)

// heapRelayConfig is the relay of the measurement: the defaults of the runs in docs/limits.md (64 reservations), with MaxConnsPerIP raised so every attacker can come from 127.0.0.1.
func heapRelayConfig() *ServerConfig {
	sec := relaySecure()
	sec.Transport.MaxConnsPerIP = sec.Transport.MaxConns
	return &ServerConfig{Secure: sec, MaxReservations: 64}
}

// TestHeapRelay is the relay process that TestHeap attacks and measures; it runs only when TestHeap starts it.
func TestHeapRelay(t *testing.T) {
	if os.Getenv(heapChildEnv) != "1" {
		t.Skip("started by TestHeap")
	}
	checkGoroutines(t)
	id := newID(t)
	s, err := Listen(context.Background(), "127.0.0.1:0", id, heapRelayConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	fmt.Printf("heap relay %s %x\n", s.Addr(), id.PublicKey())

	sample := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
	var mu sync.Mutex
	live := func() uint64 {
		mu.Lock()
		defer mu.Unlock()
		runtime.GC()
		metrics.Read(sample)
		return sample[0].Value.Uint64()
	}
	var peak atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	defer wg.Wait()
	defer close(stop)
	wg.Go(func() {
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				v := live()
				for p := peak.Load(); v > p && !peak.CompareAndSwap(p, v); p = peak.Load() {
				}
			}
		}
	})
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		switch sc.Text() {
		case "base":
			v := live()
			peak.Store(v)
			fmt.Printf("heap base %d\n", v)
		case "mark":
			v := live()
			fmt.Printf("heap peak %d\n", max(peak.Swap(v), v))
		case "quit":
			return
		}
	}
}

// heapRelay is the relay process seen from TestHeap.
type heapRelay struct {
	addr  string
	key   ed25519.PublicKey
	stdin io.Writer
	lines *bufio.Scanner
}

func startHeapRelay(t *testing.T) *heapRelay {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHeapRelay$", "-test.timeout=1h")
	cmd.Env = append(os.Environ(), heapChildEnv+"=1")
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		fmt.Fprintln(stdin, "quit")
		stdin.Close()
		cmd.Wait()
	})
	h := &heapRelay{stdin: stdin, lines: bufio.NewScanner(stdout)}
	f := h.read(t, "relay")
	if len(f) != 2 {
		t.Fatalf("relay line %q", f)
	}
	h.addr = f[0]
	if h.key, err = hex.DecodeString(f[1]); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *heapRelay) read(t *testing.T, what string) []string {
	t.Helper()
	for h.lines.Scan() {
		if f := strings.Fields(h.lines.Text()); len(f) >= 2 && f[0] == "heap" && f[1] == what {
			return f[2:]
		}
	}
	t.Fatalf("relay process ended before %q", what)
	return nil
}

func (h *heapRelay) number(t *testing.T, cmd, what string) int64 {
	t.Helper()
	fmt.Fprintln(h.stdin, cmd)
	n, err := strconv.ParseInt(h.read(t, what)[0], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// base measures the live heap of the idle relay and starts a new peak.
func (h *heapRelay) base(t *testing.T) int64 { return h.number(t, "base", "base") }

// mark returns the peak live heap since the last base or mark and starts a new one.
func (h *heapRelay) mark(t *testing.T) int64 { return h.number(t, "mark", "peak") }

// delayProxy forwards one client's UDP packets to the relay, delaying those towards the relay.
type delayProxy struct {
	in, out *net.UDPConn
	delay   atomic.Int64
	hold    atomic.Bool
	client  atomic.Pointer[net.UDPAddr]
	queue   chan delayed
	wg      sync.WaitGroup
	mu      sync.Mutex
	seconds map[int64]int64
}

// recent returns how many packets the relay sent through p during the last d.
func (p *delayProxy) recent(d time.Duration) int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now().Unix()
	var n int64
	for sec, c := range p.seconds {
		if sec > now-int64(d/time.Second) {
			n += c
		}
	}
	return n
}

type delayed struct {
	at time.Time
	b  []byte
}

func newDelayProxy(t *testing.T, relay string) *delayProxy {
	t.Helper()
	ra, err := net.ResolveUDPAddr("udp4", relay)
	if err != nil {
		t.Fatal(err)
	}
	in, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := net.DialUDP("udp4", nil, ra)
	if err != nil {
		in.Close()
		t.Fatal(err)
	}
	p := &delayProxy{in: in, out: out, queue: make(chan delayed, 1<<16), seconds: map[int64]int64{}}
	done := make(chan struct{})
	p.wg.Go(func() {
		defer close(p.queue)
		buf := make([]byte, 2048)
		for {
			n, from, err := in.ReadFromUDP(buf)
			if err != nil {
				return
			}
			p.client.Store(from)
			select {
			case p.queue <- delayed{time.Now().Add(time.Duration(p.delay.Load())), append([]byte(nil), buf[:n]...)}:
			default:
			}
		}
	})
	p.wg.Go(func() {
		for d := range p.queue {
			for p.hold.Load() {
				select {
				case <-done:
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
			time.Sleep(time.Until(d.at))
			out.Write(d.b)
		}
	})
	p.wg.Go(func() {
		buf := make([]byte, 2048)
		for {
			n, err := out.Read(buf)
			if err != nil {
				return
			}
			p.mu.Lock()
			p.seconds[time.Now().Unix()]++
			p.mu.Unlock()
			if c := p.client.Load(); c != nil {
				in.WriteToUDP(buf[:n], c)
			}
		}
	})
	t.Cleanup(func() {
		close(done)
		in.Close()
		out.Close()
		p.wg.Wait()
	})
	return p
}

func (p *delayProxy) addr() string { return p.in.LocalAddr().String() }

// attacker is one client of the relay with its control stream, which becomes the session stream.
type attacker struct {
	c   *kolosecure.Conn
	st  *kolotransport.Stream
	key ed25519.PublicKey
}

func heapClientConfig(window int64, datagrams bool) *kolosecure.Config {
	return &kolosecure.Config{Transport: &kolotransport.Config{
		IdleTimeout:            2 * time.Minute,
		MaxStreamReceiveWindow: window,
		MaxConnReceiveWindow:   2 * window,
		Datagrams:              datagrams,
	}}
}

// dialRelay connects a new key to the relay, trying again while the relay is busy with other handshakes.
func dialRelay(addr string, relay ed25519.PublicKey, window int64, datagrams bool) (*attacker, error) {
	id, err := koloid.Generate()
	if err != nil {
		return nil, err
	}
	var c *kolosecure.Conn
	for range 40 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		c, err = kolosecure.Dial(ctx, addr, id, relay, heapClientConfig(window, datagrams))
		cancel()
		if err == nil {
			return &attacker{c: c, key: id.PublicKey()}, nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return nil, fmt.Errorf("dial the relay: %w", err)
}

func heapDial(t *testing.T, addr string, relay ed25519.PublicKey, window int64, datagrams bool) *attacker {
	t.Helper()
	a, err := dialRelay(addr, relay, window, datagrams)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.c.Close() })
	return a
}

func heapTarget(t *testing.T, addr string, relay ed25519.PublicKey, window int64) *attacker {
	t.Helper()
	tg := heapDial(t, addr, relay, window, false)
	if code := rawStatus(t, rawSend(t, tg.c, wire.EncodeReserve(wire.Version0))); code != wire.StatusOK {
		t.Fatalf("reserve: status %d", code)
	}
	return tg
}

// heapSession opens a session between a new reserving target and a new initiator; it returns the initiator, then the target.
func heapSession(t *testing.T, iaddr, taddr string, relay ed25519.PublicKey, window int64) (*attacker, *attacker) {
	t.Helper()
	tg := heapTarget(t, taddr, relay, window)
	in, st := heapConnect(t, iaddr, tg, relay, window)
	tg.st = st
	return in, tg
}

// heapConnect opens a session from a new initiator to tg; it returns the initiator and the target's session stream.
func heapConnect(t *testing.T, iaddr string, tg *attacker, relay ed25519.PublicKey, window int64) (*attacker, *kolotransport.Stream) {
	t.Helper()
	got := make(chan *kolotransport.Stream, 1)
	go func() {
		ts, err := tg.c.AcceptStream(context.Background())
		if err != nil {
			got <- nil
			return
		}
		ts.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := wire.ReadMessage(ts); err != nil || wire.WriteMessage(ts, wire.EncodeStatus(wire.StatusOK)) != nil {
			got <- nil
			return
		}
		ts.SetDeadline(time.Time{})
		got <- ts
	}()
	in := heapDial(t, iaddr, relay, window, false)
	in.st = rawSend(t, in.c, wire.EncodeConnect(wire.Version0, tg.key))
	if code := rawStatus(t, in.st); code != wire.StatusOK {
		t.Fatalf("connect: status %d", code)
	}
	in.st.SetReadDeadline(time.Time{})
	st := <-got
	if st == nil {
		t.Fatal("the target did not get the session")
	}
	return in, st
}

const (
	modeBulk = iota
	modeTrickle
	modeFast
)

// feed writes to st in mode until st fails: bulk writes, one byte every 500µs, or one byte every 200µs.
func feed(st *kolotransport.Stream, mode *atomic.Int32) {
	bulk := make([]byte, 16<<10)
	one := []byte{1}
	for {
		var n int
		var err error
		switch mode.Load() {
		case modeBulk:
			n, err = st.Write(bulk)
		case modeTrickle:
			n, err = st.Write(one)
			time.Sleep(500 * time.Microsecond)
		default:
			n, err = st.Write(one)
			time.Sleep(200 * time.Microsecond)
		}
		fed.Add(int64(n))
		if err != nil {
			return
		}
	}
}

// fed counts the bytes every feed has written, so a phase can wait until the relay stops taking more.
var fed atomic.Int64

// waitBlocked waits until no feed has written for a second, or until limit.
func waitBlocked(limit time.Duration) (int64, time.Duration) {
	begin := time.Now()
	last, still := fed.Load(), time.Now()
	for time.Since(begin) < limit {
		time.Sleep(100 * time.Millisecond)
		if n := fed.Load(); n != last {
			last, still = n, time.Now()
		} else if time.Since(still) > time.Second {
			break
		}
	}
	return last, time.Since(begin)
}

// park holds a connection in its control phase: one byte of a Connect, then 1-byte frames on a stream the relay has not accepted.
func park(wg *sync.WaitGroup, addr string, relay ed25519.PublicKey) (*attacker, error) {
	a, err := dialRelay(addr, relay, 64<<10, false)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctl, err := a.c.OpenStream(ctx)
	if err == nil {
		_, err = ctl.Write([]byte{34})
	}
	var st *kolotransport.Stream
	if err == nil {
		st, err = a.c.OpenStream(ctx)
	}
	if err != nil {
		a.c.Close()
		return nil, err
	}
	// With a hundred connections on one CPU, a busy loop sends bursts that share frames; sleeping keeps one frame per packet.
	wg.Go(func() { fill(st, 0, 200*time.Microsecond) })
	return a, nil
}

// parkAll parks n connections, a few at a time so the handshakes do not time out, and waits until the first of them is about to reach timeout.
// A connection that fails to park only lowers the measurement; their number is logged.
func parkAll(t *testing.T, wg *sync.WaitGroup, n int, addr string, relay ed25519.PublicKey, timeout time.Duration) []*attacker {
	t.Helper()
	began := time.Now()
	parked := make([]*attacker, n)
	errs := make([]error, n)
	sem := make(chan struct{}, 32)
	var pw sync.WaitGroup
	for i := range n {
		pw.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			parked[i], errs[i] = park(wg, addr, relay)
		})
	}
	pw.Wait()
	took := time.Since(began)
	var out []*attacker
	for _, a := range parked {
		if a != nil {
			t.Cleanup(func() { a.c.Close() })
			out = append(out, a)
		}
	}
	if err := errors.Join(errs...); err != nil {
		t.Logf("%d of %d connections did not park: %v", n-len(out), n, err)
	}
	if len(out) == 0 {
		t.Fatal("no connection parked")
	}
	time.Sleep(time.Until(began.Add(timeout - time.Second)))
	t.Logf("parked %d connections in %v", len(out), took.Round(time.Millisecond))
	return out
}

func mib(n int64) string {
	if n > -1<<20 && n < 1<<20 {
		return fmt.Sprintf("%.0f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
}

// TestHeap attacks a relay at its defaults in a child process and reports its peak live heap per term; it runs only with KOLORELAY_HEAP=1.
func TestHeap(t *testing.T) {
	if os.Getenv(heapEnv) != "1" {
		t.Skip("set KOLORELAY_HEAP=1 to measure the relay's heap (see the README)")
	}
	checkGoroutines(t)
	cfg, err := heapRelayConfig().withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	b := memoryBound(cfg)
	conns, sessions := cfg.Secure.Transport.MaxConns, cfg.MaxSessions
	t.Logf("defaults: MaxConns %d, MaxSessions %d, windows %d KiB; bound: %s per connection, %s per sending connection, receive %s, send %s, total %s, datagram step %s",
		conns, sessions, cfg.Secure.Transport.MaxConnReceiveWindow>>10, mib(b.conn), mib(b.sendConn), mib(b.receive), mib(b.send), mib(b.total), mib(b.datagram))
	h := startHeapRelay(t)
	results := map[string]int64{}
	phases := os.Getenv("KOLORELAY_HEAP_PHASES")
	if phases == "" || strings.Contains(phases, "receive") {
		results["idle"], results["receive"] = heapReceive(t, h, cfg)
	}
	// The send step's delayed acknowledgments hold its sessions on the relay after it ends, so the datagram step comes first.
	if phases == "" || strings.Contains(phases, "datagram") {
		results["datagram"] = heapDatagram(t, h, cfg)
	}
	if phases == "" || strings.Contains(phases, "send") {
		results["send"], results["total"] = heapSend(t, h, cfg)
	}
	if got, ok := results["send"]; ok {
		results["send per connection"] = got / int64(sessions)
	}
	for _, c := range []struct {
		name  string
		bound int64
	}{{"idle", b.idle}, {"receive", b.receive}, {"send per connection", b.sendConn}, {"send", b.send}, {"total", b.total}, {"datagram", b.datagram}} {
		got, ok := results[c.name]
		if !ok {
			continue
		}
		t.Logf("%s: measured %s, bound %s (margin %s)", c.name, mib(got), mib(c.bound), mib(c.bound-got))
		if got > c.bound {
			t.Errorf("%s: measured %s above the documented bound %s", c.name, mib(got), mib(c.bound))
		}
	}
}

// heapReceive fills every connection with full stream windows of one-byte frames the relay does not read.
// It returns the heap of one idle connection and the peak of the step.
func heapReceive(t *testing.T, h *heapRelay, cfg ServerConfig) (idle, peak int64) {
	t.Helper()
	tc := cfg.Secure.Transport
	conns, sessions := tc.MaxConns, cfg.MaxSessions
	// A target holds as many full session streams as its connection window takes.
	perTarget := int(min(int64(cfg.MaxSessionsPerTarget), tc.MaxConnReceiveWindow/tc.MaxStreamReceiveWindow))
	var wg sync.WaitGroup
	var clients []*attacker
	base := h.base(t)
	idleConns := min(conns, cfg.MaxReservations)
	for range idleConns {
		a := heapDial(t, h.addr, h.key, 64<<10, false)
		if code := rawStatus(t, rawSend(t, a.c, wire.EncodeReserve(wire.Version0))); code != wire.StatusOK {
			t.Fatalf("reserve: status %d", code)
		}
		clients = append(clients, a)
	}
	idle = (h.mark(t) - base) / int64(idleConns)
	t.Logf("receive: %d idle reservations, %.0f KiB each", idleConns, float64(idle)/1024)
	for _, a := range clients {
		a.c.Close()
	}
	clients = nil
	time.Sleep(3 * time.Second)
	base = h.base(t)
	fed.Store(0)
	var tg *attacker
	for i := range sessions {
		if i%perTarget == 0 {
			tg = heapTarget(t, h.addr, h.key, 64<<10)
			clients = append(clients, tg)
		}
		in, ts := heapConnect(t, h.addr, tg, h.key, 64<<10)
		clients = append(clients, in)
		// The first 64 KiB fill the other side's window; then one-byte frames, slow enough to leave one per packet.
		wg.Go(func() { fill(in.st, 64<<10, 200*time.Microsecond) })
		wg.Go(func() { fill(ts, 64<<10, 200*time.Microsecond) })
	}
	n, d := waitBlocked(time.Minute)
	sess := h.mark(t) - base
	window := 2 * int64(sessions) * tc.MaxStreamReceiveWindow
	t.Logf("receive: %d session connections (%d targets with %d sessions each) full after %v (%d bytes written), peak %s, %.0f heap bytes per byte of window",
		len(clients), len(clients)-sessions, perTarget, d.Round(time.Second), n, mib(sess), float64(sess)/float64(window))
	before := fed.Load()
	parked := parkAll(t, &wg, conns-len(clients), h.addr, h.key, cfg.ControlTimeout)
	peak = h.mark(t) - base
	t.Logf("receive: plus %d parked connections (%d bytes written), peak %s above the idle relay", len(parked), fed.Load()-before, mib(peak))
	for _, a := range append(clients, parked...) {
		a.c.Close()
	}
	wg.Wait()
	time.Sleep(3 * time.Second)
	return idle, peak
}

// fill writes bulk bytes to st, then one byte per gap until st fails.
func fill(st *kolotransport.Stream, bulk int, gap time.Duration) {
	n, err := st.Write(make([]byte, bulk))
	fed.Add(int64(n))
	for err == nil {
		time.Sleep(gap)
		n, err = st.Write([]byte{1})
		fed.Add(int64(n))
	}
}

// heapSend makes the relay keep the most unacknowledged packets it can towards each initiator, then adds full receive windows; it returns both peaks.
// A quic-go client cannot delay its acknowledgments and still send fast, so the initiator only receives and the target sends.
func heapSend(t *testing.T, h *heapRelay, cfg ServerConfig) (send, total int64) {
	t.Helper()
	conns, sessions := cfg.Secure.Transport.MaxConns, cfg.MaxSessions
	var wg sync.WaitGroup
	base := h.base(t)
	type pair struct {
		in, tg *attacker
		p      *delayProxy
		mode   atomic.Int32
	}
	var pairs []*pair
	for range sessions {
		// The delay comes before the handshake: a round trip that jumps later ends quic-go's slow start at once.
		ip := newDelayProxy(t, h.addr)
		ip.delay.Store(int64(1200 * time.Millisecond))
		in, tg := heapSession(t, ip.addr(), h.addr, h.key, 4<<20)
		p := &pair{in: in, tg: tg, p: ip}
		pairs = append(pairs, p)
		// Traffic starts at once, so a session set up first is not idle while the others are.
		wg.Go(func() { io.Copy(io.Discard, p.in.st) })
		wg.Go(func() { io.Copy(io.Discard, p.tg.st) })
		wg.Go(func() { feed(p.tg.st, &p.mode) })
	}
	// Bulk data over a long round trip grows the relay's congestion window, so it can later hold many small packets.
	time.Sleep(12 * time.Second)
	for _, p := range pairs {
		p.mode.Store(modeTrickle)
	}
	const most = 27 * time.Second
	for d := 1200 * time.Millisecond; d < most; d += 50 * time.Millisecond {
		for _, p := range pairs {
			p.p.delay.Store(int64(d))
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, p := range pairs {
		p.p.delay.Store(int64(most))
	}
	time.Sleep(15 * time.Second)
	send = h.mark(t) - base
	var packets []int64
	for _, p := range pairs {
		packets = append(packets, p.p.recent(most))
	}
	t.Logf("send: %d streams with acknowledgments delayed %v, relay sent %v packets on them in the last %v, peak %s above the idle relay",
		sessions, most, packets, most, mib(send))

	// Initiators stop acknowledging, so the relay's packets to them stay; targets send one-byte frames the blocked relay cannot forward.
	for _, p := range pairs {
		p.p.hold.Store(true)
		p.mode.Store(modeFast)
	}
	// One byte per 200µs fills a 64 KiB stream window in about 13s; parked connections live only ControlTimeout, so they come last.
	time.Sleep(3 * time.Second)
	parked := parkAll(t, &wg, conns-2*sessions, h.addr, h.key, cfg.ControlTimeout)
	total = h.mark(t) - base
	t.Logf("total: send step plus %d full stream windows, peak %s above the idle relay", sessions+len(parked), mib(total))
	for _, p := range pairs {
		p.in.c.Close()
		p.tg.c.Close()
	}
	for _, a := range parked {
		a.c.Close()
	}
	wg.Wait()
	time.Sleep(3 * time.Second)
	return send, total
}

type bound struct{ idle, conn, sendConn, receive, send, total, datagram int64 }

// memoryBound is the README's worst case for cfg, in bytes; 176 and 96 are kolo-transport's measured heap bytes per byte of window.
func memoryBound(cfg ServerConfig) bound {
	tc := cfg.Secure.Transport
	conns, sessions := int64(tc.MaxConns), int64(cfg.MaxSessions)
	var b bound
	// Unread one-byte frames, 16 KiB of out-of-order 1-RTT CRYPTO frames, 256 queued packets and the connection itself.
	b.idle = 64 << 10
	b.conn = tc.MaxConnReceiveWindow*176 + 16<<10*176 + 256*1536 + b.idle
	// quic-go keeps at most 25000 sent packets per connection, each with a 1452-byte buffer per STREAM frame.
	b.sendConn = 25000 * 1800
	b.receive = conns*b.conn + (sessions-1)*tc.MaxStreamReceiveWindow*96 + 1024*1536 + 2*sessions*splice.BufferSize
	if tc.Datagrams {
		// quic-go's 128 received and 32 queued datagrams per connection, and each session direction's packet queue, in
		// Go's 1536-byte size class.
		b.conn += datagramConn
		b.receive += conns*datagramConn + 2*sessions*splice.QueueSize*1536
	}
	b.send = 2 * sessions * b.sendConn
	b.total = b.receive + b.send
	// The datagram step: connections with full datagram queues and no stream data, every session's packet queues and copy
	// buffers, and the send term of the half of the targets that get frames (datagrams are never kept for resending).
	b.datagram = conns*(b.idle+datagramConn) + 2*sessions*(splice.QueueSize*1536+splice.BufferSize) + sessions/2*b.sendConn
	return b
}

// datagramConn is the heap of a connection's full datagram queues: 128 received and 32 to send, 1536 bytes each.
const datagramConn = (128 + 32) * 1536

// heapDatagram floods the relay with datagrams: initiators send full-size ones for their sessions, whose targets read
// neither their stream nor their datagrams, and reservations send them for sessions that do not exist.
func heapDatagram(t *testing.T, h *heapRelay, cfg ServerConfig) int64 {
	t.Helper()
	conns, sessions := cfg.Secure.Transport.MaxConns, cfg.MaxSessions
	// The relay may still be freeing the step before; a base taken too early would hide this step's heap.
	base := h.base(t)
	for range 20 {
		time.Sleep(2 * time.Second)
		next := h.base(t)
		if next > base-1<<20 {
			base = next
			break
		}
		base = next
	}
	var sent atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var clients []*attacker
	flood := func(a *attacker, id func() uint64) {
		wg.Go(func() {
			size := wire.MaxPacketSize
			for {
				select {
				case <-stop:
					return
				default:
				}
				p, _ := wire.AppendDatagram(nil, id(), make([]byte, size))
				switch err := a.c.SendDatagram(p); {
				case err == nil:
					sent.Add(1)
				case errors.Is(err, kolotransport.ErrDatagramTooLarge):
					size = max(size-8, 1)
				case errors.Is(err, kolotransport.ErrDatagramDropped):
					time.Sleep(100 * time.Microsecond)
				default:
					return
				}
			}
		})
	}
	for i := range sessions {
		// Every other target speaks version 0, so the relay queues frames towards a stream that is never read.
		tg := heapDatagramClient(t, h, uint64(i%2*wire.Version1))
		got := make(chan struct{})
		go func() {
			defer close(got)
			ts, err := tg.c.AcceptStream(context.Background())
			if err != nil {
				return
			}
			ts.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := wire.ReadMessage(ts); err == nil {
				wire.WriteMessage(ts, wire.EncodeStatus(wire.StatusOK))
			}
		}()
		// The relay may still be ending the sessions of the step before.
		var in *attacker
		for try := 0; ; try++ {
			in = heapDial(t, h.addr, h.key, 64<<10, true)
			in.st = rawSend(t, in.c, wire.EncodeConnect(wire.Version1, tg.key))
			code := rawStatus(t, in.st)
			if code == wire.StatusOK {
				break
			}
			in.c.Close()
			if code != wire.StatusLimit || try == 30 {
				t.Fatalf("connect: status %d", code)
			}
			time.Sleep(time.Second)
		}
		<-got
		clients = append(clients, tg, in)
		qid := in.st.ID() / 4
		flood(in, func() uint64 { return qid })
	}
	strays := min(conns-2*sessions, cfg.MaxReservations-sessions)
	for i := range strays {
		a := heapDatagramClient(t, h, wire.Version1)
		clients = append(clients, a)
		next := uint64(i) << 20
		flood(a, func() uint64 {
			next++
			return next
		})
	}
	time.Sleep(20 * time.Second)
	peak := h.mark(t) - base
	close(stop)
	wg.Wait()
	t.Logf("datagram: %d sessions and %d reservations sent %d datagrams in 20s, peak %s above the idle relay",
		sessions, strays, sent.Load(), mib(peak))
	for _, a := range clients {
		a.c.Close()
	}
	time.Sleep(3 * time.Second)
	return peak
}

// heapDatagramClient is a new key with datagrams that reserved on the relay in version.
func heapDatagramClient(t *testing.T, h *heapRelay, version uint64) *attacker {
	t.Helper()
	a := heapDial(t, h.addr, h.key, 64<<10, true)
	if code := rawStatus(t, rawSend(t, a.c, wire.EncodeReserve(version))); code != wire.StatusOK {
		t.Fatalf("reserve: status %d", code)
	}
	return a
}
