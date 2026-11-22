package kolorelay

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-relay/internal/netsim"
	"github.com/ciranda-dev/kolo-relay/internal/pconn"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

const pathEnv = "KOLORELAY_PATH"

// pathDelay is the one-way delay of each leg: four legs make a 470 ms round trip end to end, as measured in the field.
const pathDelay = 117500 * time.Microsecond

// pathParams is one run of the path measurement.
type pathParams struct {
	window       int64   // the relay's and the clients' outer MaxStreamReceiveWindow
	outer, inner string  // congestion controllers of the relay connections and of the end-to-end connection
	loss         float64 // random loss on each leg and direction
	mode         string  // "stream" (protocol version 0) or "datagram" (version 1)
}

func (p pathParams) String() string {
	return fmt.Sprintf("w=%dKiB outer=%s inner=%s loss=%g%% mode=%s", p.window>>10, p.outer, p.inner, p.loss*100, p.mode)
}

// pathModes are the two ways inner packets cross a leg: on the session stream (version 0) or as datagrams (version 1).
var pathModes = []string{"stream", "datagram"}

// pathMatrix is every combination in both modes when full is set. Otherwise it is the field's shape (the relay's
// 64 KiB window, Reno outside and BBR inside) without and with loss, and a 1 MiB window with BBR on both levels at 1%.
func pathMatrix(full bool) []pathParams {
	var cells []pathParams
	if !full {
		cells = []pathParams{{64 << 10, "reno", "bbr", 0, ""}, {64 << 10, "reno", "bbr", 0.01, ""}, {1 << 20, "bbr", "bbr", 0.01, ""}}
	} else {
		for _, w := range []int64{64 << 10, 1 << 20, 4 << 20} {
			for _, outer := range []string{"reno", "bbr"} {
				for _, inner := range []string{"reno", "bbr"} {
					for _, loss := range []float64{0, 0.005, 0.01, 0.03} {
						cells = append(cells, pathParams{w, outer, inner, loss, ""})
					}
				}
			}
		}
	}
	var out []pathParams
	for _, c := range cells {
		for _, m := range pathModes {
			c.mode = m
			out = append(out, c)
		}
	}
	return out
}

// pathWindows sets the outer windows of a run: the connection window is twice the stream window, at least
// kolo-transport's 256 KiB and at most its 64 MiB.
func pathWindows(tc *kolotransport.Config, p pathParams) {
	tc.MaxStreamReceiveWindow = p.window
	tc.MaxConnReceiveWindow = min(max(256<<10, 2*p.window), 64<<20)
	tc.CongestionControl = p.outer
}

// pathServerConfig is the relay's default listener with the run's windows, controller and mode. RateBytes is at its
// maximum so that the relay's bucket is never what limits the run.
func pathServerConfig(p pathParams) *ServerConfig {
	sec := relaySecure()
	tc := sec.Transport
	pathWindows(tc, p)
	tc.Datagrams = p.mode == "datagram"
	tc.MaxMemory = max(kolotransport.DefaultMaxMemory, int64(tc.MaxConns+tc.MaxDialed)*tc.MaxConnReceiveWindow)
	return &ServerConfig{Secure: sec, RateBytes: 1 << 30}
}

func pathConfig(p pathParams) *Config {
	relay := &kolotransport.Config{KeepAlivePeriod: 5 * time.Second, Datagrams: p.mode == "datagram"}
	pathWindows(relay, p)
	return &Config{
		Relay: &kolosecure.Config{Transport: relay},
		Peer:  &kolosecure.Config{Transport: &kolotransport.Config{CongestionControl: p.inner}},
	}
}

// pathLink is one leg between a client and the relay: 3 Mbit/s, the leg's delay, 10 ms of jitter and the run's loss each way.
func pathLink(t *testing.T, relay string, loss float64, seed int64) *netsim.Link {
	t.Helper()
	p := func(seed int64) netsim.Profile {
		return netsim.Profile{Rate: 375000, Delay: pathDelay, Jitter: 10 * time.Millisecond, Loss: loss, Seed: seed}
	}
	l, err := netsim.New(relay, p(seed), p(seed+1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

var pathHeader = strings.Fields("window outer inner loss% mode KB/s " +
	"b_min_ms b_srtt_ms b_max_srtt_ms b_sent b_lost b_cwnd b_inflight b_cc " +
	"a_min_ms a_srtt_ms a_max_srtt_ms a_sent a_lost a_cwnd a_inflight a_cc " +
	"ob_min_ms ob_srtt_ms ob_sent ob_lost ob_cwnd ob_cc " +
	"oa_min_ms oa_srtt_ms oa_sent oa_lost oa_cwnd oa_cc " +
	"b_up_loss b_up_q b_down_loss b_down_q a_up_loss a_up_q a_down_loss a_down_q " +
	"ob_maxdg oa_maxdg b_frames_sent b_frames_recv b_dgrams_sent b_dgrams_recv b_dropped " +
	"a_frames_sent a_frames_recv a_dgrams_sent a_dgrams_recv a_dropped")

// pathResult is what a run adds to the comparison of the two modes.
type pathResult struct {
	goodput   float64       // bytes per second
	innerLost uint64        // PacketsLost of the sender's end-to-end connection
	srtt      time.Duration // SmoothedRTT of the sender's end-to-end connection at the end of the run
}

// pathPair is a run without its mode.
type pathPair struct {
	window       int64
	outer, inner string
	loss         float64
}

// pathTSV starts every logged row of TestPath, so the table can be taken from the log with grep.
const pathTSV = "path-tsv\t"

// The datagram mode must show inner loss and a lower smoothed RTT than the stream mode at pathLossy, and at pathNoLoss
// reach pathMinGain times its goodput with the relay's default window pathWindow (1.56 to 1.77 measured in the full matrix).
const (
	pathLossy   = 0.01
	pathWindow  = 64 << 10
	pathMinGain = 1.3
)

// pathProblems lists what the datagram mode d lacks against the stream mode s of the same settings k.
func pathProblems(k pathPair, s, d pathResult) []string {
	var out []string
	if k.loss == pathLossy {
		if d.innerLost == 0 {
			out = append(out, "datagram mode lost no inner packet")
		}
		if d.srtt >= s.srtt {
			out = append(out, fmt.Sprintf("datagram mode's smoothed RTT %v is not below the stream mode's %v", d.srtt, s.srtt))
		}
	}
	if k.loss == 0 && k.window == pathWindow && d.goodput < pathMinGain*s.goodput {
		out = append(out, fmt.Sprintf("datagram mode %.1f KB/s is below %gx the stream mode's %.1f KB/s", d.goodput/1000, pathMinGain, s.goodput/1000))
	}
	return out
}

// TestPath measures a bulk transfer through a relay over two slow, lossy legs, one row per run; set KOLORELAY_PATH=1.
// KOLORELAY_PATH_SECONDS sets the transfer time (default 20) and KOLORELAY_PATH_MATRIX=full runs every combination; each
// row is logged as TSV after the pathTSV prefix. The datagram mode is held to pathProblems.
func TestPath(t *testing.T) {
	if os.Getenv(pathEnv) != "1" {
		t.Skip("set KOLORELAY_PATH=1 to measure")
	}
	dur := 20 * time.Second
	if v := os.Getenv("KOLORELAY_PATH_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			t.Fatalf("KOLORELAY_PATH_SECONDS %q is not a positive number of seconds", v)
		}
		dur = time.Duration(n) * time.Second
	}
	t.Log(pathTSV + strings.Join(pathHeader, "\t"))
	results := map[pathPair]map[string]pathResult{}
	for _, p := range pathMatrix(os.Getenv("KOLORELAY_PATH_MATRIX") == "full") {
		t.Run(p.String(), func(t *testing.T) {
			row, res := pathRun(t, p, dur)
			t.Log(pathTSV + strings.Join(row, "\t"))
			k := pathPair{p.window, p.outer, p.inner, p.loss}
			if results[k] == nil {
				results[k] = map[string]pathResult{}
			}
			results[k][p.mode] = res
		})
	}
	for k, r := range results {
		if len(r) != len(pathModes) {
			continue
		}
		for _, p := range pathProblems(k, r["stream"], r["datagram"]) {
			t.Errorf("%+v: %s", k, p)
		}
	}
}

// pathRun connects A (Dial) and B (Reserve) to a relay over their own legs, sends from B to A for dur and returns the row.
func pathRun(t *testing.T, p pathParams, dur time.Duration) ([]string, pathResult) {
	checkGoroutines(t)
	ctx, cancel := context.WithTimeout(context.Background(), dur+2*time.Minute)
	t.Cleanup(cancel)
	rid := newID(t)
	s, err := Listen(ctx, "127.0.0.1:0", rid, pathServerConfig(p))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	legA := pathLink(t, s.Addr().String(), p.loss, 1)
	legB := pathLink(t, s.Addr().String(), p.loss, 3)
	cfg := pathConfig(p)
	idB := newID(t)
	res := reserve(t, &testRelay{addr: legB.Addr(), key: rid.PublicKey()}, idB, cfg)
	a := dial(t, &testRelay{addr: legA.Addr(), key: rid.PublicKey()}, newID(t), idB.PublicKey(), cfg)
	b := accept(t, res)

	start := time.Now()
	end := start.Add(dur)
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() {
		st, err := b.OpenStream(ctx)
		if err != nil {
			return
		}
		st.SetWriteDeadline(end)
		buf := make([]byte, 64<<10)
		for {
			if _, err := st.Write(buf); err != nil {
				return
			}
		}
	})
	var maxA, maxB time.Duration
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				maxA, maxB = max(maxA, a.Stats().SmoothedRTT), max(maxB, b.Stats().SmoothedRTT)
			}
		}
	}()
	var got int64
	if st, err := a.AcceptStream(ctx); err == nil {
		st.SetReadDeadline(end)
		buf := make([]byte, 64<<10)
		for {
			n, err := st.Read(buf)
			got += int64(n)
			if err != nil {
				break
			}
		}
	}
	close(stop)
	<-sampled
	ia, ib := a.Stats(), b.Stats()
	oa, ob := a.rc.Stats(), res.rc.Stats()
	maxA, maxB = max(maxA, ia.SmoothedRTT), max(maxB, ib.SmoothedRTT)

	if got == 0 {
		t.Error("A read nothing")
	}
	if ib.MinRTT < 4*pathDelay {
		t.Errorf("end-to-end min RTT %v is below the legs' %v", ib.MinRTT, 4*pathDelay)
	}
	if p.loss > 0 && (legB.Up().DroppedLoss == 0 || legA.Down().DroppedLoss == 0) {
		t.Error("the legs dropped no packet")
	}
	pb, pa := b.pc.Counts(), a.pc.Counts()
	for name, c := range map[string]pconn.Counts{"B": pb, "A": pa} {
		if dg := c.DatagramsSent + c.DatagramsReceived; (p.mode == "datagram") != (dg > 0) {
			t.Errorf("%s: %s mode counted %d datagrams (%+v)", name, p.mode, dg, c)
		}
	}

	ms := func(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) }
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	inner := func(s kolotransport.ConnStats, most time.Duration) []string {
		return []string{ms(s.MinRTT), ms(s.SmoothedRTT), ms(most), u(s.PacketsSent), u(s.PacketsLost), u(s.CongestionWindow), u(s.BytesInFlight), s.CongestionController}
	}
	outer := func(s kolotransport.ConnStats) []string {
		return []string{ms(s.MinRTT), ms(s.SmoothedRTT), u(s.PacketsSent), u(s.PacketsLost), u(s.CongestionWindow), s.CongestionController}
	}
	drops := func(s netsim.Stats) []string { return []string{u(s.DroppedLoss), u(s.DroppedQ)} }
	row := []string{strconv.FormatInt(p.window>>10, 10) + "KiB", p.outer, p.inner, strconv.FormatFloat(p.loss*100, 'g', -1, 64), p.mode,
		strconv.FormatFloat(float64(got)/dur.Seconds()/1000, 'f', 1, 64)}
	row = append(row, inner(ib, maxB)...)
	row = append(row, inner(ia, maxA)...)
	row = append(row, outer(ob)...)
	row = append(row, outer(oa)...)
	for _, s := range []netsim.Stats{legB.Up(), legB.Down(), legA.Up(), legA.Down()} {
		row = append(row, drops(s)...)
	}
	row = append(row, u(ob.MaxDatagramSize), u(oa.MaxDatagramSize))
	for _, e := range []struct {
		c       pconn.Counts
		dropped uint64
	}{{pb, b.pc.Dropped()}, {pa, a.pc.Dropped()}} {
		row = append(row, u(e.c.FramesSent), u(e.c.FramesReceived), u(e.c.DatagramsSent), u(e.c.DatagramsReceived), u(e.dropped))
	}
	return row, pathResult{float64(got) / dur.Seconds(), ib.PacketsLost, ib.SmoothedRTT}
}

func TestPathProblems(t *testing.T) {
	ms := time.Millisecond
	stream := pathResult{goodput: 100, srtt: 2000 * ms}
	for _, c := range []struct {
		name string
		k    pathPair
		d    pathResult
		want int
	}{
		{"lossy and fine", pathPair{64 << 10, "reno", "bbr", 0.01}, pathResult{goodput: 10, innerLost: 5, srtt: 600 * ms}, 0},
		{"lossy, no inner loss", pathPair{64 << 10, "reno", "bbr", 0.01}, pathResult{innerLost: 0, srtt: 600 * ms}, 1},
		{"lossy, slower RTT", pathPair{1 << 20, "bbr", "bbr", 0.01}, pathResult{innerLost: 5, srtt: 2000 * ms}, 1},
		{"no loss, gain 1.3", pathPair{64 << 10, "reno", "bbr", 0}, pathResult{goodput: 130}, 0},
		{"no loss, gain below 1.3", pathPair{64 << 10, "bbr", "reno", 0}, pathResult{goodput: 129}, 1},
		{"no loss, large window", pathPair{1 << 20, "bbr", "bbr", 0}, pathResult{goodput: 50}, 0},
		{"other loss", pathPair{64 << 10, "reno", "bbr", 0.005}, pathResult{goodput: 1}, 0},
	} {
		if got := pathProblems(c.k, stream, c.d); len(got) != c.want {
			t.Errorf("%s: %q, want %d problems", c.name, got, c.want)
		}
	}
}
