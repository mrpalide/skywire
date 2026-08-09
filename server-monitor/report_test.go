// report_test.go — the analysis pipeline, pinned with synthetic samples.
//
// These run on any OS: they never touch /proc or netlink, they feed Sample
// structs straight into computeRates/analyze. That covers the arithmetic the
// whole report rests on — jiffies to CPU percent, cumulative counters to
// rates, per-peer deltas to totals — plus the two failure modes that produced
// wrong numbers in real runs: a short first interval, and a failed scrape
// being read as "the metric dropped to zero".
package main

import (
	"strings"
	"testing"
	"time"
)

var base = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

// mkSample builds a sample at t seconds past base with the given cumulative
// jiffies for the host and for one tracked process.
func mkSample(sec float64, hostBusy, hostIdle, procJiff uint64) *Sample {
	s := &Sample{
		TS: base.Add(time.Duration(sec * float64(time.Second))),
		// user carries all the host busy time; idle is the remainder.
		CPU:  CPUStat{Name: "total", User: hostBusy, Idle: hostIdle},
		Mem:  MemStat{Total: 1 << 30, Available: 1 << 29},
		Load: [3]float64{1, 1, 1},
		Procs: []ProcStat{{
			PID: 42, Name: "dmsg-server", Cmd: "/usr/bin/dmsg-server config.json",
			Utime: procJiff / 2, Stime: procJiff - procJiff/2,
			Threads: 8, RSS: 100 << 20, FDs: 50, FDLimit: 1024,
		}},
	}
	return s
}

func TestComputeRatesCPU(t *testing.T) {
	// One second of wall time on a 2-core box: 200 jiffies exist in total.
	// 100 of them busy => 50% of capacity.
	a := mkSample(0, 1000, 5000, 0)
	b := mkSample(1, 1100, 5100, 0)

	r := computeRates(a, b)
	if r.DT != 1 {
		t.Fatalf("DT = %v, want 1", r.DT)
	}
	if got, want := r.CPUPct, 50.0; got != want {
		t.Errorf("CPUPct = %v, want %v", got, want)
	}
}

// A process that consumes 200 jiffies of CPU in one second is using two full
// cores: 200% of one core. This is the number that came out as 395% when the
// interval was short, so it is worth pinning.
func TestComputeRatesProcCPU(t *testing.T) {
	clkTck = 100
	a := mkSample(0, 0, 100, 1000)
	b := mkSample(1, 0, 100, 1200)

	r := computeRates(a, b)
	if got := r.ProcCPU[42]; got != 200 {
		t.Errorf("ProcCPU = %v%%, want 200%%", got)
	}

	// Same jiffies over two seconds is half the rate.
	c := mkSample(2, 0, 100, 1400)
	r2 := computeRates(b, c)
	if got := r2.ProcCPU[42]; got != 200 {
		t.Errorf("ProcCPU over 1s = %v%%, want 200%%", got)
	}
	d := mkSample(4, 0, 100, 1600)
	r3 := computeRates(c, d)
	if got := r3.ProcCPU[42]; got != 100 {
		t.Errorf("ProcCPU over 2s = %v%%, want 100%%", got)
	}
}

// A counter that goes backwards (process restarted, 32-bit wrap) must not
// produce a huge bogus rate.
func TestComputeRatesCounterReset(t *testing.T) {
	a := mkSample(0, 1000, 1000, 5000)
	b := mkSample(1, 1100, 1100, 10) // process restarted
	r := computeRates(a, b)
	if got := r.ProcCPU[42]; got != 0 {
		t.Errorf("ProcCPU after a counter reset = %v, want 0", got)
	}
}

// The run's cadence must be the median gap, so one stalled tick cannot
// redefine what "one interval" means.
func TestAnalyzeIntervalIsMedian(t *testing.T) {
	samples := []*Sample{
		mkSample(0, 0, 100, 0),
		mkSample(10, 0, 100, 0),
		mkSample(20, 0, 100, 0),
		mkSample(95, 0, 100, 0), // a 75s stall
		mkSample(105, 0, 100, 0),
	}
	r := analyze(samples, nil, nil, 10)
	if got := r.Interval; got != 10*time.Second {
		t.Errorf("Interval = %v, want 10s (median of 10,10,75,10)", got)
	}
	if len(r.Gaps) != 1 {
		t.Errorf("Gaps = %d, want 1 (the 75s stall)", len(r.Gaps))
	}
}

// A failed /metrics scrape must be excluded, not counted as a zero reading —
// otherwise averages sag and the leak detector reports a phantom collapse.
func TestAnalyzeSkipsFailedScrapes(t *testing.T) {
	var samples []*Sample
	for i := 0; i < 6; i++ {
		s := mkSample(float64(i*10), uint64(i*100), uint64(i*100), uint64(i*100))
		tgt := TargetScrape{Name: "dmsg-server"}
		if i == 4 {
			tgt.Err = "connection refused" // no Metrics map at all
		} else {
			tgt.Metrics = map[string]float64{
				"dmsg_server_vm_active_sessions_count": 400,
				"go_goroutines":                        1000,
			}
		}
		s.Targets = []TargetScrape{tgt}
		samples = append(samples, s)
	}

	r := analyze(samples, nil, nil, 10)
	if len(r.MetricRows) != len(r.Rows)-1 {
		t.Fatalf("MetricRows = %d, Rows = %d; want exactly one excluded", len(r.MetricRows), len(r.Rows))
	}
	got := summarize(series(r.MetricRows, func(w row) float64 { return w.Sessions }))
	if got.Avg != 400 || got.Min != 400 {
		t.Errorf("sessions avg/min = %v/%v, want 400/400 — a failed scrape leaked in as zero", got.Avg, got.Min)
	}

	// The timeline series carries the last good value across the gap rather
	// than punching a hole down to zero.
	ts := r.metricSeries(func(w row) float64 { return w.Sessions })
	if len(ts) != len(r.Rows) {
		t.Fatalf("metricSeries length = %d, want %d", len(ts), len(r.Rows))
	}
	for i, v := range ts {
		if v != 400 {
			t.Errorf("metricSeries[%d] = %v, want 400 (carried forward)", i, v)
		}
	}
}

func TestAnalyzePeerAggregation(t *testing.T) {
	mk := func(sec float64, peers []PeerStat, out, in uint64) *Sample {
		s := mkSample(sec, 0, 100, 0)
		s.Socks = &SockSummary{
			Source: "netlink", TCPTotal: 3,
			ByState:       map[string]int{"ESTABLISHED": 3},
			BytesOutDelta: out, BytesInDelta: in,
			Peers: peers,
		}
		return s
	}
	samples := []*Sample{
		mk(0, nil, 0, 0),
		mk(10, []PeerStat{
			{IP: "1.2.3.4", Conns: 2, OutDelta: 1000, InDelta: 100, NewConns: 2},
			{IP: "5.6.7.8", Conns: 1, OutDelta: 500, InDelta: 50, NewConns: 1},
		}, 1500, 150),
		mk(20, []PeerStat{
			{IP: "1.2.3.4", Conns: 3, OutDelta: 2000, InDelta: 200},
		}, 2000, 200),
	}

	r := analyze(samples, nil, nil, 10)
	if len(r.Peers) != 2 {
		t.Fatalf("peers = %d, want 2", len(r.Peers))
	}
	top := r.Peers[0]
	if top.IP != "1.2.3.4" {
		t.Errorf("top peer = %s, want 1.2.3.4", top.IP)
	}
	if top.Out != 3000 || top.In != 300 {
		t.Errorf("top peer bytes = %d/%d, want 3000/300", top.Out, top.In)
	}
	if top.MaxConns != 3 {
		t.Errorf("top peer MaxConns = %d, want 3", top.MaxConns)
	}
	if top.NewConns != 2 {
		t.Errorf("top peer NewConns = %d, want 2", top.NewConns)
	}

	// Interval totals: 3500 bytes out over 20s of window.
	if r.TotalSockOut != 3500 {
		t.Errorf("TotalSockOut = %v, want 3500", r.TotalSockOut)
	}
}

// The same samples must render byte-identical reports; operators diff these.
func TestRenderIsDeterministic(t *testing.T) {
	var samples []*Sample
	for i := 0; i < 12; i++ {
		s := mkSample(float64(i*10), uint64(i*50), uint64(i*150), uint64(i*80))
		s.NetStat = map[string]uint64{
			"Tcp.InSegs": uint64(i * 1000), "Tcp.OutSegs": uint64(i * 1000),
			"Tcp.ActiveOpens": uint64(i * 10), "Tcp.PassiveOpens": uint64(i * 10),
			"IpExt.InOctets": uint64(i * 5000), "IpExt.OutOctets": uint64(i * 5000),
		}
		s.Ifaces = map[string]IfaceStat{
			"eth0": {RxBytes: uint64(i * 1e6), TxBytes: uint64(i * 2e6), RxPackets: uint64(i * 100), TxPackets: uint64(i * 200)},
		}
		s.Socks = &SockSummary{
			Source: "netlink", TCPTotal: 10, ByState: map[string]int{"ESTABLISHED": 10},
			BytesOutDelta: 1000, BytesInDelta: 500, NewConns: 1, ClosedConns: 1,
			Peers: []PeerStat{
				{IP: "10.0.0.1", Conns: 5, OutDelta: 500, InDelta: 250},
				{IP: "10.0.0.2", Conns: 5, OutDelta: 500, InDelta: 250}, // deliberate tie
			},
		}
		samples = append(samples, s)
	}

	first := analyze(samples, nil, nil, 10).Render()
	for i := 0; i < 8; i++ {
		if got := analyze(samples, nil, nil, 10).Render(); got != first {
			t.Fatalf("render %d differs from the first render; a sort is not a total order", i)
		}
	}
	for _, want := range []string{"SKYWIRE SERVER MONITOR REPORT", "FINDINGS", "TOP PEERS BY TRAFFIC"} {
		if !strings.Contains(first, want) {
			t.Errorf("report is missing the %q section", want)
		}
	}
}

func TestRenderHandlesTinyRuns(t *testing.T) {
	// One sample yields no intervals at all; the report must say so rather
	// than divide by zero.
	out := analyze([]*Sample{mkSample(0, 0, 100, 0)}, nil, nil, 10).Render()
	if !strings.Contains(out, "Not enough samples") {
		t.Errorf("single-sample report should explain itself, got:\n%s", out)
	}
	if out := analyze(nil, nil, nil, 10).Render(); out == "" {
		t.Error("empty-sample report should still render a header")
	}
}

func TestSummarizeAndSpark(t *testing.T) {
	s := summarize([]float64{1, 2, 3, 4, 100})
	if s.Min != 1 || s.Max != 100 {
		t.Errorf("min/max = %v/%v, want 1/100", s.Min, s.Max)
	}
	if s.Avg != 22 {
		t.Errorf("avg = %v, want 22", s.Avg)
	}
	// A single spike must survive bucketing — that is why spark uses the
	// bucket max rather than the mean.
	vals := make([]float64, 600)
	vals[300] = 1000
	sp := spark(vals, 60)
	if len([]rune(sp)) != 60 {
		t.Fatalf("spark width = %d runes, want 60", len([]rune(sp)))
	}
	if !strings.ContainsRune(sp, '█') {
		t.Errorf("spark lost the spike: %q", sp)
	}
}

func TestCorrAndSlope(t *testing.T) {
	a := []float64{1, 2, 3, 4, 5, 6, 7, 8}
	b := []float64{2, 4, 6, 8, 10, 12, 14, 16}
	if got := corr(a, b); got < 0.999 {
		t.Errorf("corr of perfectly proportional series = %v, want ~1", got)
	}
	c := []float64{8, 7, 6, 5, 4, 3, 2, 1}
	if got := corr(a, c); got > -0.999 {
		t.Errorf("corr of inverted series = %v, want ~-1", got)
	}

	// 100 units of growth per hour, sampled every 6 minutes.
	var rows []row
	var vals []float64
	for i := 0; i < 11; i++ {
		rows = append(rows, row{T: base.Add(time.Duration(i) * 6 * time.Minute)})
		vals = append(vals, float64(i)*10)
	}
	if got := slopePerHour(vals, rows); got < 99.9 || got > 100.1 {
		t.Errorf("slopePerHour = %v, want ~100", got)
	}
}

func TestSubnetGrouping(t *testing.T) {
	cases := map[string]string{
		"192.168.1.55":    "192.168.1.0/24",
		"8.8.8.8":         "8.8.8.0/24",
		"2001:db8:1:2::5": "2001:db8:1::/48",
	}
	for in, want := range cases {
		if got := subnet(in); got != want {
			t.Errorf("subnet(%q) = %q, want %q", in, got, want)
		}
	}
}
