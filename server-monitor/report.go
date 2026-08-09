// report.go — derive rates from raw samples, then render the report.
//
// Every number the report shows is a difference between two consecutive
// samples divided by the wall time between them, so the analysis is identical
// whether it runs live at the end of a `watch` or later over a saved
// samples.jsonl.
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// runMeta is the sidecar written alongside the samples so a report rendered
// days later still knows what machine and what configuration produced it.
type runMeta struct {
	Version   string    `json:"version"`
	Started   time.Time `json:"started"`
	Host      hostInfo  `json:"host"`
	Interval  string    `json:"interval"`
	Match     string    `json:"match,omitempty"`
	Metrics   string    `json:"metrics,omitempty"`
	PProf     string    `json:"pprof,omitempty"`
	Health    string    `json:"health,omitempty"`
	Disc      string    `json:"disc,omitempty"`
	Config    string    `json:"config,omitempty"`
	PubKey    string    `json:"pubkey,omitempty"`
	SockNote  string    `json:"sock_note,omitempty"`
	CPUSpike  float64   `json:"cpu_spike,omitempty"`
	MbitSpike float64   `json:"mbit_spike,omitempty"`
}

func writeMeta(path string, m *runMeta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func readMeta(path string) (*runMeta, error) {
	b, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, err
	}
	var m runMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// rates is one interval's worth of derived numbers.
type rates struct {
	DT float64 // seconds between the two samples

	CPUPct     float64 // busy share of TOTAL capacity, 0..100
	CPUUser    float64
	CPUSys     float64
	CPUSoftIRQ float64
	CPUIOWait  float64
	CPUSteal   float64
	CPUIRQ     float64
	CPUMaxCore float64 // busiest single core; a pegged core hides in the average

	CtxtPerSec float64

	RxBytes float64 // per second, loopback excluded
	TxBytes float64
	RxPkts  float64
	TxPkts  float64
	RxMbit  float64
	TxMbit  float64
	RxDrop  float64
	TxDrop  float64

	SockOut float64 // bytes/s attributed to tracked processes (TCP payload)
	SockIn  float64
	Retrans float64
	NewConn float64
	DelConn float64

	NetStat map[string]float64 // per-second deltas of the kept counters
	ProcCPU map[int]float64    // pid -> % of one core
}

func safeDiv(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

// du is an unsigned counter difference that tolerates a counter reset (process
// restart, 32-bit wrap) by treating the decrease as "start again from here".
func du(cur, prev uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return 0
}

// computeRates differences two samples.
func computeRates(prev, cur *Sample) rates {
	r := rates{NetStat: map[string]float64{}, ProcCPU: map[int]float64{}}
	r.DT = cur.TS.Sub(prev.TS).Seconds()
	if r.DT <= 0 {
		r.DT = 1
	}

	// CPU comes from jiffy deltas, so it is exact for the interval rather
	// than a decaying average.
	totalD := float64(du(cur.CPU.Total(), prev.CPU.Total()))
	if totalD > 0 {
		pct := func(c, p uint64) float64 { return float64(du(c, p)) / totalD * 100 }
		r.CPUPct = float64(du(cur.CPU.Busy(), prev.CPU.Busy())) / totalD * 100
		r.CPUUser = pct(cur.CPU.User, prev.CPU.User) + pct(cur.CPU.Nice, prev.CPU.Nice)
		r.CPUSys = pct(cur.CPU.System, prev.CPU.System)
		r.CPUSoftIRQ = pct(cur.CPU.SoftIRQ, prev.CPU.SoftIRQ)
		r.CPUIOWait = pct(cur.CPU.IOWait, prev.CPU.IOWait)
		r.CPUSteal = pct(cur.CPU.Steal, prev.CPU.Steal)
		r.CPUIRQ = pct(cur.CPU.IRQ, prev.CPU.IRQ)
	}
	prevCores := map[string]CPUStat{}
	for _, c := range prev.Cores {
		prevCores[c.Name] = c
	}
	for _, c := range cur.Cores {
		p, ok := prevCores[c.Name]
		if !ok {
			continue
		}
		t := float64(du(c.Total(), p.Total()))
		if t <= 0 {
			continue
		}
		if v := float64(du(c.Busy(), p.Busy())) / t * 100; v > r.CPUMaxCore {
			r.CPUMaxCore = v
		}
	}

	r.CtxtPerSec = float64(du(cur.Ctxt, prev.Ctxt)) / r.DT

	for name, c := range cur.Ifaces {
		p, ok := prev.Ifaces[name]
		if !ok || name == "lo" {
			continue
		}
		r.RxBytes += float64(du(c.RxBytes, p.RxBytes)) / r.DT
		r.TxBytes += float64(du(c.TxBytes, p.TxBytes)) / r.DT
		r.RxPkts += float64(du(c.RxPackets, p.RxPackets)) / r.DT
		r.TxPkts += float64(du(c.TxPackets, p.TxPackets)) / r.DT
		r.RxDrop += float64(du(c.RxDrop, p.RxDrop)) / r.DT
		r.TxDrop += float64(du(c.TxDrop, p.TxDrop)) / r.DT
	}
	r.RxMbit = r.RxBytes * 8 / 1e6
	r.TxMbit = r.TxBytes * 8 / 1e6

	for k, v := range cur.NetStat {
		if p, ok := prev.NetStat[k]; ok {
			r.NetStat[k] = float64(du(v, p)) / r.DT
		}
	}

	// Socket byte counters are already per-interval deltas (see sock.go).
	if cur.Socks != nil {
		r.SockOut = float64(cur.Socks.BytesOutDelta) / r.DT
		r.SockIn = float64(cur.Socks.BytesInDelta) / r.DT
		r.Retrans = float64(cur.Socks.RetransDelta) / r.DT
		r.NewConn = float64(cur.Socks.NewConns) / r.DT
		r.DelConn = float64(cur.Socks.ClosedConns) / r.DT
	}

	prevJiff := map[int]uint64{}
	for _, p := range prev.Procs {
		prevJiff[p.PID] = p.Utime + p.Stime
	}
	for _, p := range prev.TopProcs {
		if _, ok := prevJiff[p.PID]; !ok {
			prevJiff[p.PID] = p.Utime + p.Stime
		}
	}
	addCPU := func(pid int, jiff uint64) {
		p, ok := prevJiff[pid]
		if !ok {
			return
		}
		r.ProcCPU[pid] = float64(du(jiff, p)) / clkTck / r.DT * 100
	}
	for _, p := range cur.Procs {
		addCPU(p.PID, p.Utime+p.Stime)
	}
	for _, p := range cur.TopProcs {
		if _, ok := r.ProcCPU[p.PID]; !ok {
			addCPU(p.PID, p.Utime+p.Stime)
		}
	}
	return r
}

// liveLine is the one-line console heartbeat during a watch.
func liveLine(s *Sample, r rates) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  cpu %5.1f%% (us%4.1f sy%4.1f si%4.1f st%4.1f)  ld %.2f  mem %2.0f%%",
		s.TS.Format("15:04:05"), r.CPUPct, r.CPUUser, r.CPUSys, r.CPUSoftIRQ, r.CPUSteal,
		s.Load[0], 100*safeDiv(float64(s.Mem.Used()), float64(s.Mem.Total)))
	fmt.Fprintf(&b, "  net ↓%7.2f ↑%7.2f Mbit/s", r.RxMbit, r.TxMbit)
	if s.Socks != nil {
		fmt.Fprintf(&b, "  tcp %d (+%d/-%d) ↑%.1f Mbit/s",
			s.Socks.TCPTotal, s.Socks.NewConns, s.Socks.ClosedConns, r.SockOut*8/1e6)
	}
	if t := primaryTarget(s); t != nil {
		var parts []string
		if v, ok := mval(t.Metrics, "dmsg_server_clients_count"); ok {
			parts = append(parts, fmt.Sprintf("cli %.0f", v))
		}
		if v, ok := mval(t.Metrics, "dmsg_server_vm_active_sessions_count"); ok {
			parts = append(parts, fmt.Sprintf("ses %.0f", v))
		}
		if v, ok := mval(t.Metrics, "dmsg_server_vm_active_streams_count"); ok {
			parts = append(parts, fmt.Sprintf("str %.0f", v))
		}
		if v, ok := mval(t.Metrics, "go_goroutines"); ok {
			parts = append(parts, fmt.Sprintf("go %.0f", v))
		}
		if len(parts) > 0 {
			fmt.Fprintf(&b, "  dmsg[%s]", strings.Join(parts, " "))
		}
	}
	if len(s.Procs) > 0 {
		p := s.Procs[0]
		fmt.Fprintf(&b, "  %s rss %s cpu %.0f%%", p.Name, humanBytes(p.RSS), r.ProcCPU[p.PID])
	}
	return b.String()
}

func primaryTarget(s *Sample) *TargetScrape {
	if len(s.Targets) == 0 {
		return nil
	}
	return &s.Targets[0]
}

// mval reads a Prometheus series by name, tolerating label suffixes.
func mval(m map[string]float64, name string) (float64, bool) {
	if m == nil {
		return 0, false
	}
	if v, ok := m[name]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.HasPrefix(k, name+"{") {
			return v, true
		}
	}
	return 0, false
}

// row is one analysed interval.
type row struct {
	T  time.Time
	DT float64

	CPU, User, Sys, SoftIRQ, IOWait, Steal, MaxCore float64
	Load1                                           float64
	MemUsedPct                                      float64
	SwapUsed                                        uint64
	Ctxt                                            float64
	ProcsRunning, ProcsBlocked                      int

	RxMbit, TxMbit float64
	RxPps, TxPps   float64
	RxDrop, TxDrop float64

	Conns, Estab, TimeWait, SynRecv int
	NewConn, DelConn                float64
	SockOutMbit, SockInMbit         float64
	Retrans                         float64
	SendQ, RecvQ                    uint64
	ListenBacklog                   uint32
	UDPSocks                        int

	// HasMetrics is false when the /metrics scrape failed for this interval.
	// Without it a failed scrape reads as "sessions dropped to zero", which
	// poisons every average, trend and correlation downstream.
	HasMetrics                             bool
	Goroutines, Clients, Sessions, Streams float64
	SessFail, StreamFail                   float64
	SessOK, StreamOK                       float64
	PktPerMin                              float64
	HeapMB, SvcRSSMB, SvcCPU               float64
	DiscClients                            int
	ScrapeErr                              string

	ProcCPU map[int]float64
	Peers   []PeerStat
}

// Report is the analysed run.
type Report struct {
	Meta    *runMeta
	Rows    []row
	Samples []*Sample
	// MetricRows is the subset of Rows whose /metrics scrape succeeded. All
	// service-metric statistics, trends and correlations use it so a failed
	// scrape never counts as a zero reading.
	MetricRows []row
	Start      time.Time
	End        time.Time
	Interval   time.Duration
	TopN       int

	Peers     []*peerTotal
	PeersFrom string // "exact" or "sampled"

	// Totals over the whole window.
	TotalRx, TotalTx        float64 // bytes
	TotalSockOut            float64
	TotalSockIn             float64
	TotalUDPIn, TotalUDPOut float64 // datagrams

	TrackedPIDs []int
	ProcNames   map[int]string
	SysProcCPU  map[int]*procCPUAgg

	Gaps  []string
	Notes []string
}

type procCPUAgg struct {
	PID  int
	Name string
	Cmd  string
	Sum  float64
	N    int
	Max  float64
}

// analyze differences the samples into rows and folds them into a Report.
// exactPeers, when non-nil, is the live collector's complete per-peer
// aggregate; without it the peer table is rebuilt from the (capped) per-sample
// top-N, which is accurate for the heavy hitters and undercounts the tail.
func analyze(samples []*Sample, meta *runMeta, exactPeers map[string]*peerTotal, topN int) *Report {
	if topN <= 0 {
		topN = 25
	}
	r := &Report{
		Meta: meta, Samples: samples, TopN: topN,
		ProcNames:  map[int]string{},
		SysProcCPU: map[int]*procCPUAgg{},
	}
	if meta == nil {
		r.Meta = &runMeta{Version: version, Host: hostInfo{}}
	}
	if len(samples) == 0 {
		return r
	}
	r.Start = samples[0].TS
	r.End = samples[len(samples)-1].TS

	// The run's cadence is the MEDIAN gap between samples, not the first one:
	// a single stalled tick must not redefine what "one interval" means for
	// the gap detector or for anything that reports "per interval".
	if len(samples) > 1 {
		gaps := make([]float64, 0, len(samples)-1)
		for i := 1; i < len(samples); i++ {
			gaps = append(gaps, samples[i].TS.Sub(samples[i-1].TS).Seconds())
		}
		sort.Float64s(gaps)
		r.Interval = time.Duration(gaps[len(gaps)/2] * float64(time.Second))
	}

	peerAgg := map[string]*peerTotal{}
	seenPID := map[int]bool{}

	for i := 1; i < len(samples); i++ {
		prev, cur := samples[i-1], samples[i]
		rt := computeRates(prev, cur)

		// A wall-clock jump means the machine was suspended, the process was
		// stopped, or the box was too loaded to schedule us. Flag it: rates
		// across such a gap are averages over the gap, not over the interval.
		if r.Interval > 0 && rt.DT > 3*r.Interval.Seconds() {
			r.Gaps = append(r.Gaps, fmt.Sprintf("%s → %s (%.0fs)",
				prev.TS.Format("15:04:05"), cur.TS.Format("15:04:05"), rt.DT))
		}

		w := row{
			T: cur.TS, DT: rt.DT,
			CPU: rt.CPUPct, User: rt.CPUUser, Sys: rt.CPUSys, SoftIRQ: rt.CPUSoftIRQ,
			IOWait: rt.CPUIOWait, Steal: rt.CPUSteal, MaxCore: rt.CPUMaxCore,
			Load1:        cur.Load[0],
			MemUsedPct:   100 * safeDiv(float64(cur.Mem.Used()), float64(cur.Mem.Total)),
			SwapUsed:     du(cur.Mem.SwapTotal, cur.Mem.SwapFree),
			Ctxt:         rt.CtxtPerSec,
			ProcsRunning: cur.ProcsRunning, ProcsBlocked: cur.ProcsBlocked,
			RxMbit: rt.RxMbit, TxMbit: rt.TxMbit,
			RxPps: rt.RxPkts, TxPps: rt.TxPkts,
			RxDrop: rt.RxDrop, TxDrop: rt.TxDrop,
			NewConn: rt.NewConn, DelConn: rt.DelConn,
			SockOutMbit: rt.SockOut * 8 / 1e6, SockInMbit: rt.SockIn * 8 / 1e6,
			Retrans: rt.Retrans,
			ProcCPU: rt.ProcCPU,
		}

		r.TotalRx += rt.RxBytes * rt.DT
		r.TotalTx += rt.TxBytes * rt.DT
		r.TotalSockOut += rt.SockOut * rt.DT
		r.TotalSockIn += rt.SockIn * rt.DT
		r.TotalUDPIn += rt.NetStat["Udp.InDatagrams"] * rt.DT
		r.TotalUDPOut += rt.NetStat["Udp.OutDatagrams"] * rt.DT

		if s := cur.Socks; s != nil {
			w.Conns = s.TCPTotal
			w.Estab = s.ByState["ESTABLISHED"]
			w.TimeWait = s.ByState["TIME_WAIT"]
			w.SynRecv = s.ByState["SYN_RECV"] + s.ByState["NEW_SYN_RECV"]
			w.SendQ, w.RecvQ = s.SendQ, s.RecvQ
			w.UDPSocks = s.UDPTotal
			for _, l := range s.Listen {
				if l.RQueue > w.ListenBacklog {
					w.ListenBacklog = l.RQueue
				}
			}
			w.Peers = s.Peers
			if exactPeers == nil {
				for _, p := range s.Peers {
					pt := peerAgg[p.IP]
					if pt == nil {
						pt = &peerTotal{IP: p.IP, FirstSeen: i}
						peerAgg[p.IP] = pt
					}
					pt.Out += p.OutDelta
					pt.In += p.InDelta
					pt.Retrans += p.Retrans
					pt.NewConns += p.NewConns
					pt.Samples++
					pt.LastSeen = i
					if p.Conns > pt.MaxConns {
						pt.MaxConns = p.Conns
					}
				}
			}
		}

		if t := primaryTarget(cur); t != nil {
			w.ScrapeErr = t.Err
			w.DiscClients = t.DiscClients
			w.HasMetrics = len(t.Metrics) > 0
			get := func(n string) float64 { v, _ := mval(t.Metrics, n); return v }
			w.Goroutines = get("go_goroutines")
			if w.Goroutines == 0 && t.GoroutineN > 0 {
				w.Goroutines = float64(t.GoroutineN)
			}
			w.Clients = get("dmsg_server_clients_count")
			w.Sessions = get("dmsg_server_vm_active_sessions_count")
			w.Streams = get("dmsg_server_vm_active_streams_count")
			w.PktPerMin = get("dmsg_server_packets_per_minute")
			w.HeapMB = get("go_memstats_heap_inuse_bytes") / 1e6
			if w.HeapMB == 0 {
				w.HeapMB = get("go_memstats_alloc_bytes") / 1e6
			}
			w.SvcRSSMB = get("process_resident_memory_bytes") / 1e6

			// Counters -> per-second rates.
			if pt := primaryTarget(prev); pt != nil {
				rate := func(n string) float64 {
					c, ok1 := mval(t.Metrics, n)
					p, ok2 := mval(pt.Metrics, n)
					if !ok1 || !ok2 || c < p {
						return 0
					}
					return (c - p) / rt.DT
				}
				w.SessFail = rate("dmsg_server_vm_session_fail_total")
				w.SessOK = rate("dmsg_server_vm_session_success_total")
				w.StreamFail = rate("dmsg_server_vm_stream_fail_total")
				w.StreamOK = rate("dmsg_server_vm_stream_success_total")
				w.SvcCPU = rate("process_cpu_seconds_total") * 100
			}
		}

		for _, p := range cur.Procs {
			if !seenPID[p.PID] {
				seenPID[p.PID] = true
				r.TrackedPIDs = append(r.TrackedPIDs, p.PID)
			}
			r.ProcNames[p.PID] = p.Name
		}
		for _, p := range cur.TopProcs {
			c, ok := rt.ProcCPU[p.PID]
			if !ok {
				continue
			}
			a := r.SysProcCPU[p.PID]
			if a == nil {
				a = &procCPUAgg{PID: p.PID, Name: p.Name, Cmd: p.Cmd}
				r.SysProcCPU[p.PID] = a
			}
			a.Sum += c
			a.N++
			if c > a.Max {
				a.Max = c
			}
		}

		r.Rows = append(r.Rows, w)
		if w.HasMetrics {
			r.MetricRows = append(r.MetricRows, w)
		}
	}

	src := exactPeers
	r.PeersFrom = "exact"
	if src == nil {
		src = peerAgg
		r.PeersFrom = "sampled"
	}
	for _, p := range src {
		r.Peers = append(r.Peers, p)
	}
	sort.Slice(r.Peers, func(i, j int) bool {
		a, b := r.Peers[i], r.Peers[j]
		if a.Out+a.In != b.Out+b.In {
			return a.Out+a.In > b.Out+b.In
		}
		if a.NewConns != b.NewConns {
			return a.NewConns > b.NewConns
		}
		return a.IP < b.IP // total order: reports of the same run must match
	})

	for _, s := range samples {
		for _, n := range s.Notes {
			if !containsStr(r.Notes, n) {
				r.Notes = append(r.Notes, n)
			}
		}
	}
	sort.Ints(r.TrackedPIDs)
	return r
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// ---------- statistics helpers ----------

type summary struct {
	Min, Avg, P50, P95, Max float64
	N                       int
}

func summarize(vals []float64) summary {
	s := summary{N: len(vals)}
	if len(vals) == 0 {
		return s
	}
	sorted := append([]float64(nil), vals...)
	sort.Float64s(sorted)
	var sum float64
	for _, v := range vals {
		sum += v
	}
	s.Min = sorted[0]
	s.Max = sorted[len(sorted)-1]
	s.Avg = sum / float64(len(vals))
	s.P50 = pct(sorted, 0.50)
	s.P95 = pct(sorted, 0.95)
	return s
}

func pct(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(q * float64(len(sorted)-1))
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

// metricSeries builds a service-metric series over the FULL row set, carrying
// the last good value across failed scrapes so the timeline shows a flat line
// rather than a hole punched down to zero. Statistics and trends use
// MetricRows instead, which simply omits the failed intervals.
func (r *Report) metricSeries(f func(row) float64) []float64 {
	out := make([]float64, 0, len(r.Rows))
	var last float64
	for _, w := range r.Rows {
		if w.HasMetrics {
			last = f(w)
		}
		out = append(out, last)
	}
	return out
}

func series(rows []row, f func(row) float64) []float64 {
	out := make([]float64, len(rows))
	for i, r := range rows {
		out[i] = f(r)
	}
	return out
}

// corr is Pearson's r. It is the fastest way to answer "does CPU follow
// bytes, or does CPU follow connection churn?" — the two have very different
// fixes.
func corr(a, b []float64) float64 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n < 3 {
		return 0
	}
	var sa, sb float64
	for i := 0; i < n; i++ {
		sa += a[i]
		sb += b[i]
	}
	ma, mb := sa/float64(n), sb/float64(n)
	var num, da, db float64
	for i := 0; i < n; i++ {
		x, y := a[i]-ma, b[i]-mb
		num += x * y
		da += x * x
		db += y * y
	}
	if da == 0 || db == 0 {
		return 0
	}
	return num / math.Sqrt(da*db)
}

// slopePerHour fits a least-squares line and returns its slope in units/hour —
// the leak detector. A goroutine count with a positive slope that never
// reverts is a leak; one that oscillates is load.
func slopePerHour(vals []float64, rows []row) float64 {
	n := len(vals)
	if n < 5 || len(rows) < n {
		return 0
	}
	t0 := rows[0].T
	var sx, sy, sxy, sxx float64
	for i := 0; i < n; i++ {
		x := rows[i].T.Sub(t0).Hours()
		y := vals[i]
		sx += x
		sy += y
		sxy += x * y
		sxx += x * x
	}
	fn := float64(n)
	den := fn*sxx - sx*sx
	if den == 0 {
		return 0
	}
	return (fn*sxy - sx*sy) / den
}

var sparkRunes = []rune("▁▂▃▄▅▆▇█")

// spark compresses a series to a fixed-width bar strip. Bucketed by MAX, not
// mean, so a one-sample spike inside an hours-long run still shows up.
func spark(vals []float64, width int) string {
	if len(vals) == 0 || width <= 0 {
		return ""
	}
	buckets := make([]float64, width)
	for i := 0; i < width; i++ {
		lo := i * len(vals) / width
		hi := (i + 1) * len(vals) / width
		if hi <= lo {
			hi = lo + 1
		}
		if lo >= len(vals) {
			lo = len(vals) - 1
		}
		if hi > len(vals) {
			hi = len(vals)
		}
		m := vals[lo]
		for _, v := range vals[lo:hi] {
			if v > m {
				m = v
			}
		}
		buckets[i] = m
	}
	max := 0.0
	for _, v := range buckets {
		if v > max {
			max = v
		}
	}
	var b strings.Builder
	for _, v := range buckets {
		if max <= 0 {
			b.WriteRune(sparkRunes[0])
			continue
		}
		i := int(v / max * float64(len(sparkRunes)-1))
		if i < 0 {
			i = 0
		}
		if i >= len(sparkRunes) {
			i = len(sparkRunes) - 1
		}
		b.WriteRune(sparkRunes[i])
	}
	return b.String()
}

// ---------- formatting helpers ----------

func humanBytes(b uint64) string { return humanFloat(float64(b), "B") }

func humanFloat(v float64, unit string) string {
	abs := math.Abs(v)
	switch {
	case abs >= 1<<50:
		return fmt.Sprintf("%.2f Pi%s", v/(1<<50), unit)
	case abs >= 1<<40:
		return fmt.Sprintf("%.2f Ti%s", v/(1<<40), unit)
	case abs >= 1<<30:
		return fmt.Sprintf("%.2f Gi%s", v/(1<<30), unit)
	case abs >= 1<<20:
		return fmt.Sprintf("%.1f Mi%s", v/(1<<20), unit)
	case abs >= 1<<10:
		return fmt.Sprintf("%.1f Ki%s", v/(1<<10), unit)
	default:
		return fmt.Sprintf("%.0f %s", v, unit)
	}
}

func humanCount(v float64) string {
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.2fG", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.2fM", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1fk", v/1e3)
	default:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
}

func sortStrings(s []string) { sort.Strings(s) }

func hdr(b *strings.Builder, title string) {
	fmt.Fprintf(b, "\n%s\n%s\n", title, strings.Repeat("─", len(title)+2))
}

// subnet groups an address into its /24 (v4) or /48 (v6), which is what shows
// a single actor spread over many addresses.
func subnet(ip string) string {
	if strings.Contains(ip, ":") {
		parts := strings.Split(ip, ":")
		if len(parts) >= 3 {
			return strings.Join(parts[:3], ":") + "::/48"
		}
		return ip
	}
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return strings.Join(parts[:3], ".") + ".0/24"
	}
	return ip
}
