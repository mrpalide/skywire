// render.go — the human-readable report.
//
// Section order follows the question an operator actually asks, in order:
// was it real, how bad, was it us, who did it, and what was the process doing.
package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const sparkWidth = 64

// gaugeCounters are the /proc/net entries that are point-in-time values rather
// than monotonic counters. Differencing them produces a meaningless "rate".
var gaugeCounters = map[string]bool{"Tcp.CurrEstab": true}

// Render produces the whole report as text.
func (r *Report) Render() string {
	var b strings.Builder

	r.renderHeader(&b)
	if len(r.Rows) == 0 {
		b.WriteString("\nNot enough samples to derive any rate (need at least 2).\n")
		return b.String()
	}
	r.renderTimeline(&b)
	r.renderCPU(&b)
	r.renderMemory(&b)
	r.renderNetwork(&b)
	r.renderAttribution(&b)
	r.renderConnections(&b)
	r.renderPeers(&b)
	r.renderSubnets(&b)
	r.renderChurn(&b)
	r.renderDmsg(&b)
	r.renderProcesses(&b)
	r.renderSystemProcesses(&b)
	r.renderSpikes(&b)
	r.renderCorrelations(&b)
	r.renderKernelCounters(&b)
	r.renderFindings(&b)

	return b.String()
}

func (r *Report) renderHeader(b *strings.Builder) {
	dur := r.End.Sub(r.Start)
	fmt.Fprintf(b, "%s\n", strings.Repeat("═", 100))
	fmt.Fprintf(b, "SKYWIRE SERVER MONITOR REPORT\n")
	fmt.Fprintf(b, "%s\n", strings.Repeat("═", 100))
	h := r.Meta.Host
	fmt.Fprintf(b, "host        %s   %d cpu   %s ram   kernel %s\n",
		orDash(h.Hostname), h.NumCPU, humanBytes(h.MemTotal), orDash(h.Kernel))
	if h.Model != "" {
		fmt.Fprintf(b, "cpu model   %s\n", h.Model)
	}
	fmt.Fprintf(b, "window      %s → %s   (%s, %d samples @ %s)\n",
		r.Start.Format("2006-01-02 15:04:05"), r.End.Format("2006-01-02 15:04:05"),
		dur.Round(time.Second), len(r.Samples), r.Interval.Round(time.Second))
	if r.Meta.PubKey != "" {
		fmt.Fprintf(b, "server pk   %s\n", r.Meta.PubKey)
	}
	if len(r.Gaps) > 0 {
		fmt.Fprintf(b, "gaps        %d sampling gap(s): %s\n", len(r.Gaps), strings.Join(firstN(r.Gaps, 4), ", "))
	}
	for _, n := range r.Notes {
		fmt.Fprintf(b, "note        %s\n", n)
	}
}

// renderTimeline is the whole run at a glance: one strip per metric, same time
// axis, so a shape that repeats across CPU and egress is visible immediately.
func (r *Report) renderTimeline(b *strings.Builder) {
	hdr(b, "TIMELINE  (each strip spans the full window, left = oldest; bar height is the interval peak)")

	strip := func(label string, vals []float64, unit string) {
		s := summarize(vals)
		if s.Max < 0.01 {
			return // nothing happened on this metric; a flat strip is noise
		}
		fmt.Fprintf(b, "  %-14s %s  peak %s%s\n", label, spark(vals, sparkWidth), trimNum(s.Max), unit)
	}
	strip("cpu", series(r.Rows, func(w row) float64 { return w.CPU }), "%")
	strip("egress", series(r.Rows, func(w row) float64 { return w.TxMbit }), " Mbit/s")
	strip("ingress", series(r.Rows, func(w row) float64 { return w.RxMbit }), " Mbit/s")
	strip("peer egress", series(r.Rows, func(w row) float64 { return w.SockOutMbit }), " Mbit/s")
	strip("tcp conns", series(r.Rows, func(w row) float64 { return float64(w.Conns) }), "")
	strip("new conns/s", series(r.Rows, func(w row) float64 { return w.NewConn }), "/s")
	strip("sessions", r.metricSeries(func(w row) float64 { return w.Sessions }), "")
	strip("streams", r.metricSeries(func(w row) float64 { return w.Streams }), "")
	strip("goroutines", r.metricSeries(func(w row) float64 { return w.Goroutines }), "")
	strip("rss (svc)", r.metricSeries(func(w row) float64 { return w.SvcRSSMB }), " MB")

	// A short time ruler so a bar position can be read back to a clock time.
	fmt.Fprintf(b, "  %-14s %s\n", "", timeRuler(r.Start, r.End, sparkWidth))
}

func (r *Report) renderCPU(b *strings.Builder) {
	hdr(b, "CPU")
	cols := []struct {
		name string
		f    func(row) float64
	}{
		{"total busy %", func(w row) float64 { return w.CPU }},
		{"user %", func(w row) float64 { return w.User }},
		{"system %", func(w row) float64 { return w.Sys }},
		{"softirq %", func(w row) float64 { return w.SoftIRQ }},
		{"iowait %", func(w row) float64 { return w.IOWait }},
		{"steal %", func(w row) float64 { return w.Steal }},
		{"busiest core %", func(w row) float64 { return w.MaxCore }},
		{"load1", func(w row) float64 { return w.Load1 }},
		{"ctx switch/s", func(w row) float64 { return w.Ctxt }},
		{"runnable", func(w row) float64 { return float64(w.ProcsRunning) }},
	}
	fmt.Fprintf(b, "  %-16s %8s %8s %8s %8s\n", "", "avg", "p50", "p95", "max")
	for _, c := range cols {
		s := summarize(series(r.Rows, c.f))
		if s.Max == 0 {
			continue
		}
		fmt.Fprintf(b, "  %-16s %8s %8s %8s %8s\n", c.name,
			trimNum(s.Avg), trimNum(s.P50), trimNum(s.P95), trimNum(s.Max))
	}
	if r.Meta.Host.NumCPU > 0 {
		s := summarize(series(r.Rows, func(w row) float64 { return w.CPU }))
		fmt.Fprintf(b, "\n  in core terms: avg %.2f of %d cores busy, peak %.2f cores\n",
			s.Avg/100*float64(r.Meta.Host.NumCPU), r.Meta.Host.NumCPU, s.Max/100*float64(r.Meta.Host.NumCPU))
	}
}

func (r *Report) renderMemory(b *strings.Builder) {
	last := r.Samples[len(r.Samples)-1]
	hdr(b, "MEMORY")
	s := summarize(series(r.Rows, func(w row) float64 { return w.MemUsedPct }))
	fmt.Fprintf(b, "  used         avg %.1f%%  p95 %.1f%%  max %.1f%%   (of %s)\n",
		s.Avg, s.P95, s.Max, humanBytes(last.Mem.Total))
	fmt.Fprintf(b, "  now          used %s   available %s   cached %s\n",
		humanBytes(last.Mem.Used()), humanBytes(last.Mem.Available), humanBytes(last.Mem.Cached))
	sw := summarize(series(r.Rows, func(w row) float64 { return float64(w.SwapUsed) }))
	if sw.Max > 0 {
		fmt.Fprintf(b, "  swap         used max %s of %s  ← swapping on a network service is a latency source\n",
			humanBytes(uint64(sw.Max)), humanBytes(last.Mem.SwapTotal))
	}
	if len(last.Pressure) > 0 {
		fmt.Fprintf(b, "  PSI avg10    cpu %.2f  io %.2f  mem %.2f  (%% of time tasks were stalled)\n",
			last.Pressure["cpu.some.avg10"], last.Pressure["io.some.avg10"], last.Pressure["memory.some.avg10"])
	}
}

func (r *Report) renderNetwork(b *strings.Builder) {
	hdr(b, "NETWORK  (all interfaces except loopback)")
	tx := summarize(series(r.Rows, func(w row) float64 { return w.TxMbit }))
	rx := summarize(series(r.Rows, func(w row) float64 { return w.RxMbit }))
	txp := summarize(series(r.Rows, func(w row) float64 { return w.TxPps }))
	rxp := summarize(series(r.Rows, func(w row) float64 { return w.RxPps }))

	fmt.Fprintf(b, "  %-22s %10s %10s %10s %10s\n", "", "avg", "p50", "p95", "max")
	fmt.Fprintf(b, "  %-22s %10s %10s %10s %10s\n", "egress Mbit/s",
		trimNum(tx.Avg), trimNum(tx.P50), trimNum(tx.P95), trimNum(tx.Max))
	fmt.Fprintf(b, "  %-22s %10s %10s %10s %10s\n", "ingress Mbit/s",
		trimNum(rx.Avg), trimNum(rx.P50), trimNum(rx.P95), trimNum(rx.Max))
	fmt.Fprintf(b, "  %-22s %10s %10s %10s %10s\n", "egress packets/s",
		trimNum(txp.Avg), trimNum(txp.P50), trimNum(txp.P95), trimNum(txp.Max))
	fmt.Fprintf(b, "  %-22s %10s %10s %10s %10s\n", "ingress packets/s",
		trimNum(rxp.Avg), trimNum(rxp.P50), trimNum(rxp.P95), trimNum(rxp.Max))

	dur := r.End.Sub(r.Start).Seconds()
	fmt.Fprintf(b, "\n  transferred over the window: out %s, in %s (over %s)\n",
		humanFloat(r.TotalTx, "B"), humanFloat(r.TotalRx, "B"), humanDuration(r.End.Sub(r.Start)))
	if r.TotalRx > 0 {
		fmt.Fprintf(b, "  egress/ingress ratio: %.2f×\n", r.TotalTx/r.TotalRx)
	}
	if tx.Avg > 0 {
		fmt.Fprintf(b, "  sustained at the average rate that is %s/day\n", humanFloat(tx.Avg*1e6/8*86400, "B"))
	}
	if txp.Avg > 0 {
		fmt.Fprintf(b, "  mean egress packet size %.0f B  (small packets ⇒ CPU per byte is high)\n",
			safeDiv(r.TotalTx, txp.Avg*dur))
	}

	drop := summarize(series(r.Rows, func(w row) float64 { return w.RxDrop + w.TxDrop }))
	if drop.Max > 0 {
		fmt.Fprintf(b, "  interface drops: avg %.2f/s, max %.2f/s\n", drop.Avg, drop.Max)
	}

	// Per-interface split, so a busy private/VPN interface is not confused
	// with the billed public one.
	first, last := r.Samples[0], r.Samples[len(r.Samples)-1]
	type ifTot struct {
		name   string
		rx, tx uint64
	}
	var ifs []ifTot
	for name, c := range last.Ifaces {
		p, ok := first.Ifaces[name]
		if !ok {
			continue
		}
		t := ifTot{name: name, rx: du(c.RxBytes, p.RxBytes), tx: du(c.TxBytes, p.TxBytes)}
		if t.rx == 0 && t.tx == 0 {
			continue
		}
		ifs = append(ifs, t)
	}
	sort.Slice(ifs, func(i, j int) bool {
		if ifs[i].tx+ifs[i].rx != ifs[j].tx+ifs[j].rx {
			return ifs[i].tx+ifs[i].rx > ifs[j].tx+ifs[j].rx
		}
		return ifs[i].name < ifs[j].name
	})
	if len(ifs) > 0 {
		fmt.Fprintf(b, "\n  %-14s %14s %14s\n", "interface", "out", "in")
		for _, t := range ifs {
			fmt.Fprintf(b, "  %-14s %14s %14s\n", t.name, humanBytes(t.tx), humanBytes(t.rx))
		}
	}
}

// renderAttribution reconciles what the NIC moved against what we could pin on
// a TCP connection of the tracked process. The gap is the answer to "is this
// even the dmsg-server's traffic?".
func (r *Report) renderAttribution(b *strings.Builder) {
	if r.TotalSockOut == 0 && r.TotalSockIn == 0 {
		return
	}
	hdr(b, "TRAFFIC ATTRIBUTION")
	// coverage is only meaningful when the interface counter is the larger of
	// the two. When attributed bytes EXCEED what left the NIC, the traffic is
	// on loopback — which is deliberately excluded from the interface totals —
	// and a percentage would be a meaningless multiple of a tiny denominator.
	coverage := func(sock, iface float64) string {
		if iface <= 0 {
			return "(no interface traffic — this is loopback traffic)"
		}
		if sock > iface*1.2 {
			return "(exceeds interface traffic — mostly loopback, which is excluded above)"
		}
		return fmt.Sprintf("(%.0f%% of it)", 100*sock/iface)
	}
	fmt.Fprintf(b, "  interface egress (excl. lo) %14s\n", humanFloat(r.TotalTx, "B"))
	fmt.Fprintf(b, "  tracked TCP payload out     %14s   %s\n",
		humanFloat(r.TotalSockOut, "B"), coverage(r.TotalSockOut, r.TotalTx))
	fmt.Fprintf(b, "  interface ingress (excl. lo)%14s\n", humanFloat(r.TotalRx, "B"))
	fmt.Fprintf(b, "  tracked TCP payload in      %14s   %s\n",
		humanFloat(r.TotalSockIn, "B"), coverage(r.TotalSockIn, r.TotalRx))
	if v, ok := deltaCounter(r, "IpExt.OutOctets"); ok && v > 0 {
		fmt.Fprintf(b, "  IP layer out (incl. lo)     %14s\n", humanFloat(float64(v), "B"))
	}
	if r.TotalUDPOut > 0 || r.TotalUDPIn > 0 {
		fmt.Fprintf(b, "  UDP datagrams               out %s, in %s   (dmsg QUIC/WebTransport rides UDP)\n",
			humanCount(r.TotalUDPOut), humanCount(r.TotalUDPIn))
	}
	b.WriteString("\n  How to read this: TCP payload excludes TCP/IP/Ethernet headers, so ~90-95% coverage\n" +
		"  means essentially all traffic is the tracked process's TCP connections. A much lower\n" +
		"  figure means the bytes are going somewhere else — UDP/QUIC, another process, or a\n" +
		"  process whose sockets we could not read (run as root).\n")

	// The one systematic blind spot, stated rather than hidden: a connection
	// that opens AND closes between two ticks is never sampled, so its bytes
	// are missing from every per-peer figure.
	closed := summarize(series(r.Rows, func(w row) float64 { return w.DelConn * w.DT }))
	live := summarize(series(r.Rows, func(w row) float64 { return float64(w.Conns) }))
	if closed.Avg > 0 && live.Avg > 0 && closed.Avg > 0.5*live.Avg {
		fmt.Fprintf(b, "\n  ⚠ High turnover: %.0f connection(s) closed per %s interval against %.0f open at a\n"+
			"    time. Connections that open and close entirely between two samples are never seen,\n"+
			"    so per-peer byte totals UNDERCOUNT here. Re-run with a shorter -interval to narrow\n"+
			"    the blind spot.\n", closed.Avg, r.Interval.Round(time.Second), live.Avg)
	}
}

func (r *Report) renderConnections(b *strings.Builder) {
	conns := summarize(series(r.Rows, func(w row) float64 { return float64(w.Conns) }))
	if conns.Max == 0 {
		return
	}
	hdr(b, "CONNECTIONS")
	show := func(label string, f func(row) float64, unit string) {
		s := summarize(series(r.Rows, f))
		if s.Max == 0 {
			return
		}
		fmt.Fprintf(b, "  %-22s avg %10s  p95 %10s  max %10s %s\n",
			label, trimNum(s.Avg), trimNum(s.P95), trimNum(s.Max), unit)
	}
	show("tcp sockets", func(w row) float64 { return float64(w.Conns) }, "")
	show("  established", func(w row) float64 { return float64(w.Estab) }, "")
	show("  time_wait", func(w row) float64 { return float64(w.TimeWait) }, "")
	show("  syn_recv", func(w row) float64 { return float64(w.SynRecv) }, "")
	show("new conns", func(w row) float64 { return w.NewConn }, "/s")
	show("closed conns", func(w row) float64 { return w.DelConn }, "/s")
	show("send queue", func(w row) float64 { return float64(w.SendQ) }, "bytes queued")
	show("recv queue", func(w row) float64 { return float64(w.RecvQ) }, "bytes queued")
	show("listen backlog", func(w row) float64 { return float64(w.ListenBacklog) }, "waiting to be accepted")
	show("udp sockets", func(w row) float64 { return float64(w.UDPSocks) }, "")
	show("retransmits", func(w row) float64 { return w.Retrans }, "/s")

	nc := summarize(series(r.Rows, func(w row) float64 { return w.NewConn }))
	if nc.Avg > 0 && conns.Avg > 0 {
		fmt.Fprintf(b, "\n  mean connection lifetime ≈ %s  (avg sockets ÷ avg new-connection rate)\n",
			time.Duration(conns.Avg/nc.Avg*float64(time.Second)).Round(time.Second))
	}
	if last := r.Samples[len(r.Samples)-1]; last.Socks != nil && len(last.Socks.Listen) > 0 {
		b.WriteString("\n  listening sockets at end of run:\n")
		for _, l := range last.Socks.Listen {
			fmt.Fprintf(b, "    %-28s accept-queue %d / %d\n", l.Addr, l.RQueue, l.WQueue)
		}
	}
}

func (r *Report) renderPeers(b *strings.Builder) {
	if len(r.Peers) == 0 {
		return
	}
	hdr(b, fmt.Sprintf("TOP PEERS BY TRAFFIC  (%d distinct remote addresses seen; %s accounting)",
		len(r.Peers), r.PeersFrom))

	var totOut, totIn float64
	for _, p := range r.Peers {
		totOut += float64(p.Out)
		totIn += float64(p.In)
	}
	dur := r.End.Sub(r.Start).Seconds()

	fmt.Fprintf(b, "  %-42s %11s %8s %11s %9s %7s %7s\n",
		"remote address", "out", "share", "in", "avg Mb/s", "conns", "new")
	fmt.Fprintf(b, "  %s\n", strings.Repeat("─", 100))
	for i, p := range r.Peers {
		if i >= r.TopN {
			break
		}
		fmt.Fprintf(b, "  %-42s %11s %7.1f%% %11s %9.2f %7d %7d\n",
			truncate(p.IP, 42),
			humanFloat(float64(p.Out), "B"),
			100*safeDiv(float64(p.Out), totOut),
			humanFloat(float64(p.In), "B"),
			safeDiv(float64(p.Out)*8, dur*1e6),
			p.MaxConns, p.NewConns)
	}
	if len(r.Peers) > r.TopN {
		var restOut, restIn float64
		for _, p := range r.Peers[r.TopN:] {
			restOut += float64(p.Out)
			restIn += float64(p.In)
		}
		fmt.Fprintf(b, "  %-42s %11s %7.1f%% %11s\n",
			fmt.Sprintf("… %d more", len(r.Peers)-r.TopN),
			humanFloat(restOut, "B"), 100*safeDiv(restOut, totOut), humanFloat(restIn, "B"))
	}
	// Concentration: how few peers account for most of the egress.
	if totOut > 0 {
		var cum float64
		var n50, n90 int
		for i, p := range r.Peers {
			cum += float64(p.Out)
			if n50 == 0 && cum >= 0.5*totOut {
				n50 = i + 1
			}
			if n90 == 0 && cum >= 0.9*totOut {
				n90 = i + 1
				break
			}
		}
		fmt.Fprintf(b, "\n  concentration: %d peer(s) account for 50%% of egress, %d for 90%%\n", n50, n90)
	}
	if r.PeersFrom == "sampled" {
		b.WriteString("  (rebuilt from the per-sample top-N in samples.jsonl: heavy hitters are exact,\n" +
			"   the long tail is undercounted. peers.csv from the original run has the full set.)\n")
	}
}

func (r *Report) renderSubnets(b *strings.Builder) {
	if len(r.Peers) < 5 {
		return
	}
	type sn struct {
		net   string
		out   float64
		in    float64
		ips   int
		conns int
		news  int
	}
	m := map[string]*sn{}
	for _, p := range r.Peers {
		k := subnet(p.IP)
		s := m[k]
		if s == nil {
			s = &sn{net: k}
			m[k] = s
		}
		s.out += float64(p.Out)
		s.in += float64(p.In)
		s.ips++
		s.conns += p.MaxConns
		s.news += p.NewConns
	}
	var list []*sn
	for _, s := range m {
		list = append(list, s)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].out+list[i].in != list[j].out+list[j].in {
			return list[i].out+list[i].in > list[j].out+list[j].in
		}
		return list[i].net < list[j].net
	})

	// Only worth printing when grouping actually merges something.
	if len(list) >= len(r.Peers) {
		return
	}
	hdr(b, "TOP NETWORKS  (peers grouped by /24 or /48 — one actor spread over many addresses)")
	fmt.Fprintf(b, "  %-24s %12s %12s %8s %8s %8s\n", "network", "out", "in", "addrs", "conns", "new")
	for i, s := range list {
		if i >= 12 {
			break
		}
		fmt.Fprintf(b, "  %-24s %12s %12s %8d %8d %8d\n",
			s.net, humanFloat(s.out, "B"), humanFloat(s.in, "B"), s.ips, s.conns, s.news)
	}
}

func (r *Report) renderChurn(b *strings.Builder) {
	churn := make([]*peerTotal, len(r.Peers))
	copy(churn, r.Peers)
	sort.Slice(churn, func(i, j int) bool {
		if churn[i].NewConns != churn[j].NewConns {
			return churn[i].NewConns > churn[j].NewConns
		}
		return churn[i].IP < churn[j].IP
	})
	if len(churn) == 0 || churn[0].NewConns < 5 {
		return
	}
	hdr(b, "TOP PEERS BY CONNECTION CHURN  (reconnect loops burn CPU on handshakes, not on bytes)")
	dur := r.End.Sub(r.Start).Minutes()
	fmt.Fprintf(b, "  %-42s %10s %12s %11s %10s\n", "remote address", "new conns", "per minute", "bytes out", "max conns")
	for i, p := range churn {
		if i >= 12 || p.NewConns < 5 {
			break
		}
		fmt.Fprintf(b, "  %-42s %10d %12.1f %11s %10d\n",
			truncate(p.IP, 42), p.NewConns, safeDiv(float64(p.NewConns), dur),
			humanFloat(float64(p.Out), "B"), p.MaxConns)
	}
}

func (r *Report) renderDmsg(b *strings.Builder) {
	mrows := r.MetricRows
	if len(mrows) == 0 {
		hdr(b, "DMSG-SERVER INTERNAL METRICS")
		b.WriteString("  Not collected. Start the server with `-m 127.0.0.1:9081` and re-run to get\n" +
			"  session/stream counts, handshake failure rates and Go runtime numbers.\n")
		return
	}
	hdr(b, "DMSG-SERVER INTERNAL METRICS")
	if n := len(r.Rows) - len(mrows); n > 0 {
		fmt.Fprintf(b, "  (%d of %d intervals had no successful scrape and are excluded from these figures)\n\n",
			n, len(r.Rows))
	}
	show := func(label string, f func(row) float64, unit string) {
		s := summarize(series(mrows, f))
		if s.Max == 0 && s.Avg == 0 {
			return
		}
		fmt.Fprintf(b, "  %-24s avg %10s  p95 %10s  max %10s %s\n",
			label, trimNum(s.Avg), trimNum(s.P95), trimNum(s.Max), unit)
	}
	show("clients", func(w row) float64 { return w.Clients }, "")
	show("active sessions", func(w row) float64 { return w.Sessions }, "")
	show("active streams", func(w row) float64 { return w.Streams }, "")
	show("session success", func(w row) float64 { return w.SessOK }, "/s")
	show("session FAIL", func(w row) float64 { return w.SessFail }, "/s")
	show("stream success", func(w row) float64 { return w.StreamOK }, "/s")
	show("stream FAIL", func(w row) float64 { return w.StreamFail }, "/s")
	show("packets/minute gauge", func(w row) float64 { return w.PktPerMin }, "")
	show("goroutines", func(w row) float64 { return w.Goroutines }, "")
	show("heap in use", func(w row) float64 { return w.HeapMB }, "MB")
	show("process rss", func(w row) float64 { return w.SvcRSSMB }, "MB")
	show("process cpu", func(w row) float64 { return w.SvcCPU }, "% of one core")
	show("delegated clients", func(w row) float64 { return float64(w.DiscClients) }, "(from discovery)")

	// Growth rates — the leak detectors.
	fmt.Fprintf(b, "\n  trend over the window (least-squares slope):\n")
	trend := func(label string, f func(row) float64, unit string) {
		v := series(mrows, f)
		s := summarize(v)
		if s.Max == 0 || len(v) < 5 {
			return
		}
		sl := slopePerHour(v, mrows)
		fmt.Fprintf(b, "    %-22s %+9.2f %s/hour   (start %s → end %s)\n",
			label, sl, unit, trimNum(v[0]), trimNum(v[len(v)-1]))
	}
	trend("goroutines", func(w row) float64 { return w.Goroutines }, "")
	trend("heap in use", func(w row) float64 { return w.HeapMB }, "MB")
	trend("process rss", func(w row) float64 { return w.SvcRSSMB }, "MB")
	trend("active sessions", func(w row) float64 { return w.Sessions }, "")
	trend("active streams", func(w row) float64 { return w.Streams }, "")

	// Goroutine breakdown from the last pprof scrape.
	for i := len(r.Samples) - 1; i >= 0; i-- {
		t := primaryTarget(r.Samples[i])
		if t == nil || len(t.Goroutines) == 0 {
			continue
		}
		type gr struct {
			fn string
			n  int
		}
		var list []gr
		for fn, n := range t.Goroutines {
			list = append(list, gr{fn, n})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].n != list[j].n {
				return list[i].n > list[j].n
			}
			return list[i].fn < list[j].fn
		})
		fmt.Fprintf(b, "\n  goroutines by parked function (last scrape, %d total):\n", t.GoroutineN)
		for j, g := range list {
			if j >= 12 {
				break
			}
			fmt.Fprintf(b, "    %6d  %s\n", g.n, g.fn)
		}
		break
	}

	// Scrape failures are themselves a symptom: a server too busy to answer
	// /metrics is a server too busy to answer clients.
	var failed int
	var lastErr string
	for _, w := range r.Rows {
		if w.ScrapeErr != "" {
			failed++
			lastErr = w.ScrapeErr
		}
	}
	if failed > 0 {
		fmt.Fprintf(b, "\n  ⚠ %d/%d scrapes failed (last: %s)\n", failed, len(r.Rows), truncate(lastErr, 120))
	}
}

func (r *Report) renderProcesses(b *strings.Builder) {
	if len(r.TrackedPIDs) == 0 {
		return
	}
	hdr(b, "TRACKED PROCESSES")
	for _, pid := range r.TrackedPIDs {
		cpu := summarize(seriesPID(r.Rows, pid))
		var first, last, maxRSS uint64
		var maxFD, fdLimit, maxThreads int
		var cmd string
		var volCtx, nvolCtx uint64
		var firstSeen, lastSeen *ProcStat
		for _, s := range r.Samples {
			for i := range s.Procs {
				p := &s.Procs[i]
				if p.PID != pid {
					continue
				}
				if firstSeen == nil {
					firstSeen = p
					first = p.RSS
					cmd = p.Cmd
				}
				lastSeen = p
				last = p.RSS
				if p.RSS > maxRSS {
					maxRSS = p.RSS
				}
				if p.FDs > maxFD {
					maxFD = p.FDs
				}
				if p.FDLimit > 0 {
					fdLimit = p.FDLimit
				}
				if p.Threads > maxThreads {
					maxThreads = p.Threads
				}
			}
		}
		if firstSeen == nil || lastSeen == nil {
			continue
		}
		volCtx = du(lastSeen.VolCtx, firstSeen.VolCtx)
		nvolCtx = du(lastSeen.NvolCtx, firstSeen.NvolCtx)
		dur := r.End.Sub(r.Start).Seconds()

		fmt.Fprintf(b, "\n  pid %d  %s\n", pid, r.ProcNames[pid])
		fmt.Fprintf(b, "    cmd            %s\n", truncate(cmd, 150))
		fmt.Fprintf(b, "    cpu            avg %.1f%%  p95 %.1f%%  max %.1f%%  (of one core)\n", cpu.Avg, cpu.P95, cpu.Max)
		fmt.Fprintf(b, "    rss            start %s → end %s   (max %s)\n",
			humanBytes(first), humanBytes(last), humanBytes(maxRSS))
		if sl := slopePerHour(seriesRSS(r.Samples, pid), r.Rows); sl != 0 && len(r.Rows) > 10 {
			fmt.Fprintf(b, "    rss trend      %+.1f MB/hour\n", sl/1e6)
		}
		fmt.Fprintf(b, "    threads        max %d\n", maxThreads)
		if maxFD > 0 {
			pctFD := 100 * safeDiv(float64(maxFD), float64(fdLimit))
			fmt.Fprintf(b, "    open fds       max %d of %d (%.0f%% of the limit)\n", maxFD, fdLimit, pctFD)
		}
		fmt.Fprintf(b, "    ctx switches   %.0f/s voluntary, %.0f/s involuntary\n",
			safeDiv(float64(volCtx), dur), safeDiv(float64(nvolCtx), dur))
		if io := du(lastSeen.RChar, firstSeen.RChar); io > 0 {
			fmt.Fprintf(b, "    io             read %s, wrote %s (syscalls: %s read, %s write)\n",
				humanBytes(io), humanBytes(du(lastSeen.WChar, firstSeen.WChar)),
				humanCount(float64(du(lastSeen.Syscr, firstSeen.Syscr))),
				humanCount(float64(du(lastSeen.Syscw, firstSeen.Syscw))))
		}
		if du(lastSeen.StartTime, firstSeen.StartTime) != 0 || lastSeen.StartTime < firstSeen.StartTime {
			b.WriteString("    ⚠ start time changed during the run — THE PROCESS RESTARTED\n")
		}
	}
}

func (r *Report) renderSystemProcesses(b *strings.Builder) {
	if len(r.SysProcCPU) == 0 {
		return
	}
	var list []*procCPUAgg
	for _, a := range r.SysProcCPU {
		if a.N > 0 && a.Sum/float64(a.N) >= 0.5 {
			list = append(list, a)
		}
	}
	if len(list) == 0 {
		return
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i].Sum/float64(list[i].N), list[j].Sum/float64(list[j].N)
		if a != b {
			return a > b
		}
		return list[i].PID < list[j].PID
	})
	hdr(b, "BUSIEST PROCESSES ON THE BOX  (whoever they are — this is how you rule the service out)")
	fmt.Fprintf(b, "  %-8s %-20s %9s %9s   %s\n", "pid", "name", "avg cpu%", "max cpu%", "command")
	for i, a := range list {
		if i >= 12 {
			break
		}
		fmt.Fprintf(b, "  %-8d %-20s %9.1f %9.1f   %s\n",
			a.PID, truncate(a.Name, 20), a.Sum/float64(a.N), a.Max, truncate(a.Cmd, 60))
	}
}

// renderSpikes lists the worst intervals with everything else that was true at
// that moment, which is usually enough to see the cause without a profile.
func (r *Report) renderSpikes(b *strings.Builder) {
	if len(r.Rows) < 3 {
		return
	}
	hdr(b, "WORST INTERVALS")

	top := func(title string, less func(a, b row) bool, n int) {
		rows := make([]row, len(r.Rows))
		copy(rows, r.Rows)
		sort.Slice(rows, func(i, j int) bool {
			if less(rows[i], rows[j]) {
				return true
			}
			if less(rows[j], rows[i]) {
				return false
			}
			return rows[i].T.Before(rows[j].T)
		})
		fmt.Fprintf(b, "\n  %s\n", title)
		fmt.Fprintf(b, "  %-10s %7s %9s %9s %9s %7s %7s %8s %8s  %s\n",
			"time", "cpu%", "nic out", "nic in", "peers out", "conns", "new/s",
			"sessions", "streams", "top peer this interval")
		for i := 0; i < n && i < len(rows); i++ {
			w := rows[i]
			peer := "-"
			if len(w.Peers) > 0 && w.Peers[0].OutDelta > 0 {
				peer = fmt.Sprintf("%s (%.1f Mb/s)", w.Peers[0].IP,
					float64(w.Peers[0].OutDelta)*8/w.DT/1e6)
			}
			sess, str := "-", "-"
			if w.HasMetrics {
				sess = strconv.FormatFloat(w.Sessions, 'f', 0, 64)
				str = strconv.FormatFloat(w.Streams, 'f', 0, 64)
			}
			fmt.Fprintf(b, "  %-10s %7.1f %9.2f %9.2f %9.2f %7d %7.1f %8s %8s  %s\n",
				w.T.Format("15:04:05"), w.CPU, w.TxMbit, w.RxMbit, w.SockOutMbit,
				w.Conns, w.NewConn, sess, str, peer)
		}
	}
	top("by egress:", func(a, b row) bool { return a.TxMbit > b.TxMbit }, 8)
	if summarize(series(r.Rows, func(w row) float64 { return w.SockOutMbit })).Max > 0 {
		top("by attributed peer egress:", func(a, b row) bool { return a.SockOutMbit > b.SockOutMbit }, 8)
	}
	top("by cpu:", func(a, b row) bool { return a.CPU > b.CPU }, 8)
	nc := summarize(series(r.Rows, func(w row) float64 { return w.NewConn }))
	if nc.Max > 1 {
		top("by new connections:", func(a, b row) bool { return a.NewConn > b.NewConn }, 8)
	}
}

func (r *Report) renderCorrelations(b *strings.Builder) {
	if len(r.Rows) < 10 {
		return
	}
	cpu := series(r.Rows, func(w row) float64 { return w.CPU })
	// Service metrics are correlated against the CPU of the SAME intervals, so
	// a dropped scrape shortens both series together instead of shifting one
	// against the other.
	cpuM := series(r.MetricRows, func(w row) float64 { return w.CPU })

	pairs := []struct {
		name string
		cpu  []float64
		vals []float64
	}{
		{"egress Mbit/s", cpu, series(r.Rows, func(w row) float64 { return w.TxMbit })},
		{"ingress Mbit/s", cpu, series(r.Rows, func(w row) float64 { return w.RxMbit })},
		{"egress packets/s", cpu, series(r.Rows, func(w row) float64 { return w.TxPps })},
		{"attributed egress", cpu, series(r.Rows, func(w row) float64 { return w.SockOutMbit })},
		{"new connections/s", cpu, series(r.Rows, func(w row) float64 { return w.NewConn })},
		{"tcp socket count", cpu, series(r.Rows, func(w row) float64 { return float64(w.Conns) })},
		{"context switches/s", cpu, series(r.Rows, func(w row) float64 { return w.Ctxt })},
		{"active sessions", cpuM, series(r.MetricRows, func(w row) float64 { return w.Sessions })},
		{"active streams", cpuM, series(r.MetricRows, func(w row) float64 { return w.Streams })},
		{"session failures/s", cpuM, series(r.MetricRows, func(w row) float64 { return w.SessFail })},
		{"goroutines", cpuM, series(r.MetricRows, func(w row) float64 { return w.Goroutines })},
	}
	hdr(b, "WHAT DOES CPU TRACK?  (Pearson correlation with host CPU, over the whole window)")
	type cv struct {
		name string
		v    float64
	}
	var list []cv
	for _, p := range pairs {
		if summarize(p.vals).Max == 0 || len(p.vals) < 10 {
			continue
		}
		list = append(list, cv{p.name, corr(p.cpu, p.vals)})
	}
	sort.Slice(list, func(i, j int) bool {
		if abs(list[i].v) != abs(list[j].v) {
			return abs(list[i].v) > abs(list[j].v)
		}
		return list[i].name < list[j].name
	})
	for _, c := range list {
		fmt.Fprintf(b, "  %-24s r = %+.2f  %s\n", c.name, c.v, corrBar(c.v))
	}
	b.WriteString("\n  r near +1 means the two rise and fall together. If CPU tracks bytes, the fix is\n" +
		"  about throughput; if it tracks new connections, the fix is about handshake/churn.\n")
}

func (r *Report) renderKernelCounters(b *strings.Builder) {
	first, last := r.Samples[0], r.Samples[len(r.Samples)-1]
	if len(first.NetStat) == 0 || len(last.NetStat) == 0 {
		return
	}
	dur := r.End.Sub(r.Start).Seconds()
	type kc struct {
		k string
		d uint64
	}
	var list []kc
	for k, v := range last.NetStat {
		if gaugeCounters[k] {
			continue // a gauge's "delta" is meaningless; shown separately below
		}
		p, ok := first.NetStat[k]
		if !ok {
			continue
		}
		if d := du(v, p); d > 0 {
			list = append(list, kc{k, d})
		}
	}
	if len(list) == 0 {
		return
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].d != list[j].d {
			return list[i].d > list[j].d
		}
		return list[i].k < list[j].k
	})
	hdr(b, "KERNEL TCP/UDP COUNTERS OVER THE WINDOW")
	for _, c := range list {
		fmt.Fprintf(b, "  %-28s %14s   %10.2f/s\n", c.k, humanCount(float64(c.d)), float64(c.d)/dur)
	}
	if v, ok := last.NetStat["Tcp.CurrEstab"]; ok {
		fmt.Fprintf(b, "  %-28s %14d   (gauge, host-wide at end of run)\n", "Tcp.CurrEstab", v)
	}
	if v, ok := last.NetStat["Tcp.RetransSegs"]; ok {
		if o, ok2 := last.NetStat["Tcp.OutSegs"]; ok2 && o > 0 {
			pr := du(v, first.NetStat["Tcp.RetransSegs"])
			po := du(o, first.NetStat["Tcp.OutSegs"])
			if po > 0 {
				fmt.Fprintf(b, "\n  retransmit rate: %.3f%% of segments sent\n", 100*float64(pr)/float64(po))
			}
		}
	}
}

// ---------- findings ----------

// renderFindings is the part someone reads first. Each line states a fact the
// data supports and what it points at; nothing here is a guess dressed up as a
// conclusion.
func (r *Report) renderFindings(b *strings.Builder) {
	hdr(b, "FINDINGS")
	var f []string

	cpu := summarize(series(r.Rows, func(w row) float64 { return w.CPU }))
	tx := summarize(series(r.Rows, func(w row) float64 { return w.TxMbit }))
	rx := summarize(series(r.Rows, func(w row) float64 { return w.RxMbit }))
	newc := summarize(series(r.Rows, func(w row) float64 { return w.NewConn }))
	steal := summarize(series(r.Rows, func(w row) float64 { return w.Steal }))
	soft := summarize(series(r.Rows, func(w row) float64 { return w.SoftIRQ }))
	iow := summarize(series(r.Rows, func(w row) float64 { return w.IOWait }))
	goro := series(r.MetricRows, func(w row) float64 { return w.Goroutines })
	sessFail := summarize(series(r.MetricRows, func(w row) float64 { return w.SessFail }))
	cpuS := series(r.Rows, func(w row) float64 { return w.CPU })

	// Who owns the CPU.
	var svcCPU float64
	var svcName string
	for _, pid := range r.TrackedPIDs {
		s := summarize(seriesPID(r.Rows, pid))
		if s.Avg > svcCPU {
			svcCPU = s.Avg
			svcName = fmt.Sprintf("%s (pid %d)", r.ProcNames[pid], pid)
		}
	}
	if r.Meta.Host.NumCPU > 0 && cpu.Avg > 0 {
		hostCores := cpu.Avg / 100 * float64(r.Meta.Host.NumCPU)
		svcCores := svcCPU / 100
		share := 100 * safeDiv(svcCores, hostCores)
		if svcName != "" {
			f = append(f, fmt.Sprintf(
				"CPU ownership: the box averaged %.2f busy cores; %s averaged %.2f cores — %.0f%% of it.",
				hostCores, svcName, svcCores, share))
			if share < 40 {
				f = append(f, "  → The tracked service is NOT the main CPU consumer. See BUSIEST PROCESSES above.")
			}
		}
	}
	if cpu.P95 > 85 {
		f = append(f, fmt.Sprintf("CPU was above 85%% for at least 5%% of the run (p95 %.0f%%, peak %.0f%%). "+
			"The box is genuinely CPU constrained, not just spiky.", cpu.P95, cpu.Max))
	} else if cpu.Max > 85 {
		f = append(f, fmt.Sprintf("CPU peaked at %.0f%% but p95 was only %.0f%% — brief spikes, not sustained load.", cpu.Max, cpu.P95))
	}
	if steal.Avg > 5 {
		f = append(f, fmt.Sprintf("Steal time averaged %.1f%%: the hypervisor is taking CPU away from this VM. "+
			"Some of the 'CPU usage' alert is the host, not this workload.", steal.Avg))
	}
	if soft.Avg > 10 {
		f = append(f, fmt.Sprintf("SoftIRQ averaged %.1f%% — a large share of CPU is packet processing in the "+
			"kernel, which tracks packet RATE rather than bytes.", soft.Avg))
	}
	if iow.Avg > 10 {
		f = append(f, fmt.Sprintf("iowait averaged %.1f%%: the box is waiting on disk. Check logging volume.", iow.Avg))
	}

	// Traffic shape.
	if tx.Avg > 0 && rx.Avg > 0 {
		ratio := tx.Avg / rx.Avg
		switch {
		case ratio > 3:
			f = append(f, fmt.Sprintf("Egress is %.1f× ingress. For a dmsg relay, which mostly forwards what it "+
				"receives, that asymmetry means fan-out: one inbound stream copied to many peers.", ratio))
		case ratio < 0.33:
			f = append(f, fmt.Sprintf("Ingress is %.1f× egress — the server is absorbing far more than it sends.", 1/ratio))
		default:
			f = append(f, fmt.Sprintf("Egress and ingress are balanced (%.2f× ratio), the normal shape for a relay "+
				"that forwards what it receives.", ratio))
		}
	}
	if tx.Max > 0 && tx.P95 > 0 && tx.Max/tx.P95 > 3 {
		f = append(f, fmt.Sprintf("Egress is bursty: peak %.0f Mbit/s against a p95 of %.0f Mbit/s. A rate alert "+
			"will fire on the burst even though the sustained rate is far lower.", tx.Max, tx.P95))
	}

	// Attribution.
	if r.TotalSockOut > 0 && r.TotalTx > 0 {
		cov := 100 * r.TotalSockOut / r.TotalTx
		switch {
		case cov > 120:
			f = append(f, "Attributed TCP payload exceeds what left the network interfaces, so most of "+
				"this traffic is on loopback — it never crosses the network and cannot be what the "+
				"host's traffic alert is measuring.")
		case cov > 80:
			f = append(f, fmt.Sprintf("%.0f%% of egress is accounted for by the tracked process's TCP connections — "+
				"this traffic IS the service.", cov))
		case cov > 30:
			f = append(f, fmt.Sprintf("Only %.0f%% of egress maps to tracked TCP connections. The rest is UDP "+
				"(dmsg QUIC/WebTransport share the server's UDP port), another process, or unreadable sockets.", cov))
		default:
			f = append(f, fmt.Sprintf("Only %.0f%% of egress maps to tracked TCP connections — most of the traffic "+
				"is NOT this process's TCP. Check UDP/QUIC and the other processes listed above.", cov))
		}
	}

	// Peer concentration.
	if len(r.Peers) > 0 {
		var tot float64
		for _, p := range r.Peers {
			tot += float64(p.Out)
		}
		if tot > 0 {
			top := r.Peers[0]
			share := 100 * float64(top.Out) / tot
			if share > 25 {
				f = append(f, fmt.Sprintf("One peer, %s, accounts for %.0f%% of all attributed egress (%s over the run). "+
					"That is the address to look at first.", top.IP, share, humanFloat(float64(top.Out), "B")))
			} else {
				f = append(f, fmt.Sprintf("Egress is spread out — the busiest peer (%s) is only %.0f%% of the total, "+
					"so this is aggregate load rather than one abusive client.", top.IP, share))
			}
		}
	}

	// Churn.
	if newc.Avg > 0 {
		conns := summarize(series(r.Rows, func(w row) float64 { return float64(w.Conns) }))
		life := safeDiv(conns.Avg, newc.Avg)
		if life > 0 && life < 60 {
			f = append(f, fmt.Sprintf("Connections live %.0fs on average (%.1f new/s against %.0f open). That is "+
				"churn, and every new dmsg session costs a Noise handshake — CPU that does not move any payload.",
				life, newc.Avg, conns.Avg))
		}
		if cc := corr(cpuS, series(r.Rows, func(w row) float64 { return w.NewConn })); cc > 0.5 {
			f = append(f, fmt.Sprintf("CPU correlates with the NEW-CONNECTION rate (r=%.2f) more than a throughput "+
				"problem would. Look at reconnect loops, not at bandwidth.", cc))
		}
	}
	if ct := corr(cpuS, series(r.Rows, func(w row) float64 { return w.TxMbit })); ct > 0.6 {
		f = append(f, fmt.Sprintf("CPU tracks egress closely (r=%.2f): the cost is proportional to the bytes "+
			"relayed — encryption and copying, which is expected work.", ct))
	}

	// Leaks.
	if len(goro) > 10 {
		s := summarize(goro)
		if sl := slopePerHour(goro, r.MetricRows); s.Avg > 0 && sl > 0 && sl*r.End.Sub(r.Start).Hours() > 0.25*s.Avg {
			f = append(f, fmt.Sprintf("Goroutines grew %+.0f/hour (%.0f → %.0f) without falling back. That is the "+
				"shape of a leak — capture a goroutine dump and compare stacks.",
				sl, goro[0], goro[len(goro)-1]))
		}
	}
	rss := series(r.MetricRows, func(w row) float64 { return w.SvcRSSMB })
	if s := summarize(rss); s.Max > 0 && len(rss) > 10 {
		if sl := slopePerHour(rss, r.MetricRows); sl > 0 && sl*r.End.Sub(r.Start).Hours() > 0.25*s.Avg {
			f = append(f, fmt.Sprintf("Service RSS grew %+.0f MB/hour (%.0f → %.0f MB) with no plateau — "+
				"memory is not being returned.", sl, rss[0], rss[len(rss)-1]))
		}
	}

	// dmsg-specific.
	if sessFail.Avg > 0.1 {
		f = append(f, fmt.Sprintf("Session handshakes are failing at %.2f/s on average (peak %.1f/s). Failed "+
			"sessions cost CPU and produce no useful traffic.", sessFail.Avg, sessFail.Max))
	}
	sess := summarize(series(r.MetricRows, func(w row) float64 { return w.Sessions }))
	conns := summarize(series(r.MetricRows, func(w row) float64 { return float64(w.Estab) }))
	if sess.Avg > 0 && conns.Avg > 0 {
		ratio := conns.Avg / sess.Avg
		if ratio > 1.5 {
			f = append(f, fmt.Sprintf("There are %.1f× more established TCP sockets (%.0f) than dmsg sessions (%.0f). "+
				"Sockets the server does not count as sessions are half-open connections or peers stuck before "+
				"the handshake completes.", ratio, conns.Avg, sess.Avg))
		}
	}
	if d := summarize(series(r.MetricRows, func(w row) float64 { return float64(w.DiscClients) })); d.Max > 0 && sess.Avg > 0 {
		if d.Avg > 2*sess.Avg {
			f = append(f, fmt.Sprintf("Discovery lists %.0f clients delegating to this server but only %.0f sessions "+
				"are live — most delegated clients are not currently connected here.", d.Avg, sess.Avg))
		}
	}

	// Saturation and errors.
	if lb := summarize(series(r.Rows, func(w row) float64 { return float64(w.ListenBacklog) })); lb.Max > 5 {
		f = append(f, fmt.Sprintf("The accept queue reached %.0f pending connections — the server was not calling "+
			"accept() fast enough at least once.", lb.Max))
	}
	if v, ok := deltaCounter(r, "TcpExt.ListenOverflows"); ok && v > 0 {
		f = append(f, fmt.Sprintf("The kernel dropped %d connection(s) from a full accept queue (ListenOverflows). "+
			"Clients saw those as connection failures.", v))
	}
	if v, ok := deltaCounter(r, "Udp.RcvbufErrors"); ok && v > 0 {
		f = append(f, fmt.Sprintf("%d UDP datagrams were dropped for lack of receive buffer — that is QUIC/"+
			"WebTransport traffic being lost before the server sees it.", v))
	}
	if dr := summarize(series(r.Rows, func(w row) float64 { return w.RxDrop + w.TxDrop })); dr.Max > 0 {
		f = append(f, fmt.Sprintf("The NIC reported dropped packets (peak %.0f/s) — the interface, not the "+
			"application, is shedding load.", dr.Max))
	}
	for _, pid := range r.TrackedPIDs {
		for _, s := range r.Samples {
			for _, p := range s.Procs {
				if p.PID == pid && p.FDLimit > 0 && float64(p.FDs) > 0.8*float64(p.FDLimit) {
					f = append(f, fmt.Sprintf("pid %d reached %d open fds against a limit of %d (>80%%). "+
						"New connections will start failing at the limit.", pid, p.FDs, p.FDLimit))
					break
				}
			}
		}
	}

	if len(f) == 0 {
		f = append(f, "Nothing stood out: no sustained CPU pressure, no dominant peer, no growth trend, no drops.")
	}
	for i, s := range f {
		if strings.HasPrefix(s, "  →") {
			fmt.Fprintf(b, "     %s\n", strings.TrimSpace(s))
			continue
		}
		fmt.Fprintf(b, "  %2d. %s\n", i+1, wrap(s, 96, "      "))
	}

	// Point at the next step.
	hdr(b, "NEXT STEPS")
	if r.Meta.Metrics == "" {
		b.WriteString("  • The server's own metrics were not available. Restart it with `-m 127.0.0.1:9081`\n" +
			"    to record session/stream counts and handshake failures.\n")
	}
	if r.Meta.PProf == "" {
		b.WriteString("  • pprof was not available. Restart with `--pprofmode http --pprofaddr 127.0.0.1:6060`\n" +
			"    so the next spike captures a CPU profile automatically.\n")
	} else {
		b.WriteString("  • Any captured profiles are in this directory. Inspect with:\n" +
			"      go tool pprof -http=: profile-01-*.cpu.pprof\n")
	}
	b.WriteString("  • peers.csv has every remote address with its byte totals; timeline.csv has every\n" +
		"    interval for plotting in a spreadsheet.\n")
}

func deltaCounter(r *Report, key string) (uint64, bool) {
	first, last := r.Samples[0], r.Samples[len(r.Samples)-1]
	a, ok1 := first.NetStat[key]
	b, ok2 := last.NetStat[key]
	if !ok1 || !ok2 {
		return 0, false
	}
	return du(b, a), true
}

// ---------- small helpers ----------

func seriesPID(rows []row, pid int) []float64 {
	out := make([]float64, 0, len(rows))
	for _, w := range rows {
		if v, ok := w.ProcCPU[pid]; ok {
			out = append(out, v)
		}
	}
	return out
}

func seriesRSS(samples []*Sample, pid int) []float64 {
	out := make([]float64, 0, len(samples))
	for _, s := range samples {
		for _, p := range s.Procs {
			if p.PID == pid {
				out = append(out, float64(p.RSS))
			}
		}
	}
	return out
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

func corrBar(v float64) string {
	n := int(abs(v)*10 + 0.5)
	if n > 10 {
		n = 10
	}
	bar := strings.Repeat("█", n) + strings.Repeat("·", 10-n)
	if v < 0 {
		return "-" + bar
	}
	return " " + bar
}

func trimNum(v float64) string {
	switch {
	case v == 0:
		return "0"
	case abs(v) >= 10000:
		return humanCount(v)
	case abs(v) >= 100:
		return strconv.FormatFloat(v, 'f', 0, 64)
	case abs(v) >= 10:
		return strconv.FormatFloat(v, 'f', 1, 64)
	default:
		return strconv.FormatFloat(v, 'f', 2, 64)
	}
}

// humanDuration rounds to a unit that stays meaningful whether the run was 30
// seconds or three days.
func humanDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return d.Round(time.Minute).String()
	case d >= time.Hour:
		return d.Round(time.Minute).String()
	case d >= time.Minute:
		return d.Round(time.Second).String()
	default:
		return d.Round(100 * time.Millisecond).String()
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// timeRuler labels a sparkline's time axis at start, middle and end.
func timeRuler(start, end time.Time, width int) string {
	if width < 20 {
		return ""
	}
	l := start.Format("15:04")
	m := start.Add(end.Sub(start) / 2).Format("15:04")
	r := end.Format("15:04")
	pad1 := width/2 - len(l) - len(m)/2
	pad2 := width - len(l) - pad1 - len(m) - len(r)
	if pad1 < 1 {
		pad1 = 1
	}
	if pad2 < 1 {
		pad2 = 1
	}
	return l + strings.Repeat(" ", pad1) + m + strings.Repeat(" ", pad2) + r
}

// wrap hard-wraps a finding so long sentences stay readable in a terminal.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return s
	}
	var b strings.Builder
	line := 0
	for i, w := range words {
		if line > 0 && line+1+len(w) > width {
			b.WriteString("\n" + indent)
			line = len(indent)
		} else if i > 0 {
			b.WriteString(" ")
			line++
		}
		b.WriteString(w)
		line += len(w)
	}
	return b.String()
}

// ---------- CSV outputs ----------

func writePeersCSV(path string, r *Report) error {
	f, err := os.Create(path) //nolint:gosec
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"ip", "subnet", "bytes_out", "bytes_in", "new_conns", "max_conns", "retrans", "samples_seen"}); err != nil {
		return err
	}
	for _, p := range r.Peers {
		rec := []string{
			p.IP, subnet(p.IP),
			strconv.FormatUint(p.Out, 10), strconv.FormatUint(p.In, 10),
			strconv.Itoa(p.NewConns), strconv.Itoa(p.MaxConns),
			strconv.FormatUint(p.Retrans, 10), strconv.Itoa(p.Samples),
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	return w.Error()
}

func writeTimelineCSV(path string, samples []*Sample) error {
	f, err := os.Create(path) //nolint:gosec
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	w := csv.NewWriter(f)
	defer w.Flush()
	head := []string{
		"time", "cpu_pct", "cpu_user", "cpu_sys", "cpu_softirq", "cpu_iowait", "cpu_steal",
		"load1", "mem_used_pct", "tx_mbit", "rx_mbit", "tx_pps", "rx_pps",
		"tcp_conns", "established", "time_wait", "new_conns_s", "closed_conns_s",
		"sock_out_mbit", "sock_in_mbit", "retrans_s",
		"clients", "sessions", "streams", "sess_fail_s", "goroutines", "heap_mb", "svc_rss_mb", "svc_cpu_pct",
	}
	if err := w.Write(head); err != nil {
		return err
	}
	for i := 1; i < len(samples); i++ {
		rt := computeRates(samples[i-1], samples[i])
		cur := samples[i]
		var conns, estab, tw int
		var sockOut, sockIn float64
		if cur.Socks != nil {
			conns = cur.Socks.TCPTotal
			estab = cur.Socks.ByState["ESTABLISHED"]
			tw = cur.Socks.ByState["TIME_WAIT"]
			sockOut = rt.SockOut * 8 / 1e6
			sockIn = rt.SockIn * 8 / 1e6
		}
		var clients, sessions, streams, goro, heap, rss, svcCPU, sessFail float64
		if t := primaryTarget(cur); t != nil {
			clients, _ = mval(t.Metrics, "dmsg_server_clients_count")
			sessions, _ = mval(t.Metrics, "dmsg_server_vm_active_sessions_count")
			streams, _ = mval(t.Metrics, "dmsg_server_vm_active_streams_count")
			goro, _ = mval(t.Metrics, "go_goroutines")
			heap, _ = mval(t.Metrics, "go_memstats_heap_inuse_bytes")
			rss, _ = mval(t.Metrics, "process_resident_memory_bytes")
			if pt := primaryTarget(samples[i-1]); pt != nil {
				c, _ := mval(t.Metrics, "process_cpu_seconds_total")
				p, _ := mval(pt.Metrics, "process_cpu_seconds_total")
				if c >= p {
					svcCPU = (c - p) / rt.DT * 100
				}
				cf, _ := mval(t.Metrics, "dmsg_server_vm_session_fail_total")
				pf, _ := mval(pt.Metrics, "dmsg_server_vm_session_fail_total")
				if cf >= pf {
					sessFail = (cf - pf) / rt.DT
				}
			}
		}
		ff := func(v float64) string { return strconv.FormatFloat(v, 'f', 3, 64) }
		rec := []string{
			cur.TS.Format(time.RFC3339),
			ff(rt.CPUPct), ff(rt.CPUUser), ff(rt.CPUSys), ff(rt.CPUSoftIRQ), ff(rt.CPUIOWait), ff(rt.CPUSteal),
			ff(cur.Load[0]), ff(100 * safeDiv(float64(cur.Mem.Used()), float64(cur.Mem.Total))),
			ff(rt.TxMbit), ff(rt.RxMbit), ff(rt.TxPkts), ff(rt.RxPkts),
			strconv.Itoa(conns), strconv.Itoa(estab), strconv.Itoa(tw),
			ff(rt.NewConn), ff(rt.DelConn), ff(sockOut), ff(sockIn), ff(rt.Retrans),
			ff(clients), ff(sessions), ff(streams), ff(sessFail), ff(goro),
			ff(heap / 1e6), ff(rss / 1e6), ff(svcCPU),
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	return w.Error()
}
