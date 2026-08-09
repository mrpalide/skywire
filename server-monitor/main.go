// Command server-monitor records what a Skywire service host is actually
// doing — CPU, memory, per-interface traffic, per-peer TCP throughput, socket
// churn, and the dmsg-server's own metrics — and turns hours of that into a
// single readable report.
//
// It exists because host-level alerts ("outbound traffic rate", "CPU usage")
// name a machine but never a cause. This names the cause: which process, which
// remote IP, how many connections, whether the CPU tracks bytes or tracks
// connection churn, and — with pprof enabled — what the server was executing
// at the moment it spiked.
//
// Usage:
//
//	server-monitor watch    [flags]   # record + report (default)
//	server-monitor snapshot [flags]   # one-off look at right now
//	server-monitor report   <dir|file># re-render a report from a saved run
//
// Zero dependencies, no agent, no daemon: build it, scp it, run it in tmux.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const version = "1.0.0"

type options struct {
	dir            string
	interval       time.Duration
	duration       time.Duration
	match          string
	pids           string
	metricsURL     string
	healthURL      string
	pprofURL       string
	discURL        string
	configPath     string
	pubKey         string
	cpuSpike       float64
	mbitSpike      float64
	profileSecs    int
	maxProfiles    int
	topPeers       int
	peersPerSample int
	topProcs       int
	printEvery     time.Duration
	reportEvery    time.Duration
	noSocks        bool
	ports          string
	clkTck         float64
	quiet          bool
}

func (o *options) register(fs *flag.FlagSet) {
	fs.StringVar(&o.dir, "dir", "", "output directory (default ./server-monitor-<host>-<timestamp>)")
	fs.DurationVar(&o.interval, "interval", 10*time.Second, "sampling interval")
	fs.DurationVar(&o.duration, "duration", 0, "how long to run; 0 = until Ctrl-C")
	fs.StringVar(&o.match, "match", `dmsg-server|dmsg\s+server|skywire|visor`,
		"regexp matched against process name and full command line")
	fs.StringVar(&o.pids, "pid", "", "comma-separated PIDs to track (overrides -match)")
	fs.StringVar(&o.metricsURL, "metrics", "", "Prometheus endpoint, e.g. http://127.0.0.1:9081/metrics (autodetected from -m in the process argv)")
	fs.StringVar(&o.healthURL, "health", "", "health endpoint, e.g. http://127.0.0.1:8082/health (autodetected from the server config)")
	fs.StringVar(&o.pprofURL, "pprof", "", "pprof base URL, e.g. http://127.0.0.1:6060 (autodetected from --pprofaddr)")
	fs.StringVar(&o.discURL, "disc", "", "dmsg-discovery base URL, for the delegated-clients cross-check")
	fs.StringVar(&o.configPath, "config", "", "dmsg-server config.json (for public_key + health address)")
	fs.Float64Var(&o.cpuSpike, "cpu-spike", 80, "capture pprof profiles when host CPU exceeds this %% of total capacity (0 = never)")
	fs.Float64Var(&o.mbitSpike, "mbit-spike", 0, "also capture profiles when egress exceeds this many Mbit/s (0 = off)")
	fs.IntVar(&o.profileSecs, "profile-secs", 30, "duration of each captured CPU profile")
	fs.IntVar(&o.maxProfiles, "max-profiles", 8, "cap on captured profile sets, so a long spike cannot fill the disk")
	fs.IntVar(&o.topPeers, "top-peers", 25, "peers listed in the report")
	fs.IntVar(&o.peersPerSample, "peers-per-sample", 64, "peers recorded per sample in samples.jsonl")
	fs.IntVar(&o.topProcs, "top-procs", 12, "processes recorded per sample for the system-wide CPU view")
	fs.DurationVar(&o.printEvery, "print-every", time.Minute, "live status line interval (0 = only at start/end)")
	fs.DurationVar(&o.reportEvery, "report-every", 30*time.Minute, "rewrite report.txt this often during the run (0 = only at the end)")
	fs.BoolVar(&o.noSocks, "no-socks", false, "skip per-connection socket statistics")
	fs.StringVar(&o.ports, "ports", "", "comma-separated local ports to attribute sockets by, when /proc/<pid>/fd is unreadable")
	fs.Float64Var(&o.clkTck, "clktck", 100, "kernel USER_HZ; only change this if getconf CLK_TCK disagrees")
	fs.BoolVar(&o.quiet, "quiet", false, "suppress the live status line")
}

func main() {
	verb := "watch"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		verb = args[0]
		args = args[1:]
	}

	var err error
	switch verb {
	case "watch":
		err = runWatch(args)
	case "snapshot":
		err = runSnapshot(args)
	case "report":
		err = runReportCmd(args)
	case "version", "-version", "--version":
		fmt.Printf("server-monitor %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		err = fmt.Errorf("unknown command %q", verb)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `server-monitor %s — Skywire host + dmsg-server diagnostics

  server-monitor watch    [flags]      record and report (default command)
  server-monitor snapshot [flags]      one-off look at the current state
  server-monitor report   <dir|file>   re-render the report of a saved run

Typical use on a dmsg host:

  sudo ./server-monitor watch -duration 6h

Run "server-monitor watch -h" for the full flag list.
`, version)
}

func runWatch(args []string) error {
	var o options
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	o.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	clkTck = o.clkTck

	host := collectHostInfo()
	if o.dir == "" {
		name := host.Hostname
		if name == "" {
			name = "host"
		}
		o.dir = fmt.Sprintf("server-monitor-%s-%s", name, time.Now().Format("20060102-150405"))
	}
	if err := os.MkdirAll(o.dir, 0o750); err != nil {
		return err
	}

	m, err := newProcMatcher(o.match, o.pids)
	if err != nil {
		return fmt.Errorf("bad -match/-pid: %w", err)
	}

	// One preliminary walk so we can autodetect the service's endpoints from
	// its own argv before the first real tick.
	var probe Sample
	inodes, fdsOK := collectProcs(&probe, m, o.topProcs)
	resolveTargets(&o, probe.Procs)

	sc := newScraper(o.metricsURL, o.healthURL, o.pprofURL, o.discURL, o.pubKey, o.dir, o.profileSecs, o.maxProfiles)

	var socks *sockCollector
	var sockNote string
	if o.noSocks {
		sockNote = "socket statistics disabled by -no-socks"
	} else if err := netlinkAvailable(); err != nil {
		sockNote = "socket statistics unavailable: " + err.Error()
	} else {
		ports := parsePorts(o.ports)
		if len(ports) == 0 {
			ports = listenPorts(inodes)
		}
		socks = newSockCollector(o.peersPerSample, ports)
		if !fdsOK {
			sockNote = "could not read /proc/<pid>/fd (run as root for exact per-process attribution); " +
				"falling back to matching local ports " + portList(ports)
		}
	}

	printBanner(&o, host, probe.Procs, sc, sockNote)

	writer, err := newSampleWriter(filepath.Join(o.dir, "samples.jsonl"))
	if err != nil {
		return err
	}
	defer writer.Close() //nolint:errcheck

	meta := runMeta{
		Version:   version,
		Started:   time.Now(),
		Host:      host,
		Interval:  o.interval.String(),
		Match:     o.match,
		Metrics:   o.metricsURL,
		PProf:     o.pprofURL,
		Health:    o.healthURL,
		Disc:      o.discURL,
		Config:    o.configPath,
		PubKey:    o.pubKey,
		SockNote:  sockNote,
		CPUSpike:  o.cpuSpike,
		MbitSpike: o.mbitSpike,
	}
	if err := writeMeta(filepath.Join(o.dir, "meta.json"), &meta); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if o.duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.duration)
		defer cancel()
	}

	// The baseline sample is taken BEFORE the ticker exists. If the ticker
	// were started during setup, the first tick would arrive less than one
	// interval after the first sample, and every rate derived from that
	// shortened interval — CPU above all — would come out inflated.
	prev := takeSample(ctx, &o, m, socks, sc, 0)
	if sockNote != "" {
		prev.Notes = append(prev.Notes, sockNote)
	}
	if err := writer.Write(prev); err != nil {
		fmt.Fprintln(os.Stderr, "write sample:", err)
	}
	idx := 1
	lastReport := time.Now()
	var lastPrint time.Time

	tick := time.NewTicker(o.interval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println()
			fmt.Printf("stopping after %d samples; writing report…\n", idx)
			if err := writer.Close(); err != nil {
				return err
			}
			return finalReport(&o, &meta, socks, true)
		case <-tick.C:
		}

		now := time.Now()
		s := takeSample(ctx, &o, m, socks, sc, idx)
		if err := writer.Write(s); err != nil {
			fmt.Fprintln(os.Stderr, "write sample:", err)
		}

		r := computeRates(prev, s)
		if !o.quiet && (o.printEvery == 0 || now.Sub(lastPrint) >= o.printEvery) {
			fmt.Println(liveLine(s, r))
			lastPrint = now
		}
		maybeCapture(&o, sc, r, s.TS)

		prev = s
		idx++

		if o.reportEvery > 0 && now.Sub(lastReport) >= o.reportEvery {
			writeInterimReport(&o, &meta, socks, meta.Started)
			lastReport = now
		}
	}
}

// takeSample runs every collector once. Collector failures degrade to notes so
// a single unreadable file never ends the run.
func takeSample(ctx context.Context, o *options, m *procMatcher, socks *sockCollector, sc *scraper, idx int) *Sample {
	s := &Sample{TS: time.Now()}

	collectCPU(s)
	collectMem(s)
	collectLoadUptime(s)
	collectNetDev(s)
	collectNetStat(s)
	collectSockStat(s)
	collectPressure(s)
	collectConntrack(s)

	inodes, _ := collectProcs(s, m, o.topProcs)

	if socks != nil {
		sum, err := socks.collect(inodes, idx)
		if err != nil {
			s.Notes = append(s.Notes, "socket dump: "+err.Error())
		} else {
			s.Socks = sum
		}
	}
	if sc.enabled() {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		t := sc.scrape(cctx)
		cancel()
		s.Targets = append(s.Targets, t)
	}
	return s
}

// maybeCapture fires a pprof capture when the host crosses a threshold. The
// point is to catch the spike unattended: by the time a human logs in, the
// interesting stack is long gone.
func maybeCapture(o *options, sc *scraper, r rates, ts time.Time) {
	if o.cpuSpike > 0 && r.CPUPct >= o.cpuSpike {
		if sc.captureProfiles(fmt.Sprintf("cpu-%.0f", r.CPUPct), ts) {
			fmt.Printf("  ↳ CPU %.0f%% ≥ %.0f%% — capturing pprof profiles (%ds)\n", r.CPUPct, o.cpuSpike, o.profileSecs)
		}
		return
	}
	if o.mbitSpike > 0 && r.TxMbit >= o.mbitSpike {
		if sc.captureProfiles(fmt.Sprintf("tx-%.0fmbit", r.TxMbit), ts) {
			fmt.Printf("  ↳ egress %.0f Mbit/s ≥ %.0f — capturing pprof profiles (%ds)\n", r.TxMbit, o.mbitSpike, o.profileSecs)
		}
	}
}

// resolveTargets fills in whatever the operator did not pass explicitly, by
// reading the service's own argv and config file.
func resolveTargets(o *options, procs []ProcStat) {
	d := autodetect(procs)
	if o.metricsURL == "" {
		o.metricsURL = d.MetricsURL
	}
	if o.pprofURL == "" {
		o.pprofURL = d.PProfURL
	}
	if o.configPath == "" {
		o.configPath = d.ConfigPath
	}
	if o.configPath != "" {
		if c, err := readDmsgConfig(o.configPath); err == nil {
			o.pubKey = c.PublicKey
			if o.healthURL == "" && c.HTTPAddress != "" {
				o.healthURL = "http://" + normalizeAddr(c.HTTPAddress) + "/health"
			}
			if o.discURL == "" && c.Discovery != "" {
				o.discURL = c.Discovery
			}
		}
	}
}

func parsePorts(s string) map[uint16]bool {
	out := map[uint16]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if n, err := strconv.ParseUint(p, 10, 16); err == nil {
			out[uint16(n)] = true
		}
	}
	return out
}

func portList(ports map[uint16]bool) string {
	if len(ports) == 0 {
		return "(none found)"
	}
	out := make([]string, 0, len(ports))
	for p := range ports {
		out = append(out, strconv.Itoa(int(p)))
	}
	sortStrings(out)
	return strings.Join(out, ",")
}

func printBanner(o *options, h hostInfo, procs []ProcStat, sc *scraper, note string) {
	fmt.Printf("server-monitor %s\n", version)
	fmt.Printf("host      %s  (%d cpu, %s ram, kernel %s)\n", h.Hostname, h.NumCPU, humanBytes(h.MemTotal), h.Kernel)
	fmt.Printf("output    %s\n", o.dir)
	fmt.Printf("interval  %s", o.interval)
	if o.duration > 0 {
		fmt.Printf("   duration %s", o.duration)
	}
	fmt.Println()

	if len(procs) == 0 {
		fmt.Printf("tracking  NO PROCESS MATCHED %q — host metrics only\n", o.match)
	} else {
		fmt.Printf("tracking  %d process(es):\n", len(procs))
		for _, p := range procs {
			fmt.Printf("          pid %-7d %-18s %s\n", p.PID, p.Name, truncate(p.Cmd, 90))
		}
	}
	if sc.metrics != "" {
		fmt.Printf("metrics   %s\n", sc.metrics)
	} else {
		fmt.Printf("metrics   not found — start the server with -m 127.0.0.1:9081 to get its internal counters\n")
	}
	if sc.pprof != "" {
		fmt.Printf("pprof     %s  (profiles captured above %.0f%% CPU)\n", sc.pprof, o.cpuSpike)
	} else {
		fmt.Printf("pprof     not found — start with --pprofmode http --pprofaddr 127.0.0.1:6060 for spike profiles\n")
	}
	if sc.health != "" {
		fmt.Printf("health    %s\n", sc.health)
	}
	if sc.disc != "" && sc.pubKey != "" {
		fmt.Printf("discovery %s (pk %s…)\n", sc.disc, truncate(sc.pubKey, 16))
	}
	if note != "" {
		fmt.Printf("note      %s\n", note)
	}
	fmt.Println(strings.Repeat("─", 100))
}

// writeInterimReport refreshes report.txt mid-run WITHOUT printing it. The
// report is a few hundred lines; dumping it into the operator's terminal every
// -report-every would bury the live status line and make a long unattended run
// unreadable. One line of acknowledgement is enough — the file is there to be
// read with `cat` whenever it is wanted.
func writeInterimReport(o *options, meta *runMeta, socks *sockCollector, started time.Time) {
	if err := finalReport(o, meta, socks, false); err != nil {
		fmt.Fprintln(os.Stderr, "interim report:", err)
		return
	}
	if !o.quiet {
		fmt.Printf("  ↳ %s/report.txt refreshed (%s elapsed)\n",
			o.dir, time.Since(started).Round(time.Minute))
	}
}

// finalReport re-reads samples.jsonl and renders report.txt plus peers.csv and
// timeline.csv. Reading back from disk (instead of keeping every sample in
// memory) is what lets a multi-day run stay flat in RSS, and it means `report`
// on a saved directory produces exactly the same output.
//
// printReport controls whether the rendered text also goes to stdout: true at
// the end of a run, false for the periodic mid-run refresh.
func finalReport(o *options, meta *runMeta, socks *sockCollector, printReport bool) error {
	samples, err := readSamples(filepath.Join(o.dir, "samples.jsonl"))
	if err != nil {
		return err
	}
	var exact map[string]*peerTotal
	if socks != nil {
		exact = socks.Peers
	}
	rep := analyze(samples, meta, exact, o.topPeers)

	text := rep.Render()
	if err := os.WriteFile(filepath.Join(o.dir, "report.txt"), []byte(text), 0o600); err != nil {
		return err
	}
	if err := writePeersCSV(filepath.Join(o.dir, "peers.csv"), rep); err != nil {
		return err
	}
	if err := writeTimelineCSV(filepath.Join(o.dir, "timeline.csv"), samples); err != nil {
		return err
	}
	if printReport {
		fmt.Print(text)
		fmt.Printf("\nwritten: %s/report.txt, peers.csv, timeline.csv, samples.jsonl\n", o.dir)
	}
	return nil
}

func runReportCmd(args []string) error {
	var o options
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	fs.IntVar(&o.topPeers, "top-peers", 25, "peers listed in the report")
	if err := fs.Parse(args); err != nil {
		return err
	}
	target := fs.Arg(0)
	if target == "" {
		return fmt.Errorf("usage: server-monitor report <run-dir|samples.jsonl>")
	}

	path := target
	dir := filepath.Dir(target)
	if st, err := os.Stat(target); err == nil && st.IsDir() {
		dir = target
		path = filepath.Join(target, "samples.jsonl")
	}
	samples, err := readSamples(path)
	if err != nil {
		return err
	}
	meta, _ := readMeta(filepath.Join(dir, "meta.json"))
	rep := analyze(samples, meta, nil, o.topPeers)
	fmt.Print(rep.Render())
	return nil
}

// runSnapshot takes two samples a couple of seconds apart and prints the
// derived rates — a quick "what is this box doing right now" without starting
// a recording.
func runSnapshot(args []string) error {
	var o options
	fs := flag.NewFlagSet("snapshot", flag.ExitOnError)
	o.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	clkTck = o.clkTck
	if o.interval > 5*time.Second {
		o.interval = 3 * time.Second
	}

	host := collectHostInfo()
	m, err := newProcMatcher(o.match, o.pids)
	if err != nil {
		return err
	}
	var probe Sample
	inodes, _ := collectProcs(&probe, m, o.topProcs)
	resolveTargets(&o, probe.Procs)

	sc := newScraper(o.metricsURL, o.healthURL, o.pprofURL, o.discURL, o.pubKey, os.TempDir(), o.profileSecs, 0)
	var socks *sockCollector
	if !o.noSocks && netlinkAvailable() == nil {
		ports := parsePorts(o.ports)
		if len(ports) == 0 {
			ports = listenPorts(inodes)
		}
		socks = newSockCollector(o.topPeers, ports)
	}

	printBanner(&o, host, probe.Procs, sc, "")

	ctx := context.Background()
	a := takeSample(ctx, &o, m, socks, sc, 0)
	time.Sleep(o.interval)
	b := takeSample(ctx, &o, m, socks, sc, 1)

	rep := analyze([]*Sample{a, b}, &runMeta{Version: version, Started: a.TS, Host: host}, nil, o.topPeers)
	fmt.Print(rep.Render())
	return nil
}
