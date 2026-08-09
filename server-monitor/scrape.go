// scrape.go — the service's own HTTP surfaces.
//
// A dmsg-server started with `-m <addr>` serves Prometheus text at
// /metrics: the dmsg_server_* gauges (clients, sessions, streams,
// packets/minute) plus the Go runtime and process metrics VictoriaMetrics
// exports. That is the inside view — how many sessions the server THINKS it
// has — which is what makes the outside view (sockets, bytes) interpretable.
//
// With `--pprofmode http` we additionally get goroutine breakdowns and can
// capture a real CPU profile at the moment CPU spikes, which is the difference
// between "CPU was 300%" and "CPU was 300% inside Noise handshakes".
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// keepMetric decides which Prometheus series survive into the sample. The
// endpoint emits a few hundred series per scrape; over a 12-hour run at 10s
// that is millions of numbers nobody reads. These prefixes are the ones the
// report actually uses.
var keepMetricPrefix = []string{
	"dmsg_",
	"go_goroutines",
	"go_threads",
	"go_memstats_alloc_bytes",
	"go_memstats_heap_",
	"go_memstats_stack_",
	"go_memstats_sys_bytes",
	"go_memstats_next_gc_bytes",
	"go_gc_duration_seconds",
	"go_gc_forced_count",
	"go_sched_latency_seconds",
	"process_cpu_seconds_total",
	"process_resident_memory_bytes",
	"process_virtual_memory_bytes",
	"process_open_fds",
	"process_max_fds",
	"process_io_",
	"process_num_threads",
	"process_minor_pagefaults_total",
	"process_major_pagefaults_total",
}

func keepMetric(name string) bool {
	for _, p := range keepMetricPrefix {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// scraper fetches the service's endpoints. All requests are short-timeout and
// failures are recorded in the sample rather than aborting the run — a
// dmsg-server that stops answering /metrics is itself a finding.
type scraper struct {
	client   *http.Client
	metrics  string
	health   string
	pprof    string
	disc     string
	pubKey   string
	outDir   string
	profSecs int
	maxProfs int

	mu       sync.Mutex
	nProfs   int
	profBusy bool
}

func newScraper(metricsURL, healthURL, pprofURL, discURL, pubKey, outDir string, profSecs, maxProfs int) *scraper {
	return &scraper{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DisableKeepAlives:   false,
				MaxIdleConnsPerHost: 2,
			},
		},
		metrics:  metricsURL,
		health:   healthURL,
		pprof:    strings.TrimSuffix(pprofURL, "/"),
		disc:     strings.TrimSuffix(discURL, "/"),
		pubKey:   pubKey,
		outDir:   outDir,
		profSecs: profSecs,
		maxProfs: maxProfs,
	}
}

func (s *scraper) enabled() bool {
	return s.metrics != "" || s.health != "" || s.pprof != "" || s.disc != ""
}

// scrape gathers one TargetScrape. Every sub-fetch is independent: a dead
// pprof endpoint must not cost us the metrics.
func (s *scraper) scrape(ctx context.Context) TargetScrape {
	t := TargetScrape{Name: "dmsg-server"}
	var errs []string

	if s.metrics != "" {
		start := time.Now()
		m, err := s.fetchMetrics(ctx)
		t.LatencyMs = float64(time.Since(start).Microseconds()) / 1000
		if err != nil {
			errs = append(errs, "metrics: "+err.Error())
		} else {
			t.Metrics = m
		}
	}
	if s.health != "" {
		h, err := s.fetchHealth(ctx)
		if err != nil {
			errs = append(errs, "health: "+err.Error())
		} else {
			t.Health = h
		}
	}
	if s.pprof != "" {
		g, total, err := s.fetchGoroutines(ctx)
		if err != nil {
			errs = append(errs, "pprof: "+err.Error())
		} else {
			t.Goroutines = g
			t.GoroutineN = total
		}
	}
	if s.disc != "" && s.pubKey != "" {
		n, err := s.fetchDiscClients(ctx)
		if err != nil {
			errs = append(errs, "disc: "+err.Error())
		} else {
			t.DiscClients = n
		}
	}
	if len(errs) > 0 {
		t.Err = strings.Join(errs, "; ")
	}
	return t
}

func (s *scraper) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return body, fmt.Errorf("http %d", resp.StatusCode)
	}
	return body, nil
}

// fetchMetrics parses the Prometheus text exposition format. Labels are kept
// as part of the series name so e.g. quantile buckets stay distinguishable.
func (s *scraper) fetchMetrics(ctx context.Context) (map[string]float64, error) {
	body, err := s.get(ctx, s.metrics)
	if err != nil {
		return nil, err
	}
	out := map[string]float64{}
	for _, ln := range strings.Split(string(body), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || ln[0] == '#' {
			continue
		}
		i := strings.LastIndexByte(ln, ' ')
		if i < 0 {
			continue
		}
		series := strings.TrimSpace(ln[:i])
		name := series
		if b := strings.IndexByte(series, '{'); b >= 0 {
			name = series[:b]
		}
		if !keepMetric(name) {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(ln[i+1:]), 64)
		if err != nil {
			continue
		}
		out[series] = v
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no matching series in %d bytes", len(body))
	}
	return out, nil
}

func (s *scraper) fetchHealth(ctx context.Context) (map[string]any, error) {
	body, err := s.get(ctx, s.health)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// fetchGoroutines reads /debug/pprof/goroutine?debug=1 and buckets goroutines
// by the function they are parked in. A leak shows up as one bucket growing
// without bound; a handshake storm shows up as a big transient bucket.
func (s *scraper) fetchGoroutines(ctx context.Context) (map[string]int, int, error) {
	body, err := s.get(ctx, s.pprof+"/debug/pprof/goroutine?debug=1")
	if err != nil {
		return nil, 0, err
	}
	lines := strings.Split(string(body), "\n")
	out := map[string]int{}
	total := 0
	pending := 0
	for _, ln := range lines {
		switch {
		case strings.HasPrefix(ln, "goroutine profile: total "):
			total = atoi(strings.TrimSpace(strings.TrimPrefix(ln, "goroutine profile: total ")))
		case strings.Contains(ln, " @ "):
			// "<count> @ 0x... 0x..." starts a new stack group.
			pending = atoi(strings.Fields(ln)[0])
		case strings.HasPrefix(ln, "#") && pending > 0:
			// First frame line after the header names the stack. Fields are
			// "#", "0xADDR", "pkg.Func+0x..", "/path/file.go:123".
			f := strings.Fields(ln)
			if len(f) >= 3 {
				fn := f[2]
				if p := strings.IndexByte(fn, '+'); p > 0 {
					fn = fn[:p]
				}
				out[shortFunc(fn)] += pending
			}
			pending = 0
		}
	}
	if total == 0 {
		for _, v := range out {
			total += v
		}
	}
	return out, total, nil
}

// shortFunc trims a fully qualified symbol to something readable in a table,
// keeping the last package element and the function.
func shortFunc(fn string) string {
	if i := strings.LastIndexByte(fn, '/'); i >= 0 {
		fn = fn[i+1:]
	}
	return fn
}

// fetchDiscClients asks dmsg-discovery how many clients name this server as a
// delegated server. Comparing that with the live session count catches the
// "registered but nobody can reach it" and "serving clients that no longer
// list us" cases.
func (s *scraper) fetchDiscClients(ctx context.Context) (int, error) {
	url := s.disc + "/dmsg-discovery/server/" + s.pubKey + "/clients"
	body, err := s.get(ctx, url)
	if err != nil {
		return 0, err
	}
	var pks []string
	if err := json.Unmarshal(body, &pks); err != nil {
		return 0, err
	}
	return len(pks), nil
}

// captureProfiles grabs a CPU profile, a full goroutine dump and a heap
// profile, writing them next to the samples for later `go tool pprof`. It is
// fired when CPU crosses the spike threshold, which is exactly when a profile
// is worth having and exactly when nobody is at the keyboard to take one.
//
// Runs in its own goroutine; a guard keeps one capture in flight at a time so
// a sustained spike does not stack up 30-second profiles.
func (s *scraper) captureProfiles(reason string, ts time.Time) bool {
	if s.pprof == "" {
		return false
	}
	s.mu.Lock()
	if s.profBusy || (s.maxProfs > 0 && s.nProfs >= s.maxProfs) {
		s.mu.Unlock()
		return false
	}
	s.profBusy = true
	s.nProfs++
	n := s.nProfs
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			s.profBusy = false
			s.mu.Unlock()
		}()

		stamp := ts.Format("20060102-150405")
		base := filepath.Join(s.outDir, fmt.Sprintf("profile-%02d-%s-%s", n, stamp, sanitize(reason)))

		// Longer client timeout than the profile duration, or the CPU
		// profile fetch always times out.
		cl := &http.Client{Timeout: time.Duration(s.profSecs+30) * time.Second}
		save := func(suffix, url string) {
			req, err := http.NewRequest(http.MethodGet, url, nil) //nolint:noctx
			if err != nil {
				return
			}
			resp, err := cl.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close() //nolint:errcheck
			if resp.StatusCode != http.StatusOK {
				return
			}
			f, err := os.Create(base + suffix) //nolint:gosec
			if err != nil {
				return
			}
			defer f.Close() //nolint:errcheck
			_, _ = io.Copy(f, io.LimitReader(resp.Body, 256<<20))
		}

		// Goroutine dump first — it is instant and captures the state DURING
		// the spike, before the 30s CPU profile has smeared it.
		save(".goroutines.txt", s.pprof+"/debug/pprof/goroutine?debug=2")
		save(".heap.pprof", s.pprof+"/debug/pprof/heap")
		save(".cpu.pprof", fmt.Sprintf("%s/debug/pprof/profile?seconds=%d", s.pprof, s.profSecs))
	}()
	return true
}

func (s *scraper) profileCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nProfs
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// readDmsgConfig pulls what we need out of a dmsg-server config.json: the
// public key (for the discovery cross-check) and the health endpoint address.
type dmsgConfig struct {
	PublicKey     string `json:"public_key"`
	LocalAddress  string `json:"local_address"`
	HTTPAddress   string `json:"health_endpoint_address"`
	PublicAddress string `json:"public_address"`
	Discovery     string `json:"discovery"`
	MaxSessions   int    `json:"max_sessions"`
}

func readDmsgConfig(path string) (*dmsgConfig, error) {
	b, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, err
	}
	var c dmsgConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
