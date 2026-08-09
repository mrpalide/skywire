// sample.go — the on-disk sample record and its JSONL reader/writer.
//
// Every tick the collectors fill one Sample and it is appended to
// samples.jsonl as a single line. Counters are stored RAW (cumulative,
// exactly as the kernel reports them); all rates and deltas are derived at
// report time. That keeps the recording lossless, so `server-monitor report`
// on a saved run produces byte-identical output to the live run's report.
//
// The one exception is Socks.Peers: per-connection byte counters reset when a
// connection closes, so per-peer numbers are already differenced by the
// collector (it holds the previous tick's per-socket counters) and stored as
// per-interval deltas. Those fields are named *Delta to keep it obvious.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Sample is one tick of everything we can see about the host and the
// processes we track.
type Sample struct {
	TS       time.Time `json:"ts"`
	UptimeS  float64   `json:"uptime_s,omitempty"`
	BootTime int64     `json:"boot_time,omitempty"`

	// Host-wide.
	CPU          CPUStat              `json:"cpu"`
	Cores        []CPUStat            `json:"cores,omitempty"`
	Load         [3]float64           `json:"load"`
	Mem          MemStat              `json:"mem"`
	Ifaces       map[string]IfaceStat `json:"ifaces,omitempty"`
	NetStat      map[string]uint64    `json:"netstat,omitempty"`
	SockStat     map[string]int64     `json:"sockstat,omitempty"`
	Pressure     map[string]float64   `json:"pressure,omitempty"`
	Ctxt         uint64               `json:"ctxt,omitempty"`
	Interrupts   uint64               `json:"intr,omitempty"`
	ForkTotal    uint64               `json:"forks,omitempty"`
	ProcsRunning int                  `json:"procs_running,omitempty"`
	ProcsBlocked int                  `json:"procs_blocked,omitempty"`
	Conntrack    int64                `json:"conntrack,omitempty"`

	// Processes.
	Procs    []ProcStat  `json:"procs,omitempty"`     // the ones we track
	TopProcs []ProcBrief `json:"top_procs,omitempty"` // busiest on the box, whoever they are

	// Sockets owned by the tracked processes.
	Socks *SockSummary `json:"socks,omitempty"`

	// Scrapes of the service's own HTTP surfaces.
	Targets []TargetScrape `json:"targets,omitempty"`

	// Notes carries collector-level problems (permission denied, endpoint
	// down) so the report can say why a section is empty instead of
	// silently showing zeros.
	Notes []string `json:"notes,omitempty"`
}

// CPUStat holds raw jiffies from /proc/stat.
type CPUStat struct {
	Name    string `json:"n,omitempty"`
	User    uint64 `json:"user"`
	Nice    uint64 `json:"nice"`
	System  uint64 `json:"system"`
	Idle    uint64 `json:"idle"`
	IOWait  uint64 `json:"iowait"`
	IRQ     uint64 `json:"irq"`
	SoftIRQ uint64 `json:"softirq"`
	Steal   uint64 `json:"steal"`
}

// Total is every jiffy the CPU accounted for in this snapshot.
func (c CPUStat) Total() uint64 {
	return c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
}

// Busy is everything that is not idle or waiting on IO.
func (c CPUStat) Busy() uint64 { return c.Total() - c.Idle - c.IOWait }

// MemStat is the subset of /proc/meminfo worth keeping, in bytes.
type MemStat struct {
	Total     uint64 `json:"total"`
	Free      uint64 `json:"free"`
	Available uint64 `json:"available"`
	Buffers   uint64 `json:"buffers"`
	Cached    uint64 `json:"cached"`
	SwapTotal uint64 `json:"swap_total"`
	SwapFree  uint64 `json:"swap_free"`
	Dirty     uint64 `json:"dirty"`
}

// Used is total minus available (the number people mean by "memory used").
func (m MemStat) Used() uint64 {
	if m.Available > m.Total {
		return 0
	}
	return m.Total - m.Available
}

// IfaceStat is one row of /proc/net/dev.
type IfaceStat struct {
	RxBytes   uint64 `json:"rxb"`
	RxPackets uint64 `json:"rxp"`
	RxErrs    uint64 `json:"rxe,omitempty"`
	RxDrop    uint64 `json:"rxd,omitempty"`
	TxBytes   uint64 `json:"txb"`
	TxPackets uint64 `json:"txp"`
	TxErrs    uint64 `json:"txe,omitempty"`
	TxDrop    uint64 `json:"txd,omitempty"`
}

// ProcStat is the deep per-process snapshot for a tracked process.
type ProcStat struct {
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid,omitempty"`
	Name      string `json:"name"`
	Cmd       string `json:"cmd,omitempty"`
	State     string `json:"state,omitempty"`
	StartTime uint64 `json:"start_jiffies,omitempty"`

	Utime   uint64 `json:"utime"`
	Stime   uint64 `json:"stime"`
	Threads int    `json:"threads"`
	RSS     uint64 `json:"rss"`
	VMS     uint64 `json:"vms"`
	MinFlt  uint64 `json:"minflt,omitempty"`
	MajFlt  uint64 `json:"majflt,omitempty"`
	VolCtx  uint64 `json:"volctx,omitempty"`
	NvolCtx uint64 `json:"nvolctx,omitempty"`

	FDs     int `json:"fds,omitempty"`
	FDLimit int `json:"fd_limit,omitempty"`
	Sockets int `json:"sockets,omitempty"`

	RChar      uint64 `json:"rchar,omitempty"`
	WChar      uint64 `json:"wchar,omitempty"`
	ReadBytes  uint64 `json:"read_bytes,omitempty"`
	WriteBytes uint64 `json:"write_bytes,omitempty"`
	Syscr      uint64 `json:"syscr,omitempty"`
	Syscw      uint64 `json:"syscw,omitempty"`
}

// ProcBrief is the cheap snapshot kept for every process on the box, so a CPU
// spike that is NOT the dmsg-server still has a name attached to it.
type ProcBrief struct {
	PID   int    `json:"pid"`
	Name  string `json:"name"`
	Cmd   string `json:"cmd,omitempty"`
	Utime uint64 `json:"utime"`
	Stime uint64 `json:"stime"`
	RSS   uint64 `json:"rss,omitempty"`
}

// SockSummary is the per-tick socket picture for the tracked processes.
type SockSummary struct {
	Source string `json:"source"` // "netlink" or "procfs"

	TCPTotal int            `json:"tcp_total"`
	ByState  map[string]int `json:"by_state,omitempty"`
	Listen   []ListenStat   `json:"listen,omitempty"`

	UDPTotal   int    `json:"udp_total,omitempty"`
	UDPRxQueue uint64 `json:"udp_rxq,omitempty"`
	UDPTxQueue uint64 `json:"udp_txq,omitempty"`
	UDPDrops   uint64 `json:"udp_drops,omitempty"`

	NewConns    int `json:"new_conns"`
	ClosedConns int `json:"closed_conns"`

	// Per-interval totals across all tracked connections.
	BytesOutDelta uint64 `json:"bytes_out_delta"`
	BytesInDelta  uint64 `json:"bytes_in_delta"`
	RetransDelta  uint64 `json:"retrans_delta,omitempty"`

	// Aggregate queue depth — a rising SendQ means peers are not draining.
	SendQ uint64 `json:"sendq,omitempty"`
	RecvQ uint64 `json:"recvq,omitempty"`

	// RTT stats over established conns, microseconds.
	RTTAvgUs uint32 `json:"rtt_avg_us,omitempty"`
	RTTMaxUs uint32 `json:"rtt_max_us,omitempty"`

	// Peers holds the top talkers of THIS interval (capped, see
	// -peers-per-sample). PeersOther/PeersOtherN account for the tail so
	// interval totals still reconcile.
	Peers       []PeerStat `json:"peers,omitempty"`
	PeersOther  uint64     `json:"peers_other_out,omitempty"`
	PeersOtherN int        `json:"peers_other_n,omitempty"`

	Untracked int `json:"untracked,omitempty"` // sockets we could not attribute
}

// ListenStat is a listening socket plus its accept-queue occupancy. RQueue is
// the current completed-connection backlog, WQueue the configured maximum —
// RQueue approaching WQueue means accept() is not keeping up.
type ListenStat struct {
	Addr   string `json:"addr"`
	RQueue uint32 `json:"rq"`
	WQueue uint32 `json:"wq"`
}

// PeerStat aggregates one remote IP for one interval.
type PeerStat struct {
	IP       string `json:"ip"`
	Conns    int    `json:"conns"`
	NewConns int    `json:"new,omitempty"`
	OutDelta uint64 `json:"out"`
	InDelta  uint64 `json:"in"`
	Retrans  uint64 `json:"rtx,omitempty"`
	Ports    int    `json:"ports,omitempty"` // distinct local ports it is on
	RTTUs    uint32 `json:"rtt_us,omitempty"`
}

// TargetScrape is one HTTP surface of the monitored service.
type TargetScrape struct {
	Name        string             `json:"name"`
	Metrics     map[string]float64 `json:"metrics,omitempty"`
	Health      map[string]any     `json:"health,omitempty"`
	Goroutines  map[string]int     `json:"goroutines,omitempty"`
	GoroutineN  int                `json:"goroutine_n,omitempty"`
	DiscClients int                `json:"disc_clients,omitempty"`
	LatencyMs   float64            `json:"latency_ms,omitempty"`
	Err         string             `json:"err,omitempty"`
}

// sampleWriter appends samples to a JSONL file.
type sampleWriter struct {
	mu sync.Mutex
	f  *os.File
	w  *bufio.Writer
	n  int
}

func newSampleWriter(path string) (*sampleWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &sampleWriter{f: f, w: bufio.NewWriterSize(f, 1<<16)}, nil
}

// Write appends one sample and flushes, so a run killed with SIGKILL still
// leaves every completed tick on disk.
func (s *sampleWriter) Write(smp *Sample) error {
	b, err := json.Marshal(smp)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(b); err != nil {
		return err
	}
	if err := s.w.WriteByte('\n'); err != nil {
		return err
	}
	s.n++
	return s.w.Flush()
}

func (s *sampleWriter) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.w.Flush(); err != nil {
		s.f.Close() //nolint:errcheck
		return err
	}
	return s.f.Close()
}

// readSamples loads a samples.jsonl back into memory. A truncated final line
// (process killed mid-write) is skipped rather than failing the whole read.
func readSamples(path string) ([]*Sample, error) {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)

	var out []*Sample
	var bad int
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var s Sample
		if err := json.Unmarshal(line, &s); err != nil {
			bad++
			continue
		}
		out = append(out, &s)
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("read %s: %w", path, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable samples in %s (%d unparsable lines)", path, bad)
	}
	return out, nil
}
