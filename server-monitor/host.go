// host.go — host-wide collectors, all of them plain /proc reads.
//
// Nothing here is Linux-build-tagged: the reads are ordinary file opens, so
// the package still compiles on macOS/Windows for development. On a non-Linux
// host the files are simply absent and each collector degrades to a note in
// the sample rather than an error.
package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// procRoot is a variable so a run can be pointed at a copied /proc tree.
var procRoot = "/proc"

func procPath(parts ...string) string {
	return strings.Join(append([]string{procRoot}, parts...), "/")
}

// readLines returns the file's lines, or nil if it cannot be read. Callers
// treat "missing" as "feature unavailable on this kernel", which is the right
// behaviour for every optional file below (/proc/pressure, nf_conntrack, ...).
func readLines(path string) []string {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<22)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	if sc.Err() != nil {
		// Partial content is still useful (procfs reads can race with the
		// kernel rewriting a file); return what we got.
		return out
	}
	return out
}

func readFileTrim(path string) string {
	b, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func atou(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

func atoi(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

func atof(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

// collectCPU parses /proc/stat: the aggregate line, each core, and the
// scheduler counters (context switches, run queue, blocked tasks) that
// distinguish "busy doing work" from "thrashing".
func collectCPU(s *Sample) {
	for _, ln := range readLines(procPath("stat")) {
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		switch {
		case f[0] == "cpu":
			s.CPU = parseCPULine("total", f)
		case strings.HasPrefix(f[0], "cpu"):
			s.Cores = append(s.Cores, parseCPULine(f[0], f))
		case f[0] == "ctxt":
			s.Ctxt = atou(f[1])
		case f[0] == "intr":
			s.Interrupts = atou(f[1])
		case f[0] == "processes":
			s.ForkTotal = atou(f[1])
		case f[0] == "procs_running":
			s.ProcsRunning = atoi(f[1])
		case f[0] == "procs_blocked":
			s.ProcsBlocked = atoi(f[1])
		case f[0] == "btime":
			s.BootTime = int64(atou(f[1])) //nolint:gosec
		}
	}
}

func parseCPULine(name string, f []string) CPUStat {
	get := func(i int) uint64 {
		if i < len(f) {
			return atou(f[i])
		}
		return 0
	}
	return CPUStat{
		Name:    name,
		User:    get(1),
		Nice:    get(2),
		System:  get(3),
		Idle:    get(4),
		IOWait:  get(5),
		IRQ:     get(6),
		SoftIRQ: get(7),
		Steal:   get(8),
	}
}

// collectMem parses /proc/meminfo (kB) into bytes.
func collectMem(s *Sample) {
	for _, ln := range readLines(procPath("meminfo")) {
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		v := atou(f[1]) * 1024
		switch strings.TrimSuffix(f[0], ":") {
		case "MemTotal":
			s.Mem.Total = v
		case "MemFree":
			s.Mem.Free = v
		case "MemAvailable":
			s.Mem.Available = v
		case "Buffers":
			s.Mem.Buffers = v
		case "Cached":
			s.Mem.Cached = v
		case "SwapTotal":
			s.Mem.SwapTotal = v
		case "SwapFree":
			s.Mem.SwapFree = v
		case "Dirty":
			s.Mem.Dirty = v
		}
	}
	// Pre-MemAvailable kernels: approximate so Used() stays meaningful.
	if s.Mem.Available == 0 && s.Mem.Total > 0 {
		s.Mem.Available = s.Mem.Free + s.Mem.Buffers + s.Mem.Cached
	}
}

func collectLoadUptime(s *Sample) {
	if f := strings.Fields(readFileTrim(procPath("loadavg"))); len(f) >= 3 {
		s.Load = [3]float64{atof(f[0]), atof(f[1]), atof(f[2])}
	}
	if f := strings.Fields(readFileTrim(procPath("uptime"))); len(f) >= 1 {
		s.UptimeS = atof(f[0])
	}
}

// collectNetDev reads per-interface byte/packet/error/drop counters. Loopback
// is kept: dmsg health checks and local scrapes ride it, and it is useful to
// be able to subtract it.
func collectNetDev(s *Sample) {
	lines := readLines(procPath("net", "dev"))
	if len(lines) < 3 {
		return
	}
	s.Ifaces = make(map[string]IfaceStat, len(lines))
	for _, ln := range lines[2:] {
		i := strings.IndexByte(ln, ':')
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(ln[:i])
		f := strings.Fields(ln[i+1:])
		if len(f) < 16 {
			continue
		}
		s.Ifaces[name] = IfaceStat{
			RxBytes: atou(f[0]), RxPackets: atou(f[1]), RxErrs: atou(f[2]), RxDrop: atou(f[3]),
			TxBytes: atou(f[8]), TxPackets: atou(f[9]), TxErrs: atou(f[10]), TxDrop: atou(f[11]),
		}
	}
}

// netStatKeys is the allowlist kept from /proc/net/snmp and /proc/net/netstat.
// The full set is ~200 counters per tick; these are the ones that actually
// answer "is the box dropping / retransmitting / overflowing".
var netStatKeys = map[string]bool{
	"Tcp.ActiveOpens": true, "Tcp.PassiveOpens": true, "Tcp.AttemptFails": true,
	"Tcp.EstabResets": true, "Tcp.CurrEstab": true, "Tcp.InSegs": true,
	"Tcp.OutSegs": true, "Tcp.RetransSegs": true, "Tcp.InErrs": true, "Tcp.OutRsts": true,
	"Udp.InDatagrams": true, "Udp.OutDatagrams": true, "Udp.InErrors": true,
	"Udp.NoPorts": true, "Udp.RcvbufErrors": true, "Udp.SndbufErrors": true,
	"TcpExt.ListenOverflows": true, "TcpExt.ListenDrops": true,
	"TcpExt.TCPSynRetrans": true, "TcpExt.TCPTimeouts": true,
	"TcpExt.TCPLostRetransmit": true, "TcpExt.TCPBacklogDrop": true,
	"TcpExt.PruneCalled": true, "TcpExt.RcvPruned": true, "TcpExt.TCPMemoryPressures": true,
	"TcpExt.TCPAbortOnMemory": true, "TcpExt.TCPAbortOnTimeout": true,
	"TcpExt.SyncookiesSent": true, "TcpExt.TCPReqQFullDrop": true,
	"IpExt.InOctets": true, "IpExt.OutOctets": true,
}

// collectNetStat parses the two-line-per-protocol format shared by
// /proc/net/snmp and /proc/net/netstat: a header line naming the columns,
// then a value line with the same prefix.
func collectNetStat(s *Sample) {
	s.NetStat = make(map[string]uint64, len(netStatKeys))
	for _, p := range []string{procPath("net", "snmp"), procPath("net", "netstat")} {
		lines := readLines(p)
		for i := 0; i+1 < len(lines); i += 2 {
			hdr := strings.Fields(lines[i])
			val := strings.Fields(lines[i+1])
			if len(hdr) < 2 || len(val) < 2 || hdr[0] != val[0] {
				continue
			}
			prefix := strings.TrimSuffix(hdr[0], ":")
			for j := 1; j < len(hdr) && j < len(val); j++ {
				k := prefix + "." + hdr[j]
				if netStatKeys[k] {
					s.NetStat[k] = atou(val[j])
				}
			}
		}
	}
	if len(s.NetStat) == 0 {
		s.NetStat = nil
	}
}

// collectSockStat reads /proc/net/sockstat{,6}: socket counts by protocol plus
// the TCP memory pages figure, which is what actually gets hit before a box
// starts refusing connections.
func collectSockStat(s *Sample) {
	s.SockStat = map[string]int64{}
	parse := func(path, suffix string) {
		for _, ln := range readLines(path) {
			f := strings.Fields(ln)
			if len(f) < 3 {
				continue
			}
			proto := strings.TrimSuffix(f[0], ":") + suffix
			for i := 1; i+1 < len(f); i += 2 {
				v, err := strconv.ParseInt(f[i+1], 10, 64)
				if err != nil {
					continue
				}
				s.SockStat[proto+"."+f[i]] = v
			}
		}
	}
	parse(procPath("net", "sockstat"), "")
	parse(procPath("net", "sockstat6"), "6")
	if len(s.SockStat) == 0 {
		s.SockStat = nil
	}
}

// collectPressure reads PSI (kernel >= 4.20). avg10 for cpu/io/memory tells
// you whether tasks are actually STALLING, which plain CPU% never does.
func collectPressure(s *Sample) {
	s.Pressure = map[string]float64{}
	for _, res := range []string{"cpu", "io", "memory"} {
		for _, ln := range readLines(procPath("pressure", res)) {
			f := strings.Fields(ln)
			if len(f) < 2 {
				continue
			}
			kind := f[0] // "some" | "full"
			for _, kv := range f[1:] {
				k, v, ok := strings.Cut(kv, "=")
				if !ok || k == "total" {
					continue
				}
				s.Pressure[res+"."+kind+"."+k] = atof(v)
			}
		}
	}
	if len(s.Pressure) == 0 {
		s.Pressure = nil
	}
}

func collectConntrack(s *Sample) {
	v := readFileTrim("/proc/sys/net/netfilter/nf_conntrack_count")
	if v == "" {
		return
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err == nil {
		s.Conntrack = n
	}
}

// hostInfo is the one-shot machine description printed at the top of a report.
type hostInfo struct {
	Hostname string
	Kernel   string
	NumCPU   int
	MemTotal uint64
	Model    string
}

func collectHostInfo() hostInfo {
	h := hostInfo{}
	h.Hostname, _ = os.Hostname()
	h.Kernel = readFileTrim(procPath("sys", "kernel", "osrelease"))
	for _, ln := range readLines(procPath("cpuinfo")) {
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "processor":
			h.NumCPU++
		case "model name", "Model", "Hardware":
			if h.Model == "" {
				h.Model = strings.TrimSpace(v)
			}
		}
	}
	var s Sample
	collectMem(&s)
	h.MemTotal = s.Mem.Total
	return h
}
