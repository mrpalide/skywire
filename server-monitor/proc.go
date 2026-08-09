// proc.go — process discovery and per-process sampling.
//
// Two levels of detail on purpose:
//
//   - Every process on the box gets a ProcBrief (pid, name, cpu jiffies, rss).
//     That is what makes the report able to say "the CPU spike was not the
//     dmsg-server, it was unattended-upgrades" instead of just "CPU was high".
//   - Processes matching -match / -pid get the full ProcStat (fds, io, context
//     switches, thread count) and have their sockets dumped.
package main

import (
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// clkTck is USER_HZ. It is 100 on every mainstream Linux build; -clktck
// overrides it for the rare kernel configured otherwise.
var clkTck float64 = 100

var pageSize = uint64(os.Getpagesize()) //nolint:gosec

// listPIDs returns every numeric entry under /proc.
func listPIDs() []int {
	d, err := os.Open(procRoot) //nolint:gosec
	if err != nil {
		return nil
	}
	defer d.Close() //nolint:errcheck

	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil
	}
	pids := make([]int, 0, len(names))
	for _, n := range names {
		if n[0] < '0' || n[0] > '9' {
			continue
		}
		if pid, err := strconv.Atoi(n); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// readCmdline returns the full argv with NULs turned into spaces.
func readCmdline(pid int) string {
	b, err := os.ReadFile(procPath(strconv.Itoa(pid), "cmdline")) //nolint:gosec
	if err != nil || len(b) == 0 {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(strings.TrimRight(string(b), "\x00"), "\x00", " "))
}

// readStat parses /proc/<pid>/stat.
//
// The comm field is parenthesised and may itself contain spaces and
// parentheses ("(my (weird) proc)"), so the split has to start after the LAST
// ')' — splitting on whitespace from the left silently shifts every field for
// such processes and yields nonsense CPU numbers.
func readStat(pid int, p *ProcStat) bool {
	b, err := os.ReadFile(procPath(strconv.Itoa(pid), "stat")) //nolint:gosec
	if err != nil {
		return false
	}
	line := string(b)
	open := strings.IndexByte(line, '(')
	closeIdx := strings.LastIndexByte(line, ')')
	if open < 0 || closeIdx < open {
		return false
	}
	p.PID = pid
	p.Name = line[open+1 : closeIdx]

	// f[i] is stat field i+3 (field 1 = pid, 2 = comm, 3 = state).
	f := strings.Fields(line[closeIdx+1:])
	get := func(i int) uint64 {
		if i < len(f) {
			return atou(f[i])
		}
		return 0
	}
	if len(f) > 0 {
		p.State = f[0]
	}
	p.PPID = int(get(1))       //nolint:gosec // field 4
	p.MinFlt = get(7)          // field 10
	p.MajFlt = get(9)          // field 12
	p.Utime = get(11)          // field 14
	p.Stime = get(12)          // field 15
	p.Threads = int(get(17))   //nolint:gosec // field 20
	p.StartTime = get(19)      // field 22
	p.VMS = get(20)            // field 23
	p.RSS = get(21) * pageSize // field 24, in pages
	return true
}

// readProcIO parses /proc/<pid>/io. Needs the same uid or root; on failure the
// io fields simply stay zero.
func readProcIO(pid int, p *ProcStat) {
	for _, ln := range readLines(procPath(strconv.Itoa(pid), "io")) {
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		n := atou(strings.TrimSpace(v))
		switch k {
		case "rchar":
			p.RChar = n
		case "wchar":
			p.WChar = n
		case "read_bytes":
			p.ReadBytes = n
		case "write_bytes":
			p.WriteBytes = n
		case "syscr":
			p.Syscr = n
		case "syscw":
			p.Syscw = n
		}
	}
}

// readProcStatus picks up the context-switch counters, which are the tell for
// a process burning CPU on scheduling rather than on work.
func readProcStatus(pid int, p *ProcStat) {
	for _, ln := range readLines(procPath(strconv.Itoa(pid), "status")) {
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "voluntary_ctxt_switches":
			p.VolCtx = atou(v)
		case "nonvoluntary_ctxt_switches":
			p.NvolCtx = atou(v)
		}
	}
}

// readFDLimit pulls "Max open files" (soft) out of /proc/<pid>/limits.
func readFDLimit(pid int) int {
	for _, ln := range readLines(procPath(strconv.Itoa(pid), "limits")) {
		if !strings.HasPrefix(ln, "Max open files") {
			continue
		}
		f := strings.Fields(ln)
		// "Max open files  <soft>  <hard>  files"
		if len(f) >= 5 {
			if n, err := strconv.Atoi(f[3]); err == nil {
				return n
			}
		}
	}
	return 0
}

// scanFDs walks /proc/<pid>/fd once and returns the fd count plus the set of
// socket inodes the process owns. The inode set is what lets the socket dump
// be filtered down to THIS process's connections.
//
// Requires root (or same-uid). On EACCES it returns ok=false and the caller
// records a note; socket attribution then falls back to -ports matching.
func scanFDs(pid int) (nfd int, inodes map[uint32]bool, ok bool) {
	dir := procPath(strconv.Itoa(pid), "fd")
	d, err := os.Open(dir) //nolint:gosec
	if err != nil {
		return 0, nil, false
	}
	defer d.Close() //nolint:errcheck

	names, err := d.Readdirnames(-1)
	if err != nil {
		return 0, nil, false
	}
	inodes = make(map[uint32]bool, len(names))
	for _, n := range names {
		nfd++
		link, err := os.Readlink(dir + "/" + n)
		if err != nil || !strings.HasPrefix(link, "socket:[") {
			continue
		}
		ino, err := strconv.ParseUint(link[8:len(link)-1], 10, 32)
		if err == nil {
			inodes[uint32(ino)] = true
		}
	}
	return nfd, inodes, true
}

// procMatcher decides which processes get the deep treatment.
type procMatcher struct {
	re   *regexp.Regexp
	pids map[int]bool
	self int
}

func newProcMatcher(match, pidList string) (*procMatcher, error) {
	m := &procMatcher{pids: map[int]bool{}, self: os.Getpid()}
	for _, p := range strings.Split(pidList, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
		m.pids[n] = true
	}
	if len(m.pids) == 0 && match != "" {
		re, err := regexp.Compile(match)
		if err != nil {
			return nil, err
		}
		m.re = re
	}
	return m, nil
}

func (m *procMatcher) match(pid int, name, cmd string) bool {
	if pid == m.self {
		return false // never monitor ourselves into a feedback loop
	}
	if len(m.pids) > 0 {
		return m.pids[pid]
	}
	if m.re == nil {
		return false
	}
	return m.re.MatchString(cmd) || m.re.MatchString(name)
}

// collectProcs walks /proc once, filling Procs (tracked, deep) and TopProcs
// (everything, shallow — trimmed to the busiest by the caller's ranking at
// report time). It returns the union of socket inodes owned by tracked
// processes, and whether every tracked process's fds were readable.
func collectProcs(s *Sample, m *procMatcher, topN int) (inodes map[uint32]bool, fdsOK bool) {
	inodes = map[uint32]bool{}
	fdsOK = true
	var briefs []ProcBrief

	for _, pid := range listPIDs() {
		var p ProcStat
		if !readStat(pid, &p) {
			continue // exited between readdir and read; normal
		}
		cmd := readCmdline(pid)
		if cmd == "" {
			cmd = "[" + p.Name + "]" // kernel thread
		}
		briefs = append(briefs, ProcBrief{
			PID: pid, Name: p.Name, Cmd: truncate(cmd, 120),
			Utime: p.Utime, Stime: p.Stime, RSS: p.RSS,
		})

		if !m.match(pid, p.Name, cmd) {
			continue
		}
		p.Cmd = truncate(cmd, 400)
		readProcIO(pid, &p)
		readProcStatus(pid, &p)
		p.FDLimit = readFDLimit(pid)
		nfd, ino, ok := scanFDs(pid)
		if !ok {
			fdsOK = false
		} else {
			p.FDs = nfd
			p.Sockets = len(ino)
			for i := range ino {
				inodes[i] = true
			}
		}
		s.Procs = append(s.Procs, p)
	}

	// Keep every brief for a small box; otherwise keep the top-N by lifetime
	// CPU plus anything with a big RSS. The report differences consecutive
	// samples, so a process must appear in BOTH to get a rate — ranking by
	// lifetime CPU keeps that stable across ticks.
	s.TopProcs = trimBriefs(briefs, topN)
	return inodes, fdsOK
}

// trimBriefs keeps the n processes with the most lifetime CPU and the n with
// the largest RSS (union), so both a CPU hog and a memory hog stay visible
// without recording all ~300 processes every tick.
func trimBriefs(b []ProcBrief, n int) []ProcBrief {
	if n <= 0 || len(b) <= n {
		return b
	}
	keep := map[int]bool{}
	byCPU := make([]ProcBrief, len(b))
	copy(byCPU, b)
	sort.Slice(byCPU, func(x, y int) bool {
		return byCPU[x].Utime+byCPU[x].Stime > byCPU[y].Utime+byCPU[y].Stime
	})
	for i := 0; i < n && i < len(byCPU); i++ {
		keep[byCPU[i].PID] = true
	}
	byRSS := make([]ProcBrief, len(b))
	copy(byRSS, b)
	sort.Slice(byRSS, func(x, y int) bool { return byRSS[x].RSS > byRSS[y].RSS })
	for i := 0; i < n && i < len(byRSS); i++ {
		keep[byRSS[i].PID] = true
	}
	out := make([]ProcBrief, 0, len(keep))
	for _, p := range b {
		if keep[p.PID] {
			out = append(out, p)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// autodetect pulls the service's own HTTP surfaces out of the tracked
// processes' argv, so the common case needs no flags at all:
//
//	--metrics/-m <addr>   -> http://<addr>/metrics
//	--pprofaddr <addr>    -> http://<addr>/debug/pprof   (when --pprofmode http)
//	<config.json>         -> health_endpoint_address, public_key
type detected struct {
	MetricsURL string
	PProfURL   string
	HealthURL  string
	ConfigPath string
	PubKey     string
}

func autodetect(procs []ProcStat) detected {
	var d detected
	for _, p := range procs {
		args := strings.Fields(p.Cmd)
		var pprofMode, pprofAddr string

		for i := 0; i < len(args); i++ {
			a := args[i]
			// Accept both "--flag=value" and "--flag value".
			key, val, hasEq := strings.Cut(a, "=")
			if !hasEq {
				key = a
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					val = args[i+1]
				}
			}
			switch key {
			case "-m", "--metrics":
				if d.MetricsURL == "" && val != "" {
					d.MetricsURL = "http://" + normalizeAddr(val) + "/metrics"
				}
			case "--pprofaddr":
				pprofAddr = val
			case "--pprofmode":
				pprofMode = val
			default:
				// The config is a bare positional argument whose name varies
				// by deployment (`dmsg server start /etc/skywire-dmsgd.conf`
				// in the shipped systemd unit, config.json elsewhere), so
				// match on "is an existing regular file" rather than on a
				// suffix. i > 0 skips the executable itself.
				if d.ConfigPath == "" && i > 0 && !strings.HasPrefix(a, "-") && isRegularFile(a) {
					d.ConfigPath = a
				}
			}
		}
		if pprofMode == "http" && pprofAddr != "" && d.PProfURL == "" {
			d.PProfURL = "http://" + normalizeAddr(pprofAddr)
		}
	}
	return d
}

func isRegularFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// normalizeAddr turns a bind address into something dialable: a wildcard or
// empty host becomes 127.0.0.1, since the monitor runs on the same box.
func normalizeAddr(a string) string {
	a = strings.TrimSpace(a)
	if a == "" {
		return "127.0.0.1"
	}
	if strings.HasPrefix(a, ":") {
		return "127.0.0.1" + a
	}
	if strings.HasPrefix(a, "0.0.0.0:") {
		return "127.0.0.1:" + strings.TrimPrefix(a, "0.0.0.0:")
	}
	if strings.HasPrefix(a, "[::]:") {
		return "127.0.0.1:" + strings.TrimPrefix(a, "[::]:")
	}
	return a
}
