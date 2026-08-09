// proc_test.go — process parsing and endpoint auto-detection.
//
// Auto-detection is what makes `server-monitor watch` work with no flags at
// all, so it is pinned against the command lines the dmsg-server is actually
// started with in production (the shipped systemd unit) rather than an
// idealised one.
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAutodetectFromSystemdCommandLine(t *testing.T) {
	// The unit in init/skywire-dmsg.service, plus the two flags the README
	// asks operators to add.
	conf := filepath.Join(t.TempDir(), "skywire-dmsgd.conf")
	if err := os.WriteFile(conf, []byte(`{"public_key":"abc"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	procs := []ProcStat{{
		PID:  4242,
		Name: "skywire",
		Cmd: "/bin/skywire dmsg server start " + conf +
			" -m 127.0.0.1:9081 --pprofmode http --pprofaddr 127.0.0.1:6060",
	}}

	d := autodetect(procs)
	if want := "http://127.0.0.1:9081/metrics"; d.MetricsURL != want {
		t.Errorf("MetricsURL = %q, want %q", d.MetricsURL, want)
	}
	if want := "http://127.0.0.1:6060"; d.PProfURL != want {
		t.Errorf("PProfURL = %q, want %q", d.PProfURL, want)
	}
	if d.ConfigPath != conf {
		t.Errorf("ConfigPath = %q, want %q", d.ConfigPath, conf)
	}
}

// The "--flag=value" spelling has to work too, and a pprof address without
// --pprofmode=http must NOT be advertised: the server would not be serving it.
func TestAutodetectEqualsFormAndPProfGate(t *testing.T) {
	d := autodetect([]ProcStat{{
		PID: 1, Name: "skywire",
		Cmd: "/bin/skywire dmsg server start --metrics=0.0.0.0:9081 --pprofaddr=127.0.0.1:6060",
	}})
	if want := "http://127.0.0.1:9081/metrics"; d.MetricsURL != want {
		t.Errorf("MetricsURL = %q, want %q (wildcard host must become loopback)", d.MetricsURL, want)
	}
	if d.PProfURL != "" {
		t.Errorf("PProfURL = %q, want empty: --pprofmode http was not set", d.PProfURL)
	}
}

func TestNormalizeAddr(t *testing.T) {
	cases := map[string]string{
		":9081":          "127.0.0.1:9081",
		"0.0.0.0:9081":   "127.0.0.1:9081",
		"[::]:9081":      "127.0.0.1:9081",
		"127.0.0.1:9081": "127.0.0.1:9081",
		"10.0.0.5:9081":  "10.0.0.5:9081",
		"":               "127.0.0.1",
	}
	for in, want := range cases {
		if got := normalizeAddr(in); got != want {
			t.Errorf("normalizeAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

// A comm field containing spaces and parentheses shifts every subsequent field
// if /proc/<pid>/stat is split from the left. Splitting after the LAST ')' is
// what keeps the CPU numbers correct for such processes.
func TestReadStatWeirdComm(t *testing.T) {
	dir := t.TempDir()
	old := procRoot
	procRoot = dir
	defer func() { procRoot = old }()

	if err := os.MkdirAll(filepath.Join(dir, "77"), 0o750); err != nil {
		t.Fatal(err)
	}
	// fields: pid (comm) state ppid pgrp session tty tpgid flags minflt
	//         cminflt majflt cmajflt utime stime cutime cstime prio nice
	//         threads itrealvalue starttime vsize rss
	line := "77 (weird (proc) name) S 1 77 77 0 -1 4194560 111 0 222 0 " +
		"1400 600 0 0 20 0 9 0 5555 123456 789"
	if err := os.WriteFile(filepath.Join(dir, "77", "stat"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	var p ProcStat
	if !readStat(77, &p) {
		t.Fatal("readStat returned false")
	}
	if p.Name != "weird (proc) name" {
		t.Errorf("Name = %q, want %q", p.Name, "weird (proc) name")
	}
	if p.State != "S" {
		t.Errorf("State = %q, want S", p.State)
	}
	if p.PPID != 1 {
		t.Errorf("PPID = %d, want 1", p.PPID)
	}
	if p.MinFlt != 111 || p.MajFlt != 222 {
		t.Errorf("faults = %d/%d, want 111/222", p.MinFlt, p.MajFlt)
	}
	if p.Utime != 1400 || p.Stime != 600 {
		t.Errorf("cpu jiffies = %d/%d, want 1400/600", p.Utime, p.Stime)
	}
	if p.Threads != 9 {
		t.Errorf("Threads = %d, want 9", p.Threads)
	}
	if p.StartTime != 5555 {
		t.Errorf("StartTime = %d, want 5555", p.StartTime)
	}
	if p.VMS != 123456 {
		t.Errorf("VMS = %d, want 123456", p.VMS)
	}
	if want := 789 * pageSize; p.RSS != want {
		t.Errorf("RSS = %d, want %d (789 pages)", p.RSS, want)
	}
}

func TestProcMatcher(t *testing.T) {
	m, err := newProcMatcher(`dmsg-server|dmsg\s+server|skywire`, "")
	if err != nil {
		t.Fatal(err)
	}
	if !m.match(10, "skywire", "/bin/skywire dmsg server start /etc/x.conf") {
		t.Error("systemd-style dmsg server command line did not match")
	}
	if !m.match(11, "dmsg-server", "./dmsg-server config.json") {
		t.Error("standalone dmsg-server did not match")
	}
	if m.match(12, "sshd", "/usr/sbin/sshd -D") {
		t.Error("sshd should not match")
	}
	if m.match(os.Getpid(), "server-monitor", "server-monitor watch") {
		t.Error("the monitor must never track itself")
	}

	// An explicit -pid list overrides the regexp entirely.
	m2, err := newProcMatcher("skywire", "99,100")
	if err != nil {
		t.Fatal(err)
	}
	if !m2.match(99, "anything", "anything") {
		t.Error("pid 99 should match the explicit list")
	}
	if m2.match(5, "skywire", "/bin/skywire dmsg server start") {
		t.Error("regexp should be ignored when -pid is given")
	}
}
