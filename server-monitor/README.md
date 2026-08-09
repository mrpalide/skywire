# server-monitor

A single, dependency-free Go binary that records what a Skywire service host is
actually doing — and turns hours of that into one readable report.

It exists for alerts like these:

```
outbound traffic rate - dmsg-server-2
inbound traffic rate  - dmsg-server-2
CPU Usage             - dmsg-server-2
```

Those name a machine. They never name a cause. This names the cause: **which
process**, **which remote peer**, **how many connections**, whether the CPU
tracks *bytes* or tracks *connection churn*, and — with pprof enabled — what
the server was executing at the moment it spiked.

Build it, `scp` it, run it as a systemd service (unit file included) or in
`tmux`. No agent, no collector, no Prometheus, no dependencies.

---

## Build

From this directory (it is its own Go module, separate from the skywire one):

```bash
cd server-monitor && ./build.sh
```

That produces `dist/server-monitor-linux-amd64` and `-arm64`. Or by hand:

```bash
GOOS=linux GOARCH=amd64 go build -o server-monitor .
```

Copy it to the server:

```bash
scp dist/server-monitor-linux-amd64 root@dmsg-server-2:/usr/local/bin/server-monitor
```

## Run

```bash
sudo server-monitor watch -duration 6h
```

That is the whole thing. It finds the dmsg-server process by itself, discovers
its `/metrics` and pprof endpoints from its own command line, samples every 10
seconds, prints a status line every minute, and writes a report when it stops
(or when you hit Ctrl-C — the report is written on the way out).

**Run it as root.** Without root it cannot read `/proc/<pid>/fd`, and per-peer
traffic can only be attributed by listening port instead of exactly per
process. Everything else still works.

### Run it as a service (recommended for anything unattended)

`tmux` is fine for a quick look, but for a run measured in hours or days use
systemd: it survives your ssh session *and* a reboot — which matters, because a
reboot may be the very incident you are chasing.

```bash
install -m755 dist/server-monitor-linux-amd64 /usr/local/bin/server-monitor
install -m644 skywire-monitor.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now skywire-monitor
```

```bash
journalctl -u skywire-monitor -f          # live status line
cat /var/log/skywire-monitor/*/report.txt # the current report, any time
systemctl stop skywire-monitor            # SIGTERM -> final report is written
```

The shipped unit runs as root, rotates daily (`-duration 24h` with
`Restart=always`, so each day is one self-contained report), and is
deliberately **not** niced — a low-priority monitor gets descheduled exactly
during the spike it was installed to measure.

Two things it does *not* do, on purpose: it never pins `-dir` to a fixed path
(`samples.jsonl` is opened for append, so a restart would splice two runs into
one timeline), and it is not part of the deployment — install it while you are
investigating and disable it when you are done.

If the box hard-reboots, nothing is lost: every sample is flushed as it is
taken, so `server-monitor report <dir>` reconstructs the full report from
whatever was recorded.

Runs accumulate one directory per day at roughly 50–100 MB each, so prune them:

```bash
find /var/log/skywire-monitor -maxdepth 1 -type d -mtime +7 -exec rm -rf {} +
```

For a quick interactive look instead, `tmux new -s monitor` and
`sudo server-monitor watch -duration 12h` works exactly as well.

### Output

A directory `server-monitor-<host>-<timestamp>/` containing:

| file | what it is |
|---|---|
| `report.txt` | the human-readable report (also printed to the terminal) |
| `peers.csv` | every remote address with byte totals, connection counts, churn |
| `timeline.csv` | every interval, every metric — for a spreadsheet or gnuplot |
| `samples.jsonl` | the raw samples; nothing is thrown away |
| `profile-NN-*.cpu.pprof` | CPU profiles captured automatically during spikes |
| `profile-NN-*.goroutines.txt` | full goroutine dumps taken at the same moment |
| `profile-NN-*.heap.pprof` | heap profiles from the same moment |

There is one `report.txt`, and it is **cumulative over the whole run** — not one
report per interval. `-report-every` only controls how often that single file is
refreshed on disk (quietly; it is not printed) so you can `cat` it mid-run
without stopping the recording.

### Matching a recurring alert

If your alert fires on a schedule (say every 2 hours), run long enough to cover
**several cycles** — the TIMELINE sparklines then answer the first question for
you. Evenly spaced humps mean a genuinely periodic event; a flat plateau means
one sustained condition that your monitoring is simply re-notifying about.

```bash
sudo server-monitor watch -duration 8h -mbit-spike 400
```

Setting `-mbit-spike` (or `-cpu-spike`) near your alert's own threshold makes
the monitor capture a CPU profile and goroutine dump *at the moment the alert
fires*. Raise `-max-profiles` if you want one for every cycle.

Note that whole-run averages dilute a short periodic spike. For a recurring
event, read **WORST INTERVALS**, the TIMELINE strips, and `timeline.csv` rather
than the p50/avg columns.

Re-render a report later, on any machine, without re-running anything:

```bash
server-monitor report server-monitor-dmsg-server-2-20260809-101500/
```

Same input always produces the same output, so reports from two different days
can be `diff`ed directly.

---

## Getting the most out of it

The tool works with zero configuration, but two flags on the **dmsg-server
itself** roughly double what it can tell you. Both are safe on a bind address
restricted to localhost.

### 1. Metrics — the server's own view

Without this, the report knows how many TCP sockets exist but not how many
*dmsg sessions* the server thinks it has, how many handshakes are failing, or
how its goroutines and heap are trending.

```
ExecStart=/bin/skywire dmsg server start /etc/skywire-dmsgd.conf -m 127.0.0.1:9081
```

### 2. pprof — what the CPU is actually executing

With this, the monitor captures a CPU profile, a full goroutine dump and a heap
profile **automatically, the moment CPU crosses the threshold** — which is
exactly when a profile is worth having and exactly when nobody is watching.

```
ExecStart=/bin/skywire dmsg server start /etc/skywire-dmsgd.conf \
    -m 127.0.0.1:9081 --pprofmode http --pprofaddr 127.0.0.1:6060
```

Then:

```bash
go tool pprof -http=: profile-01-*.cpu.pprof
```

After editing the unit: `systemctl daemon-reload && systemctl restart skywire-dmsg`.

---

## What the report tells you

The sections answer an operator's questions in the order they get asked.

- **TIMELINE** — every metric as a sparkline on one shared time axis. A shape
  that repeats across CPU and egress is visible at a glance.
- **CPU** — busy time split into user/system/softirq/iowait/steal, plus the
  busiest single core (a pegged core hides in an average) and how many cores
  that adds up to. High `steal` means the hypervisor is taking your CPU: part
  of the alert isn't your workload at all.
- **NETWORK** — egress/ingress rates with p50/p95/max, totals, packet rates,
  mean packet size, per-interface split, and drops.
- **TRAFFIC ATTRIBUTION** — how much of what left the NIC can be pinned on the
  tracked process's TCP connections. High coverage means *this traffic is the
  service*. Low coverage means it is UDP/QUIC, another process, or sockets we
  couldn't read.
- **CONNECTIONS** — sockets by state, new/closed rate, mean connection
  lifetime, send/receive queue depth, and accept-queue backlog.
- **TOP PEERS / TOP NETWORKS / CHURN** — who the bytes went to, grouped also by
  /24 and /48 so one actor spread across many addresses still shows as one, and
  separately ranked by *reconnect* rate.
- **DMSG-SERVER INTERNAL METRICS** — sessions, streams, handshake failures,
  goroutines, heap, plus growth trends per hour (the leak detectors).
- **TRACKED PROCESSES / BUSIEST PROCESSES** — per-process CPU, RSS trend, fds
  against the limit, context switches; and every busy process on the box, so
  you can *rule the service out*.
- **WORST INTERVALS** — the peak intervals with everything else that was true
  at that moment, including the top peer during that interval.
- **WHAT DOES CPU TRACK?** — correlation of CPU against bytes, packets, new
  connections, sessions, streams. If CPU tracks bytes, the problem is
  throughput. If it tracks new connections, the problem is handshake churn.
  Different fixes.
- **FINDINGS** — the plain-language conclusions the numbers support.

---

## Useful flags

```
-duration 6h          how long to run (0 = until Ctrl-C)
-interval 10s         sampling interval
-pid 12345            track exactly this process instead of matching by name
-match REGEX          what counts as a tracked process
-cpu-spike 80         capture pprof profiles above this % of total CPU (0 = off)
-mbit-spike 500       also capture above this egress rate
-top-peers 25         peers listed in the report
-report-every 30m     how often report.txt is rewritten during the run
-quiet                no live status line
```

`server-monitor snapshot` gives a one-off look at the current state without
starting a recording. `server-monitor watch -h` lists everything.

## Cost of running it

One sample is a few dozen small `/proc` reads, one netlink socket dump, and one
HTTP scrape — single-digit milliseconds. At the default 10s interval the
monitor costs well under 0.1% of a core. `samples.jsonl` grows at roughly
50–100 MB per 24 hours on a busy server; `-peers-per-sample` bounds the
largest contributor.

## Limits worth knowing

- **Connections shorter than the sampling interval are invisible.** Per-peer
  bytes come from the kernel's per-socket counters, read once per tick. A
  connection that opens *and* closes between two ticks is never sampled. The
  report detects high turnover and says so explicitly; use a shorter
  `-interval` to narrow the gap.
- **Per-peer byte counts are TCP payload**, excluding TCP/IP/Ethernet headers,
  so they run ~5–10% below the NIC counters. That is why the attribution
  section compares them rather than expecting them to match.
- **UDP/QUIC traffic is not attributable per peer.** dmsg serves QUIC and
  WebTransport over UDP on the same port number, and QUIC multiplexes every
  peer onto a single socket — the kernel keeps no per-peer counters there. The
  report shows UDP datagram totals and the unattributed gap instead.
- **Linux only** for the socket statistics (`sock_diag`/`NETLINK_INET_DIAG`).
  The binary builds and the report engine runs anywhere; on other systems the
  socket sections are simply absent.

## Tests

```bash
go test ./...
```

The analysis tests run anywhere. The netlink tests — struct offsets against a
hand-built `inet_diag_msg`, plus a live dump of the machine's own sockets —
need Linux and skip elsewhere.
