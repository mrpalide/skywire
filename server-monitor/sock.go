// sock.go — turns raw socket dumps into a per-tick SockSummary.
//
// The tricky part is byte accounting. tcpi_bytes_acked / tcpi_bytes_received
// are cumulative FOR THE LIFE OF ONE CONNECTION, so you cannot just sum them
// across ticks. The collector keeps the previous tick's value per socket and
// records the difference:
//
//	existing socket -> delta = now - previous
//	new socket      -> delta = now            (bytes since it was opened)
//	closed socket   -> whatever it moved after the last tick is lost
//
// With a 10s interval that trailing loss is negligible, and the alternative
// (per-connection cumulative totals in every sample) would make the JSONL
// enormous and still need differencing to be read.
package main

import (
	"net"
	"sort"
	"strconv"
)

// stateNames maps the TCP state enum the kernel returns.
var stateNames = map[uint8]string{
	1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
	5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
	9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING", 12: "NEW_SYN_RECV",
}

func stateName(s uint8) string {
	if n, ok := stateNames[s]; ok {
		return n
	}
	return "STATE_" + strconv.Itoa(int(s))
}

// sockCollector holds the cross-tick state needed to difference byte counters.
type sockCollector struct {
	prev     map[sockKey]sockBytes
	primed   bool            // false until the first dump has established a baseline
	ports    map[uint16]bool // -ports fallback when fds are unreadable
	topPeers int

	// Peers accumulates the whole run so the final report can rank talkers
	// exactly, not just from the per-sample top-N that lands in the JSONL.
	Peers    map[string]*peerTotal
	overflow int
}

type sockBytes struct {
	out     uint64
	in      uint64
	retrans uint32
}

// peerTotal is the run-long aggregate for one remote IP.
type peerTotal struct {
	IP        string
	Out       uint64
	In        uint64
	Retrans   uint64
	NewConns  int
	MaxConns  int
	Samples   int
	FirstSeen int // sample index
	LastSeen  int
}

const maxTrackedPeers = 200000

func newSockCollector(topPeers int, ports map[uint16]bool) *sockCollector {
	return &sockCollector{
		prev:     map[sockKey]sockBytes{},
		ports:    ports,
		topPeers: topPeers,
		Peers:    map[string]*peerTotal{},
	}
}

// owns decides whether a socket belongs to the processes we track. inodes is
// the union of socket inodes read from /proc/<pid>/fd; when that was not
// readable (no root) it is nil and we fall back to matching the local port
// against the tracked listen ports.
func (c *sockCollector) owns(s rawSock, inodes map[uint32]bool) bool {
	if len(inodes) > 0 {
		return inodes[s.Inode]
	}
	if len(c.ports) > 0 {
		return c.ports[s.SrcPort]
	}
	return true // no filter available: account for everything
}

// collect dumps TCP (and UDP for the QUIC listener) and builds the summary.
func (c *sockCollector) collect(inodes map[uint32]bool, sampleIdx int) (*SockSummary, error) {
	tcp, err := dumpSockets(protoTCP)
	if err != nil {
		return nil, err
	}

	sum := &SockSummary{Source: "netlink", ByState: map[string]int{}}
	seen := make(map[sockKey]sockBytes, len(tcp))

	type agg struct {
		conns    int
		newConns int
		out      uint64
		in       uint64
		retrans  uint64
		ports    map[uint16]bool
		rttSum   uint64
		rttN     uint64
	}
	peers := map[string]*agg{}

	var rttSum, rttN uint64

	for _, s := range tcp {
		if !c.owns(s, inodes) {
			sum.Untracked++
			continue
		}
		sum.TCPTotal++
		st := stateName(s.State)
		sum.ByState[st]++

		if s.State == 10 { // LISTEN
			sum.Listen = append(sum.Listen, ListenStat{
				Addr:   net.JoinHostPort(s.SrcIP.String(), strconv.Itoa(int(s.SrcPort))),
				RQueue: s.RQueue,
				WQueue: s.WQueue,
			})
			continue
		}

		sum.SendQ += uint64(s.WQueue)
		sum.RecvQ += uint64(s.RQueue)

		k := s.key()
		cur := sockBytes{out: s.BytesAcked, in: s.BytesRecv, retrans: s.TotalRetrans}
		seen[k] = cur

		var dOut, dIn, dRtx uint64
		isNew := false
		p, known := c.prev[k]

		// The priming dump has no earlier reading to difference against. Every
		// socket in it is PRE-EXISTING, not new, and its counters hold the
		// bytes of its whole lifetime — counting those would put a phantom
		// spike (potentially gigabytes) into this one interval and credit it
		// to whichever peers happened to be connected when we started. So on
		// the first dump we only record the baseline and report no movement.
		switch {
		case !c.primed:
			// deltas stay zero; seen[k] above is the baseline.
		case known:
			// Counters only move forward within a connection; a decrease means
			// the kernel recycled the identity, so treat it as a fresh socket.
			if cur.out >= p.out {
				dOut = cur.out - p.out
			} else {
				dOut = cur.out
			}
			if cur.in >= p.in {
				dIn = cur.in - p.in
			} else {
				dIn = cur.in
			}
			if cur.retrans >= p.retrans {
				dRtx = uint64(cur.retrans - p.retrans)
			}
		default:
			isNew = true
			dOut, dIn = cur.out, cur.in
			dRtx = uint64(cur.retrans)
			sum.NewConns++
		}

		sum.BytesOutDelta += dOut
		sum.BytesInDelta += dIn
		sum.RetransDelta += dRtx

		if s.State == 1 && s.RTTUs > 0 { // ESTABLISHED
			rttSum += uint64(s.RTTUs)
			rttN++
			if s.RTTUs > sum.RTTMaxUs {
				sum.RTTMaxUs = s.RTTUs
			}
		}

		ip := s.DstIP.String()
		a := peers[ip]
		if a == nil {
			a = &agg{ports: map[uint16]bool{}}
			peers[ip] = a
		}
		a.conns++
		if isNew {
			a.newConns++
		}
		a.out += dOut
		a.in += dIn
		a.retrans += dRtx
		a.ports[s.SrcPort] = true
		if s.RTTUs > 0 {
			a.rttSum += uint64(s.RTTUs)
			a.rttN++
		}
	}

	for k := range c.prev {
		if _, ok := seen[k]; !ok {
			sum.ClosedConns++
		}
	}
	c.prev = seen
	c.primed = true

	if rttN > 0 {
		sum.RTTAvgUs = uint32(rttSum / rttN) //nolint:gosec
	}

	// UDP: the dmsg server serves QUIC + WebTransport on the same port number
	// over UDP. There are no per-socket byte counters for UDP, and QUIC muxes
	// every peer onto ONE socket anyway, so all we can do here is count
	// sockets and queue depth. Datagram volume comes from /proc/net/snmp and
	// the "unattributed" gap in the report's traffic reconciliation.
	if udp, err := dumpSockets(protoUDP); err == nil {
		for _, s := range udp {
			if !c.owns(s, inodes) {
				continue
			}
			sum.UDPTotal++
			sum.UDPRxQueue += uint64(s.RQueue)
			sum.UDPTxQueue += uint64(s.WQueue)
		}
	}

	// Fold this tick into the run-long aggregate, then emit the per-sample
	// top-N (plus a remainder bucket so interval totals still reconcile).
	list := make([]PeerStat, 0, len(peers))
	for ip, a := range peers {
		var rtt uint32
		if a.rttN > 0 {
			rtt = uint32(a.rttSum / a.rttN) //nolint:gosec
		}
		list = append(list, PeerStat{
			IP: ip, Conns: a.conns, NewConns: a.newConns,
			OutDelta: a.out, InDelta: a.in, Retrans: a.retrans,
			Ports: len(a.ports), RTTUs: rtt,
		})
		c.addPeer(ip, a.out, a.in, a.retrans, a.newConns, a.conns, sampleIdx)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].OutDelta != list[j].OutDelta {
			return list[i].OutDelta > list[j].OutDelta
		}
		return list[i].InDelta > list[j].InDelta
	})
	if c.topPeers > 0 && len(list) > c.topPeers {
		for _, p := range list[c.topPeers:] {
			sum.PeersOther += p.OutDelta + p.InDelta
			sum.PeersOtherN++
		}
		list = list[:c.topPeers]
	}
	sum.Peers = list

	sort.Slice(sum.Listen, func(i, j int) bool { return sum.Listen[i].Addr < sum.Listen[j].Addr })
	return sum, nil
}

func (c *sockCollector) addPeer(ip string, out, in, rtx uint64, newConns, conns, idx int) {
	p := c.Peers[ip]
	if p == nil {
		if len(c.Peers) >= maxTrackedPeers {
			c.overflow++
			return
		}
		p = &peerTotal{IP: ip, FirstSeen: idx}
		c.Peers[ip] = p
	}
	p.Out += out
	p.In += in
	p.Retrans += rtx
	p.NewConns += newConns
	p.Samples++
	p.LastSeen = idx
	if conns > p.MaxConns {
		p.MaxConns = conns
	}
}

// listenPorts extracts the local ports of the tracked processes' listening
// sockets, used as the -ports fallback filter and to label the report.
func listenPorts(inodes map[uint32]bool) map[uint16]bool {
	out := map[uint16]bool{}
	socks, err := dumpSockets(protoTCP)
	if err != nil {
		return out
	}
	for _, s := range socks {
		if s.State == 10 && (len(inodes) == 0 || inodes[s.Inode]) {
			out[s.SrcPort] = true
		}
	}
	return out
}
