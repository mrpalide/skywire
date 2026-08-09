//go:build linux

// netlink_linux_test.go — the tcp_info / inet_diag_msg field offsets are the
// one place in this tool where a silent off-by-eight produces plausible-looking
// but wrong per-peer byte numbers. These tests build the kernel's byte layout
// by hand and assert every field lands where it should.
package main

import (
	"encoding/binary"
	"io"
	"net"
	"syscall"
	"testing"
)

// buildSockID lays out a 48-byte inet_diag_sockid.
func buildSockID(sport, dport uint16, src, dst net.IP, cookie uint64) []byte {
	b := make([]byte, 48)
	binary.BigEndian.PutUint16(b[0:2], sport) // ports are network order
	binary.BigEndian.PutUint16(b[2:4], dport)
	copy(b[4:20], src.To16())
	copy(b[20:36], dst.To16())
	nativeEndian.PutUint32(b[36:40], 0) // idiag_if
	nativeEndian.PutUint32(b[40:44], uint32(cookie))
	nativeEndian.PutUint32(b[44:48], uint32(cookie>>32))
	return b
}

// buildDiagMsg lays out inet_diag_msg + an optional INET_DIAG_INFO attribute.
func buildDiagMsg(family, state uint8, sockid []byte, rq, wq, uid, inode uint32, info []byte) []byte {
	b := make([]byte, inetDiagMsgLen)
	b[0] = family
	b[1] = state
	b[2] = 0 // timer
	b[3] = 0 // retrans
	copy(b[4:52], sockid)
	nativeEndian.PutUint32(b[52:56], 0) // expires
	nativeEndian.PutUint32(b[56:60], rq)
	nativeEndian.PutUint32(b[60:64], wq)
	nativeEndian.PutUint32(b[64:68], uid)
	nativeEndian.PutUint32(b[68:72], inode)

	if info != nil {
		attr := make([]byte, 4+len(info))
		nativeEndian.PutUint16(attr[0:2], uint16(4+len(info)))
		nativeEndian.PutUint16(attr[2:4], inetDiagInfo)
		copy(attr[4:], info)
		// pad to NLA_ALIGN
		for len(attr)%4 != 0 {
			attr = append(attr, 0)
		}
		b = append(b, attr...)
	}
	return b
}

// buildTCPInfo writes a struct tcp_info with known values at the documented
// offsets.
func buildTCPInfo(size int) []byte {
	b := make([]byte, size)
	b[tiCAState] = 3
	b[tiRetransmits] = 7
	put32 := func(off int, v uint32) {
		if off+4 <= len(b) {
			nativeEndian.PutUint32(b[off:off+4], v)
		}
	}
	put64 := func(off int, v uint64) {
		if off+8 <= len(b) {
			nativeEndian.PutUint64(b[off:off+8], v)
		}
	}
	put32(tiUnacked, 11)
	put32(tiLost, 12)
	put32(tiRTT, 45000)
	put32(tiSndCwnd, 64)
	put32(tiTotalRetrans, 99)
	put64(tiBytesAcked, 123456789)
	put64(tiBytesRecv, 987654321)
	put32(tiSegsOut, 4242)
	put32(tiSegsIn, 2424)
	put32(tiNotSent, 555)
	put32(tiMinRTT, 1500)
	return b
}

func TestParseDiagMsgIPv4(t *testing.T) {
	src := net.ParseIP("10.0.0.7")
	dst := net.ParseIP("203.0.113.9")
	// AF_INET only fills the first 4 bytes of the 16-byte address slots.
	sid := make([]byte, 48)
	binary.BigEndian.PutUint16(sid[0:2], 8081)
	binary.BigEndian.PutUint16(sid[2:4], 51234)
	copy(sid[4:8], src.To4())
	copy(sid[20:24], dst.To4())
	nativeEndian.PutUint32(sid[40:44], 0xAAAABBBB)
	nativeEndian.PutUint32(sid[44:48], 0xCCCCDDDD)

	msg := buildDiagMsg(syscall.AF_INET, 1, sid, 100, 200, 1000, 654321, buildTCPInfo(192))

	s, ok := parseDiagMsg(msg)
	if !ok {
		t.Fatal("parseDiagMsg returned !ok")
	}
	if got := s.SrcIP.String(); got != "10.0.0.7" {
		t.Errorf("SrcIP = %q, want 10.0.0.7", got)
	}
	if got := s.DstIP.String(); got != "203.0.113.9" {
		t.Errorf("DstIP = %q, want 203.0.113.9", got)
	}
	if s.SrcPort != 8081 || s.DstPort != 51234 {
		t.Errorf("ports = %d/%d, want 8081/51234", s.SrcPort, s.DstPort)
	}
	if s.State != 1 {
		t.Errorf("State = %d, want 1", s.State)
	}
	if s.RQueue != 100 || s.WQueue != 200 {
		t.Errorf("queues = %d/%d, want 100/200", s.RQueue, s.WQueue)
	}
	if s.UID != 1000 {
		t.Errorf("UID = %d, want 1000", s.UID)
	}
	if s.Inode != 654321 {
		t.Errorf("Inode = %d, want 654321", s.Inode)
	}
	if want := uint64(0xCCCCDDDD)<<32 | 0xAAAABBBB; s.Cookie != want {
		t.Errorf("Cookie = %#x, want %#x", s.Cookie, want)
	}
}

func TestParseTCPInfoOffsets(t *testing.T) {
	sid := buildSockID(1, 2, net.ParseIP("::1"), net.ParseIP("::2"), 5)
	msg := buildDiagMsg(syscall.AF_INET6, 1, sid, 0, 0, 0, 1, buildTCPInfo(192))

	s, ok := parseDiagMsg(msg)
	if !ok {
		t.Fatal("parseDiagMsg returned !ok")
	}
	if !s.HasInfo {
		t.Fatal("HasInfo = false, want true")
	}
	checks := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"CAState", uint64(s.CAState), 3},
		{"Retransmits", uint64(s.Retransmits), 7},
		{"Unacked", uint64(s.Unacked), 11},
		{"Lost", uint64(s.Lost), 12},
		{"RTTUs", uint64(s.RTTUs), 45000},
		{"SndCwnd", uint64(s.SndCwnd), 64},
		{"TotalRetrans", uint64(s.TotalRetrans), 99},
		{"BytesAcked", s.BytesAcked, 123456789},
		{"BytesRecv", s.BytesRecv, 987654321},
		{"SegsOut", uint64(s.SegsOut), 4242},
		{"SegsIn", uint64(s.SegsIn), 2424},
		{"NotSent", uint64(s.NotSent), 555},
		{"MinRTTUs", uint64(s.MinRTTUs), 1500},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// An older kernel returns a SHORTER tcp_info. Reading past the end must yield
// zero rather than panicking or reading neighbouring memory.
func TestParseTCPInfoTruncated(t *testing.T) {
	sid := buildSockID(1, 2, net.ParseIP("::1"), net.ParseIP("::2"), 5)
	short := buildTCPInfo(104) // stops right before pacing_rate/bytes_acked
	msg := buildDiagMsg(syscall.AF_INET6, 1, sid, 0, 0, 0, 1, short)

	s, ok := parseDiagMsg(msg)
	if !ok {
		t.Fatal("parseDiagMsg returned !ok")
	}
	if s.TotalRetrans != 99 {
		t.Errorf("TotalRetrans = %d, want 99 (present in the short struct)", s.TotalRetrans)
	}
	if s.BytesAcked != 0 || s.BytesRecv != 0 {
		t.Errorf("bytes = %d/%d, want 0/0 for a truncated tcp_info", s.BytesAcked, s.BytesRecv)
	}
}

func TestParseDiagMsgTooShort(t *testing.T) {
	if _, ok := parseDiagMsg(make([]byte, 40)); ok {
		t.Error("parseDiagMsg accepted a 40-byte message; want rejection")
	}
}

// buildDiagRequest must produce exactly the 72 bytes the kernel expects, or
// the dump fails with EINVAL at runtime.
func TestBuildDiagRequest(t *testing.T) {
	req := buildDiagRequest(syscall.AF_INET, protoTCP)
	if len(req) != 72 {
		t.Fatalf("request length = %d, want 72", len(req))
	}
	if got := nativeEndian.Uint32(req[0:4]); got != 72 {
		t.Errorf("nlmsg_len = %d, want 72", got)
	}
	if got := nativeEndian.Uint16(req[4:6]); got != sockDiagByFamily {
		t.Errorf("nlmsg_type = %d, want %d", got, sockDiagByFamily)
	}
	if got := nativeEndian.Uint16(req[6:8]); got != syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP {
		t.Errorf("nlmsg_flags = %#x, want %#x", got, syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	}
	if req[16] != syscall.AF_INET {
		t.Errorf("sdiag_family = %d, want %d", req[16], syscall.AF_INET)
	}
	if req[17] != protoTCP {
		t.Errorf("sdiag_protocol = %d, want %d", req[17], protoTCP)
	}
	if req[18]&extInfo == 0 {
		t.Error("idiag_ext does not request INET_DIAG_INFO; per-peer byte counters would be missing")
	}
	if got := nativeEndian.Uint32(req[20:24]); got != allStates {
		t.Errorf("idiag_states = %#x, want %#x", got, allStates)
	}
}

// The first dump of a run must report NO traffic and NO new connections.
// Sockets that already exist carry their whole lifetime in tcpi_bytes_acked;
// counting those would credit every peer connected at startup with gigabytes
// in a single interval, and that number feeds the run-long peer aggregate
// behind TOP PEERS and peers.csv.
func TestSockCollectorPrimingReportsNoTraffic(t *testing.T) {
	if err := netlinkAvailable(); err != nil {
		t.Skipf("sock_diag unavailable: %v", err)
	}

	// Move real bytes over a real connection first, so the sockets we prime
	// against have non-zero lifetime counters to be tempted by.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close() //nolint:errcheck
		buf := make([]byte, 64*1024)
		for i := 0; i < 64; i++ {
			if _, err := c.Write(buf); err != nil {
				return
			}
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck
	if _, err := io.CopyN(io.Discard, conn, 4<<20); err != nil {
		t.Fatalf("draining the test connection: %v", err)
	}

	c := newSockCollector(64, nil)
	first, err := c.collect(nil, 0)
	if err != nil {
		t.Fatalf("first collect: %v", err)
	}
	if first.TCPTotal == 0 {
		t.Skip("no attributable TCP sockets in this environment")
	}
	if first.BytesOutDelta != 0 || first.BytesInDelta != 0 {
		t.Errorf("priming dump reported %d/%d bytes; want 0/0 — pre-existing "+
			"connections' lifetime counters leaked into the first interval",
			first.BytesOutDelta, first.BytesInDelta)
	}
	if first.NewConns != 0 {
		t.Errorf("priming dump reported %d new connections; want 0 — they existed already", first.NewConns)
	}
	for _, p := range first.Peers {
		if p.OutDelta != 0 || p.InDelta != 0 {
			t.Errorf("peer %s credited with %d/%d bytes on the priming dump; want 0/0",
				p.IP, p.OutDelta, p.InDelta)
		}
	}
	for ip, p := range c.Peers {
		if p.Out != 0 || p.In != 0 {
			t.Errorf("run-long aggregate for %s starts at %d/%d bytes; want 0/0", ip, p.Out, p.In)
		}
	}

	// The second dump is a real difference and may legitimately be non-zero.
	if _, err := c.collect(nil, 1); err != nil {
		t.Fatalf("second collect: %v", err)
	}
	if !c.primed {
		t.Error("collector still not primed after two dumps")
	}
	<-done
}

// The real thing: dump this machine's own sockets and sanity-check the result
// against /proc/net/tcp. Skipped where sock_diag is unavailable.
func TestDumpSocketsLive(t *testing.T) {
	if err := netlinkAvailable(); err != nil {
		t.Skipf("sock_diag unavailable: %v", err)
	}
	// Hold an established connection open for the duration of the dump. The
	// kernel only attaches INET_DIAG_INFO to FULL sockets — a box whose only
	// socket is in TIME_WAIT legitimately returns none — so the assertion
	// below needs an established socket it can count on existing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck
	srv := <-accepted
	defer srv.Close() //nolint:errcheck

	socks, err := dumpSockets(protoTCP)
	if err != nil {
		t.Fatalf("dumpSockets: %v", err)
	}
	t.Logf("dumped %d TCP sockets", len(socks))

	var established, estabWithInfo, listening int
	for _, s := range socks {
		switch s.State {
		case 1: // ESTABLISHED
			established++
			if s.HasInfo {
				estabWithInfo++
			}
			if s.DstPort == 0 {
				t.Errorf("established socket with zero remote port: %+v", s)
			}
		case 10: // LISTEN
			listening++
		}
		if len(s.SrcIP) == 0 {
			t.Errorf("socket with no local address: %+v", s)
		}
	}
	t.Logf("%d established (%d with tcp_info), %d listening", established, estabWithInfo, listening)

	if established == 0 {
		t.Fatal("the connection opened above did not appear in the dump")
	}
	if estabWithInfo == 0 {
		t.Error("no established socket carried INET_DIAG_INFO; per-peer byte accounting would be silently empty")
	}
}
