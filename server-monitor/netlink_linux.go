//go:build linux

// netlink_linux.go — sock_diag(NETLINK_INET_DIAG) dump, stdlib only.
//
// This is the whole reason the tool exists. /proc/net/tcp gives you a
// connection list with queue depths but NO byte counters, so it can tell you
// "412 connections" and nothing about which of them is moving 300 Mbit/s.
// inet_diag with the INET_DIAG_INFO extension returns the kernel's struct
// tcp_info per socket, which carries tcpi_bytes_acked / tcpi_bytes_received —
// cumulative payload bytes for the life of that connection. Differencing those
// between ticks gives real per-peer throughput.
//
// Same data as `ss -tinepm`, without shelling out to iproute2 or parsing its
// output.
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

const (
	// sockDiagByFamily is SOCK_DIAG_BY_FAMILY, the only request type
	// NETLINK_INET_DIAG serves. Not exported by the syscall package.
	sockDiagByFamily = 20

	// Attribute ids returned in the rtattr stream after inet_diag_msg.
	inetDiagMeminfo = 1
	inetDiagInfo    = 2
	inetDiagSKMem   = 21

	// idiag_ext is a bitmask over (attr-1).
	extMeminfo = 1 << (inetDiagMeminfo - 1)
	extInfo    = 1 << (inetDiagInfo - 1)

	// inet_diag_msg is a fixed 72-byte header: 4 bytes of state/family/timer/
	// retrans, a 48-byte inet_diag_sockid, then expires/rqueue/wqueue/uid/inode.
	inetDiagMsgLen = 72

	// allStates covers TCP_ESTABLISHED(1) .. TCP_NEW_SYN_RECV(12).
	allStates = uint32(0xFFFF)
)

// nativeEndian is the byte order netlink uses (host order). Addresses and
// ports inside inet_diag_sockid are the exception — those stay network order.
var nativeEndian = binary.NativeEndian

// rawSock is one socket as the kernel described it.
type rawSock struct {
	Family  uint8
	State   uint8
	Timer   uint8
	Retrans uint8

	SrcIP   net.IP
	SrcPort uint16
	DstIP   net.IP
	DstPort uint16

	Cookie uint64
	RQueue uint32
	WQueue uint32
	UID    uint32
	Inode  uint32

	// From INET_DIAG_INFO (struct tcp_info). Absent for UDP.
	HasInfo      bool
	CAState      uint8
	Retransmits  uint8
	RTTUs        uint32
	MinRTTUs     uint32
	SndCwnd      uint32
	Unacked      uint32
	Lost         uint32
	TotalRetrans uint32
	BytesAcked   uint64 // outbound payload the peer has ACKed
	BytesRecv    uint64 // inbound payload
	SegsOut      uint32
	SegsIn       uint32
	NotSent      uint32
}

// key identifies a socket across ticks. The cookie is the kernel's stable
// per-socket id; inode alone can be recycled after a close, which would make a
// brand-new connection look like a huge negative byte delta.
func (s rawSock) key() sockKey { return sockKey{Inode: s.Inode, Cookie: s.Cookie} }

type sockKey struct {
	Inode  uint32
	Cookie uint64
}

// dumpSockets returns every socket of the given IP protocol (syscall.IPPROTO_TCP
// or IPPROTO_UDP) across both address families.
func dumpSockets(proto uint8) ([]rawSock, error) {
	var out []rawSock
	var firstErr error
	for _, fam := range []uint8{syscall.AF_INET, syscall.AF_INET6} {
		socks, err := dumpFamily(fam, proto)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, socks...)
	}
	if out == nil && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func dumpFamily(family, proto uint8) ([]rawSock, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_INET_DIAG)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	defer syscall.Close(fd) //nolint:errcheck

	// A busy dmsg-server can have thousands of sockets; a small rcvbuf makes
	// the kernel drop dump fragments (ENOBUFS) instead of blocking.
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20)

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, sa); err != nil {
		return nil, fmt.Errorf("netlink bind: %w", err)
	}

	req := buildDiagRequest(family, proto)
	if err := syscall.Sendto(fd, req, 0, sa); err != nil {
		return nil, fmt.Errorf("netlink send: %w", err)
	}

	buf := make([]byte, 1<<19)
	var out []rawSock
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return out, fmt.Errorf("netlink recv: %w", err)
		}
		if n < syscall.NLMSG_HDRLEN {
			return out, fmt.Errorf("netlink short read (%d bytes)", n)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return out, fmt.Errorf("netlink parse: %w", err)
		}
		done := false
		for _, m := range msgs {
			switch m.Header.Type {
			case syscall.NLMSG_DONE:
				done = true
			case syscall.NLMSG_ERROR:
				if len(m.Data) >= 4 {
					// errno arrives negated.
					e := int32(nativeEndian.Uint32(m.Data[:4])) //nolint:gosec
					if e != 0 {
						return out, fmt.Errorf("netlink error: %w", syscall.Errno(-e))
					}
				}
				done = true
			case sockDiagByFamily:
				s, ok := parseDiagMsg(m.Data)
				if ok {
					out = append(out, s)
				}
			}
		}
		if done {
			break
		}
	}
	return out, nil
}

// buildDiagRequest lays out nlmsghdr(16) + inet_diag_req_v2(56) by hand.
func buildDiagRequest(family, proto uint8) []byte {
	const reqLen = syscall.NLMSG_HDRLEN + 56
	b := make([]byte, reqLen)

	nativeEndian.PutUint32(b[0:], reqLen)
	nativeEndian.PutUint16(b[4:], sockDiagByFamily)
	nativeEndian.PutUint16(b[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	nativeEndian.PutUint32(b[8:], 1) // seq
	nativeEndian.PutUint32(b[12:], 0)

	b[16] = family
	b[17] = proto
	b[18] = extInfo | extMeminfo
	b[19] = 0
	nativeEndian.PutUint32(b[20:], allStates)
	// b[24:72] is inet_diag_sockid — all zero means "no filter".
	return b
}

// parseDiagMsg decodes inet_diag_msg plus the rtattr stream that follows it.
func parseDiagMsg(d []byte) (rawSock, bool) {
	var s rawSock
	if len(d) < inetDiagMsgLen {
		return s, false
	}
	s.Family = d[0]
	s.State = d[1]
	s.Timer = d[2]
	s.Retrans = d[3]

	// inet_diag_sockid at offset 4:
	//   sport[2] dport[2] src[16] dst[16] if[4] cookie[8]
	s.SrcPort = binary.BigEndian.Uint16(d[4:6])
	s.DstPort = binary.BigEndian.Uint16(d[6:8])
	s.SrcIP = decodeIP(s.Family, d[8:24])
	s.DstIP = decodeIP(s.Family, d[24:40])
	s.Cookie = uint64(nativeEndian.Uint32(d[44:48])) | uint64(nativeEndian.Uint32(d[48:52]))<<32

	s.RQueue = nativeEndian.Uint32(d[56:60])
	s.WQueue = nativeEndian.Uint32(d[60:64])
	s.UID = nativeEndian.Uint32(d[64:68])
	s.Inode = nativeEndian.Uint32(d[68:72])

	parseAttrs(d[inetDiagMsgLen:], &s)
	return s, true
}

// decodeIP reads the fixed 16-byte address slot; AF_INET only fills the first 4.
func decodeIP(family uint8, b []byte) net.IP {
	if family == syscall.AF_INET {
		ip := make(net.IP, 4)
		copy(ip, b[:4])
		return ip
	}
	ip := make(net.IP, 16)
	copy(ip, b[:16])
	return ip
}

// parseAttrs walks the netlink attribute stream (len/type header, 4-byte
// aligned payload).
func parseAttrs(b []byte, s *rawSock) {
	for len(b) >= 4 {
		alen := int(nativeEndian.Uint16(b[0:2]))
		atype := nativeEndian.Uint16(b[2:4])
		if alen < 4 || alen > len(b) {
			return
		}
		payload := b[4:alen]
		if atype == inetDiagInfo {
			parseTCPInfo(payload, s)
		}
		step := (alen + 3) &^ 3 // NLA_ALIGN
		if step <= 0 || step > len(b) {
			return
		}
		b = b[step:]
	}
}

// tcp_info field offsets. The struct is append-only across kernel versions, so
// reading by offset with a length guard is forward- and backward-compatible:
// an old kernel simply returns a shorter blob and the newer fields stay zero.
const (
	tiCAState      = 1
	tiRetransmits  = 2
	tiUnacked      = 24
	tiLost         = 32
	tiRTT          = 68
	tiSndCwnd      = 80
	tiTotalRetrans = 100
	tiBytesAcked   = 120
	tiBytesRecv    = 128
	tiSegsOut      = 136
	tiSegsIn       = 140
	tiNotSent      = 144
	tiMinRTT       = 148
)

func parseTCPInfo(b []byte, s *rawSock) {
	u32 := func(off int) uint32 {
		if off+4 <= len(b) {
			return nativeEndian.Uint32(b[off : off+4])
		}
		return 0
	}
	u64 := func(off int) uint64 {
		if off+8 <= len(b) {
			return nativeEndian.Uint64(b[off : off+8])
		}
		return 0
	}
	s.HasInfo = true
	if len(b) > tiRetransmits {
		s.CAState = b[tiCAState]
		s.Retransmits = b[tiRetransmits]
	}
	s.Unacked = u32(tiUnacked)
	s.Lost = u32(tiLost)
	s.RTTUs = u32(tiRTT)
	s.SndCwnd = u32(tiSndCwnd)
	s.TotalRetrans = u32(tiTotalRetrans)
	s.BytesAcked = u64(tiBytesAcked)
	s.BytesRecv = u64(tiBytesRecv)
	s.SegsOut = u32(tiSegsOut)
	s.SegsIn = u32(tiSegsIn)
	s.NotSent = u32(tiNotSent)
	s.MinRTTUs = u32(tiMinRTT)
}

// protoTCP / protoUDP name the IP protocols we dump.
const (
	protoTCP = syscall.IPPROTO_TCP
	protoUDP = syscall.IPPROTO_UDP
)

// netlinkAvailable reports whether sock_diag works here at all (it is compiled
// out of some hardened kernels, and containers can block it).
func netlinkAvailable() error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_INET_DIAG)
	if err != nil {
		return err
	}
	return syscall.Close(fd)
}
