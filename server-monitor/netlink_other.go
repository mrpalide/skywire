//go:build !linux

// netlink_other.go — stubs so the tool still builds (and its report/analysis
// path still runs) on macOS or Windows. sock_diag is Linux-only; on any other
// OS the socket collector is simply disabled and the report says so.
package main

import (
	"errors"
	"net"
)

const (
	protoTCP = 6
	protoUDP = 17
)

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

	HasInfo      bool
	CAState      uint8
	Retransmits  uint8
	RTTUs        uint32
	MinRTTUs     uint32
	SndCwnd      uint32
	Unacked      uint32
	Lost         uint32
	TotalRetrans uint32
	BytesAcked   uint64
	BytesRecv    uint64
	SegsOut      uint32
	SegsIn       uint32
	NotSent      uint32
}

type sockKey struct {
	Inode  uint32
	Cookie uint64
}

func (s rawSock) key() sockKey { return sockKey{Inode: s.Inode, Cookie: s.Cookie} }

var errNotLinux = errors.New("socket statistics require Linux (sock_diag/NETLINK_INET_DIAG)")

func dumpSockets(uint8) ([]rawSock, error) { return nil, errNotLinux }

func netlinkAvailable() error { return errNotLinux }
