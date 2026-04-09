// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package netutil

import (
	"net"
	"runtime"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// BatchConn abstracts ipv4.PacketConn and ipv6.PacketConn behind a single interface.
//
// Both ipv4.Message and ipv6.Message are type aliases for the same underlying
// golang.org/x/net/internal/socket.Message type, so []ipv4.Message is identical
// to []ipv6.Message at compile time and both PacketConn implementations satisfy
// this interface without any conversion overhead.
type BatchConn interface {
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
	WriteBatch(ms []ipv4.Message, flags int) (int, error)
}

// fallbackBatchConn is a pure-Go implementation of BatchConn for platforms that
// do not support recvmmsg/sendmmsg (e.g. Windows, macOS). It processes exactly
// one message per call, which is functionally correct if slower than the batch
// path on Linux.
type fallbackBatchConn struct {
	conn *net.UDPConn
}

// ReadBatch reads a single UDP datagram into ms[0] using the standard ReadFromUDP
// syscall and returns 1. Callers must ensure len(ms) >= 1 and that ms[0].Buffers
// contains at least one non-empty byte slice.
func (f *fallbackBatchConn) ReadBatch(ms []ipv4.Message, _ int) (int, error) {
	if len(ms) == 0 {
		return 0, nil
	}
	if len(ms[0].Buffers) == 0 {
		ms[0].Buffers = [][]byte{make([]byte, 4096)}
	}
	n, addr, err := f.conn.ReadFromUDP(ms[0].Buffers[0])
	if err != nil {
		return 0, err
	}
	ms[0].N = n
	ms[0].Addr = addr
	return 1, nil
}

// WriteBatch writes each message in ms sequentially using WriteToUDP. It returns
// the number of messages successfully written. A nil Addr is silently skipped.
func (f *fallbackBatchConn) WriteBatch(ms []ipv4.Message, _ int) (int, error) {
	written := 0
	for i := range ms {
		if ms[i].Addr == nil {
			continue
		}
		udpAddr, ok := ms[i].Addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		var buf []byte
		if len(ms[i].Buffers) > 0 {
			buf = ms[i].Buffers[0]
		}
		if len(buf) == 0 {
			continue
		}
		// ms[i].N is 0 before WriteBatch runs (callers set Buffers but not N).
		// Write the full buffer; N is updated afterwards to reflect bytes sent.
		n, err := f.conn.WriteToUDP(buf, udpAddr)
		if err != nil {
			return written, err
		}
		ms[i].N = n
		written++
	}
	return written, nil
}

// NewBatchConn wraps conn in the most capable BatchConn available for the current
// platform:
//
//   - Linux / Android: uses ipv4.PacketConn or ipv6.PacketConn (recvmmsg/sendmmsg)
//   - All other platforms: uses fallbackBatchConn (single-packet ReadFromUDP /
//     WriteToUDP). This avoids the "recvmsg: not implemented" panic on Windows
//     and macOS where golang.org/x/net does not support batch syscalls.
//
// Selection table for the Linux/Android path:
//
//	0.0.0.0 / IPv4-mapped (::ffff:x.x.x.x) → ipv4.PacketConn
//	:: / ::1 / true IPv6                    → ipv6.PacketConn
func NewBatchConn(conn *net.UDPConn) BatchConn {
	if conn == nil {
		return nil
	}

	// Platforms without recvmmsg/sendmmsg support: use the portable fallback.
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		return &fallbackBatchConn{conn: conn}
	}

	// Linux / Android: prefer the batch syscall path.
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr != nil && addr.IP != nil && addr.IP.To4() == nil {
		// Genuine IPv6 local address (including "::" dual-stack wildcard)
		return ipv6.NewPacketConn(conn)
	}
	return ipv4.NewPacketConn(conn)
}
