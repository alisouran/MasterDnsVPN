// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package netutil

import (
	"net"

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

// NewBatchConn wraps conn in ipv4.PacketConn or ipv6.PacketConn based on the
// local address family of the connection. Falls back to ipv4 when the address
// is ambiguous or nil.
//
// Selection table:
//
//	0.0.0.0 / IPv4-mapped (::ffff:x.x.x.x) → ipv4.PacketConn
//	:: / ::1 / true IPv6                    → ipv6.PacketConn
func NewBatchConn(conn *net.UDPConn) BatchConn {
	if conn == nil {
		return nil
	}
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr != nil && addr.IP != nil && addr.IP.To4() == nil {
		// Genuine IPv6 local address (including "::" dual-stack wildcard)
		return ipv6.NewPacketConn(conn)
	}
	return ipv4.NewPacketConn(conn)
}
