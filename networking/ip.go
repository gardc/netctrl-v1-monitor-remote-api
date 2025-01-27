package networking

import (
	"encoding/binary"
	"net"
)

// IPs is a simple and not very good method for getting all IPv4 addresses from a
// net.IPNet.  It returns all TargetIPs it can over the channel it sends back, closing
// the channel when done.
func IPs(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	num &= mask
	for mask < 0xffffffff {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], num)
		out = append(out, net.IP(buf[:]))
		mask++
		num++
	}
	return
}
