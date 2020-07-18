package main

import (
	"net"
)

type tunnelConnection struct {
	remote    net.UDPAddr
	tunnelNet net.IPNet
}

func newConnection(addr net.UDPAddr, tunAddr net.IP) tunnelConnection {
	tunNet := net.IPNet{tunAddr, net.IPv4Mask(255, 255, 255, 255)}
	return tunnelConnection{addr, tunNet}
}
