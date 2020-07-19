package main

import (
	"net"
)

var peers []remotePeer

type remotePeer struct {
	addr      net.Addr
	tunnelNet net.IPNet
}

func addPeer(addr net.Addr, tunAddr net.IP) {
	tunNet := net.IPNet{tunAddr, net.IPv4Mask(255, 255, 255, 255)}
	peer := remotePeer{addr, tunNet}
	peers = append(peers, peer)
}

func addDefaultPeer(addr net.Addr) {
	anyNet := net.IPNet{
		net.IPv4(0, 0, 0, 0),
		net.IPv4Mask(0, 0, 0, 0),
	}
	peer := remotePeer{addr, anyNet}
	peers = append(peers, peer)
}

func findPeer(ip net.IP) *remotePeer {
	for i := range peers {
		if peers[i].tunnelNet.Contains(ip) {
			return &peers[i]
		}
	}
	return nil
}

func findPeerByAddr(addr net.Addr) *remotePeer {
	for i := range peers {
		if peers[i].addr.String() == addr.String() {
			return &peers[i]
		}
	}
	return nil
}
