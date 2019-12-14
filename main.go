package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"strconv"
	// "time"

	"github.com/songgao/water"
)

func initTun(name string, address string) *water.Interface {
	// ip, net := net.ParseCIDR(address)

	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = name

	iface, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}

	set_up := exec.Command("ip", "link", "set", name, "up")
	set_addr := exec.Command("ip", "addr", "add", address, "dev", name)

	err = set_up.Run()
	if err != nil {
		log.Fatal(err)
	}

	err = set_addr.Run()
	if err != nil {
		log.Fatal(err)
	}

	return iface
}

func rot13(destination, source []byte) {
	if len(destination) < len(source) {
		panic("rot13 with smaller destination is impossible")
	}

	rot := func(r byte) byte {
		if r >= byte('a') && r <= byte('m') || 
		   r >= byte('A') && r <= byte('M') {
			return r + 13
		} else if r >= byte('n') && r <= byte('z') || 
		   r >= byte('n') && r <= byte('Z') {
			return r - 13
		}
		return r
	}

	for i, b := range source {
		destination[i] = rot(b)
	}
}

type TunnelConnection struct {
	link  net.Conn
}

const MTU = 2000

func (t TunnelConnection) Read(data []byte) (int, error) {
	packet := make([]byte, MTU)

	n, err := t.link.Read(packet)
	if err != nil {
		return 0, err
	}

	decrypted_data := make([]byte, n)
	rot13(decrypted_data, packet[:n])

	copy(data, decrypted_data)
	return min(len(data), len(decrypted_data)), nil
}

func (t TunnelConnection) Write(data []byte) (int, error) {
	encrypted_data := make([]byte, len(data))

	rot13(encrypted_data, data)

	_, err := t.link.Write(encrypted_data)
	return len(data), err
}

func (t TunnelConnection) Close() error {
	t.link.Close()

	// flag this structure as closed?
	return nil
}

func main() {
	var (
		server = flag.Bool("server", false, "Acting as server")
		addr   = flag.String("addr", "6.0.0.2/8", "Address of the tunnel adapter")
		remote = flag.String("remote", "", "Address of server to connect to")
		port   = flag.Int("port", 8084, "Port to use for tunnel connection")
	)

	flag.Parse()

	if *server {
		log.Println("Starting tunnel as server with addr", *addr)
	} else {
		log.Println("Starting tunnel as client with addr", *addr)
	}

	var (
		iface = initTun("tunnel", *addr)
		conn  net.Conn
	)

	remote_s := *remote + ":" + strconv.Itoa(*port)

	udp, err := net.ResolveUDPAddr("udp", remote_s)
	if err != nil {
		log.Fatal(err)
	}

	if *server {
		conn, err := net.ListenPacket("udp", remote_s)
		if err != nil {
			panic(err)
		}

		udp_conn := conn.(*net.UDPConn)

		demux := NewUDPDemux(udp_conn)
		go demux.PerformDemux()

		for {
			c, err := demux.Accept()
			if err != nil {
				panic(err)
			}
			fmt.Println("Got connection from", c.RemoteAddr())

			tunnelConnection := TunnelConnection{c}

			go io.Copy(iface, tunnelConnection)
			go io.Copy(tunnelConnection, iface)
		}
	} else {
		log.Println("Connecting to", remote_s)
		conn, err = net.DialUDP("udp", nil, udp)
		if err != nil {
			log.Fatal(err)
		}
		tunnelConnection := TunnelConnection{conn}

		go io.Copy(iface, tunnelConnection)
		io.Copy(tunnelConnection, iface)
	}
}
