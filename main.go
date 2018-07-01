package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"flag"
	// "io"
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

const (
	TYPE_DATA = iota + 1
	TYPE_CTRL
	TYPE_PING
	TYPE_KEYX
)

func doSendData(iface *water.Interface, conn net.Conn, encrypt cipher.Stream) {
	buf := make([]byte, 10*1024)

	if_r := bufio.NewReader(iface)
	conn_w := bufio.NewWriter(conn)

	for {
		n, err := if_r.Read(buf)
		if err != nil {
			log.Fatal(err)
		}

		// log.Println("Read", n, "bytes from tun interface")

		if buf[0]&0xF0 != 0x40 {
			// log.Println("Ignoring non-ipv4 packet")
			continue
		}

		pkt := make([]byte, n+1)
		pkt[0] = TYPE_DATA
		copy(pkt[1:], buf[:n])
		encrypt.XORKeyStream(pkt, pkt)

		conn_w.Write(pkt)
		conn_w.Flush()
	}
}

func doRecieveData(iface *water.Interface, conn net.Conn, decrypt cipher.Stream) {
	buf := make([]byte, 10*1024)

	conn_r := bufio.NewReader(conn)
	if_w := bufio.NewWriter(iface)

	for {
		n, err := conn_r.Read(buf)
		if err != nil {
			log.Fatal(err)
		}

		pkt := buf[:n]
		decrypt.XORKeyStream(pkt, pkt)

		switch pkt[0] {
		case TYPE_DATA:
			if_w.Write(pkt[1:])
			if_w.Flush()
		case TYPE_CTRL:
			log.Println(string(buf[1:n]))
		case TYPE_PING:
			// do nothing
		default:
			log.Println("Unknown packet type:", pkt[0])
		}
	}
}

/* func doRoatateKeys(conn net.Conn) {
	// do magic
} */

func runTunnelEncap(key []byte, encrypt bool, iface *water.Interface, conn net.Conn) {
	var stop_exit chan int

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	var iv [aes.BlockSize]byte

	enc_stream := cipher.NewCFBEncrypter(block, iv[:])
	dec_stream := cipher.NewCFBDecrypter(block, iv[:])

	go doSendData(iface, conn, enc_stream)
	go doRecieveData(iface, conn, dec_stream)
	// go doRotateKeys(conn)

	<-stop_exit
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
		err   error
	)

	if *server && *remote != "" {
		log.Fatal("If running as a server, remote must not be specified")
	}

	remote_s := (*remote + ":" + strconv.Itoa(*port))

	hexkey := "fa76b62c6ca79481ea747aefd80f98ddc896e8d9d68ff7aebbe4d54d448e85ec"
	key, err := hex.DecodeString(hexkey)
	if err != nil {
		log.Fatal(err)
	}

	if *server {
		log.Println("Waiting for connection on port tcp", remote_s)
		ln, err := net.Listen("tcp", remote_s)
		if err != nil {
			log.Fatal(err)
		}
		conn, err = ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Println("Connecting to", remote_s)
		conn, err = net.Dial("tcp", remote_s)
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Println("Tunnel running!")
	runTunnelEncap(key, true, iface, conn)
}
