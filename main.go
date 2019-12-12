package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"strconv"
	// "time"

	"github.com/songgao/water"
	"golang.org/x/crypto/scrypt"
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

type TunnelConnection struct {
	link  net.Conn
	key   []byte
	block cipher.Block
}

const MTU = 2048

func (t TunnelConnection) Read(data []byte) (int, error) {
	packet := make([]byte, MTU)
	iv := packet[:aes.BlockSize]

	n, err := t.link.Read(packet)
	if err != nil {
		return 0, err
	}
	if n < aes.BlockSize+1 {
		return 0, errors.New("Packet too short")
	}

	stream := cipher.NewCTR(t.block, iv)
	decrypted_data := make([]byte, n-aes.BlockSize)
	stream.XORKeyStream(decrypted_data, packet[aes.BlockSize:n])

	copy(data, decrypted_data)
	return min(len(data), len(decrypted_data)), nil
}

func (t TunnelConnection) Write(data []byte) (int, error) {
	encrypted_data := make([]byte, len(data)+aes.BlockSize)
	iv := encrypted_data[:aes.BlockSize]

	count, err := rand.Reader.Read(iv)
	if count != aes.BlockSize || err != nil {
		return 0, err
	}

	stream := cipher.NewCTR(t.block, iv)
	stream.XORKeyStream(encrypted_data[aes.BlockSize:], data)

	_, err = t.link.Write(encrypted_data)
	return len(data), err
}

func (t TunnelConnection) Close() error {
	t.link.Close()

	// flag this structure as closed?
	return nil
}

func Connect(wr io.Writer, rd io.Reader) {
	buffer := make([]byte, MTU)
	for {
		n, err := rd.Read(buffer)
		if err != nil {
			fmt.Println(err)
			break
		}
		_, err = wr.Write(buffer[:n])
		if err != nil {
			fmt.Println(err)
			break
		}
		// fmt.Print(".")
	}
}

func main() {
	var (
		server = flag.Bool("server", false, "Acting as server")
		addr   = flag.String("addr", "6.0.0.2/8", "Address of the tunnel adapter")
		remote = flag.String("remote", "", "Address of server to connect to")
		port   = flag.Int("port", 8084, "Port to use for tunnel connection")
		psk    = flag.String("psk", "", "Pre-shard key for tunnel")
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

	salt := []byte("This is a salt for the tunnel scrypt initial key")
	key, err := scrypt.Key([]byte(*psk), salt, 32768, 8, 1, 32)
	if err != nil {
		log.Fatal(err)
	}

	block, err := aes.NewCipher(key)
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

			tunnelConnection := TunnelConnection{c, key, block}

			go Connect(iface, tunnelConnection)
			go Connect(tunnelConnection, iface)
		}
	} else {
		log.Println("Connecting to", remote_s)
		conn, err = net.DialUDP("udp", nil, udp)
		if err != nil {
			log.Fatal(err)
		}
		tunnelConnection := TunnelConnection{conn, key, block}

		go Connect(tunnelConnection, iface)
		go Connect(iface, tunnelConnection)
		c := make(chan int)
		<-c
	}
}
