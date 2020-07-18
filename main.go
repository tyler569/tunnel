package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"log"
	"net"
	"os/exec"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
	"golang.org/x/crypto/scrypt"
)

var block cipher.Block
var udpSocket *net.UDPConn
var iface *water.Interface
var remotes []tunnelConnection

var anyNet net.IPNet = net.IPNet{
	net.IPv4(0, 0, 0, 0),
	net.IPv4Mask(0, 0, 0, 0),
}

func min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

func createTunAdapter(name string, address string) *water.Interface {
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = name

	iface, err := water.New(config)
	if err != nil {
		log.Fatal("Failed to create interface:", err)
	}

	setIfaceUp := exec.Command("ip", "link", "set", name, "up")
	if err = setIfaceUp.Run(); err != nil {
		log.Fatal("Failed to set tun adapter up:", err)
	}

	setIfaceAddr := exec.Command("ip", "addr", "add", address, "dev", name)
	if err = setIfaceAddr.Run(); err != nil {
		log.Fatal("Failed to set tun adapter interface:", err)
	}

	return iface
}

func randomIV() (iv []byte) {
	iv = make([]byte, 16)
	length, err := rand.Read(iv)
	if err != nil || length != 16 {
		log.Fatal("random IV generation failed", err)
	}
	return
}

func srcIP(packetData []byte) net.IP {
	if packetData[0] >> 4 != 4 {
		return nil
	}
	packet := gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Lazy)
	ip4Layer, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip4Layer == nil || !ok {
		return nil
	}
	return ip4Layer.SrcIP
}

func dstIP(packetData []byte) net.IP {
	if packetData[0] >> 4 != 4 {
		return nil
	}
	packet := gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Lazy)
	ip4Layer, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip4Layer == nil || !ok {
		return nil
	}
	return ip4Layer.DstIP
}

func (t *tunnelConnection) writePacket(data []byte, server bool) error {
	encryptedPacket := make([]byte, len(data)+16)
	iv := randomIV()
	copy(encryptedPacket, iv)

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(encryptedPacket[16:], data)

	if server {
		_, err := udpSocket.WriteToUDP(encryptedPacket, &t.remote)
		return err
	} else {
		_, err := udpSocket.Write(encryptedPacket)
		return err
	}
}

func decodePacket(encryptedPacket []byte) []byte {
	iv := make([]byte, 16)
	data := make([]byte, len(encryptedPacket)-16)
	copy(iv, encryptedPacket[:16])

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(data, encryptedPacket[16:])

	return data
}

func findRemote(ip net.IP) *tunnelConnection {
	for i := range remotes {
		if remotes[i].tunnelNet.Contains(ip) {
			return &remotes[i]
		}
	}
	return nil
}

func findRemoteByUDP(addr net.UDPAddr) *tunnelConnection {
	for i := range remotes {
		if remotes[i].remote.String() == addr.String() {
			return &remotes[i]
		}
	}
	return nil
}

func fromInterfaceLoop(server bool) {
	buffer := make([]byte, 2048)
	for {
		length, err := iface.Read(buffer)
		if err != nil {
			log.Fatal("Failed to read from interface:", err)
		}
		packet := buffer[:length]

		dst := dstIP(packet)
		remote := findRemote(dst)
		if remote == nil {
			log.Println("No remote found for tunnel address:", dst)
			log.Println("remotes:", remotes)
			continue
		}

		err = remote.writePacket(packet, server)
		if err != nil {
			log.Println("Failed to send packet to:", remote.remote, err)
			continue
		}
	}
}

func fromUDPLoop() {
	buffer := make([]byte, 2048)
	for {
		length, addr, err := udpSocket.ReadFromUDP(buffer)
		if err != nil {
			log.Fatal("Failed to read from UDP:", err)
		}
		encryptedPacket := buffer[:length]
		packet := decodePacket(encryptedPacket)
		// TODO: decode packet and forward to another client if needed
		// TODO: drop packet if no known route to destination
		remote := findRemoteByUDP(*addr)
		if remote == nil {
			src := srcIP(packet)
			if src == nil {
				// v6 probably
				continue
			}
			log.Println("new remote, ip:", src)
			remotes = append(remotes, newConnection(*addr, src))
		}
		length, err = iface.Write(packet)
		if err != nil {
			log.Fatal("Failed to write to interface:", err)
		}
	}
}

func main() {
	var (
		server = flag.Bool("server", false, "Acting as server")
		addr   = flag.String("addr", "10.254.1.2/24", "Address of the tunnel adapter")
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

	remote_s := *remote + ":" + strconv.Itoa(*port)

	udp, err := net.ResolveUDPAddr("udp", remote_s)
	if err != nil {
		log.Fatal("Failed to resolve address:", err)
	}

	iface = createTunAdapter("tunnel", *addr)

	salt := []byte("This is a salt for the tunnel scrypt initial key")
	key, err := scrypt.Key([]byte(*psk), salt, 32768, 8, 1, 32)
	if err != nil {
		log.Fatal("Failed to scrypt key:", err)
	}

	block, err = aes.NewCipher(key)
	if err != nil {
		log.Fatal("Failed to create AES cipher:", err)
	}

	if *server {
		udpSocket, err = net.ListenUDP("udp", udp)
		if err != nil {
			log.Fatal("Failed to bind to UDP port:", err)
		}
		go fromInterfaceLoop(*server)
		fromUDPLoop()
	} else {
		log.Println("Connecting to", remote_s)
		udpSocket, err = net.DialUDP("udp", nil, udp)
		if err != nil {
			log.Fatal("Failed to dial UDP outbound:", err)
		}
		remotes = append(remotes, tunnelConnection{*udp, anyNet})
		go fromInterfaceLoop(*server)
		fromUDPLoop()
	}
}
