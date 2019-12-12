package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"time"
)

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type UDPSession struct {
	remote net.UDPAddr
	demux  *UDPDemux
	queue  chan []byte
}

func (u *UDPSession) Write(data []byte) (int, error) {
	n, err := u.demux.Connection.WriteTo(data, &u.remote)
	return n, err
}

func (u *UDPSession) Read(data []byte) (int, error) {
	next := <-u.queue
	copy(data, next)
	return min(len(data), len(next)), nil
}

func (u *UDPSession) Close() error {
	delete(u.demux.Sessions, u.remote.String())
	return nil
}

func (u *UDPSession) LocalAddr() net.Addr {
	return u.demux.Connection.LocalAddr()
}

func (u *UDPSession) RemoteAddr() net.Addr {
	return &u.remote
}

func (u *UDPSession) SetDeadline(t time.Time) error      { return nil }
func (u *UDPSession) SetReadDeadline(t time.Time) error  { return nil }
func (u *UDPSession) SetWriteDeadline(t time.Time) error { return nil }

type UDPDemux struct {
	Sessions    map[string]*UDPSession
	Connection  *net.UDPConn
	acceptQueue chan *UDPSession
}

func (u *UDPDemux) Accept() (net.Conn, error) {
	// block until new remote address seen
	return <-u.acceptQueue, nil
}

func (u *UDPDemux) Addr() net.Addr {
	return u.Connection.LocalAddr()
}

func (u *UDPDemux) PerformDemux() {
	buffer := make([]byte, 2048)
	for {
		n, addr, err := u.Connection.ReadFrom(buffer)
		if err != nil {
			// handle repeated errors?
			log.Println("udp error:", err)
			continue
		}
		dispatch := make([]byte, n)
		copy(dispatch, buffer[:n])

		_, ok := u.Sessions[addr.String()]
		if !ok {
			fmt.Println("making new session")
			new_x := &UDPSession{*addr.(*net.UDPAddr), u, make(chan []byte, 10)}
			u.Sessions[addr.String()] = new_x
			u.acceptQueue <- new_x
		}
		session := u.Sessions[addr.String()]
		session.queue <- dispatch
	}
}

func NewUDPDemux(base *net.UDPConn) UDPDemux {
	demux := UDPDemux{}
	demux.Sessions = make(map[string]*UDPSession)
	demux.Connection = base
	demux.acceptQueue = make(chan *UDPSession, 16)
	return demux
}

func UDPEcho(c net.Conn) {
	scanner := bufio.NewScanner(c)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Fprintln(c, line)
	}
}

/*
func main() {
	conn, err := net.ListenPacket("udp", "0.0.0.0:1234")
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
		go UDPEcho(c)
	}
}
*/
