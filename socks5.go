package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

var (
	errExtraData = errors.New("get extra data")
	errAddrType  = errors.New("unsupported address type")
	errVersion   = errors.New("unsupported socks version")
	errMethod    = errors.New("unsupported method")
	errCmd       = errors.New("unsupported command")
)

const (
	bufferSize = 4096

	methodNoAuth           = 0x00
	methodUsernamePassword = 0x02
	methodNoAcceptable     = 0xff

	version5 = 0x05

	cmdConnect   = 0x01
	cmdBind      = 0x02
	cmdAssociate = 0x03

	atypIPV4   = 0x01
	atypDomain = 0x03
	atypIPV6   = 0x04

	repSucceed                 = 0x00
	repGeneralFailer           = 0x01
	repNotAllowed              = 0x02
	repNetworkUnreadchable     = 0x03
	repHostUnreadchable        = 0x04
	repConnectionRefused       = 0x05
	repTTLExpired              = 0x06
	repCommandNotSupport       = 0x07
	repAddressTypeNotSupported = 0x08

	rsv = 0x00
)

type TimeoutDialer func(network, address string, timeout time.Duration) (net.Conn, error)

type Server struct {
	addr    *net.TCPAddr
	pool    sync.Pool
	timeout time.Duration
	logger  *log.Logger
	td      TimeoutDialer
}

func New(addr string, timeout time.Duration) (server *Server, err error) {
	ad, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return
	}

	server = &Server{
		addr: ad,
		pool: sync.Pool{
			New: func() interface{} { return make([]byte, bufferSize) },
		},
		timeout: timeout,
		logger:  log.New(os.Stderr, "", log.LstdFlags),
	}
	return
}

func (s *Server) SetTimeoutDialer(td TimeoutDialer) {
	s.td = td
}

func (s *Server) Listen() (err error) {
	ln, err := net.ListenTCP("tcp", s.addr)
	if err != nil {
		return
	}

	if s.td == nil {
		s.td = net.DialTimeout
	}

	var tempDelay time.Duration
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}

				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}

				time.Sleep(tempDelay)
				continue
			}
			return err
		}

		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	//defer conn.Close()
	defer func() {
		fmt.Println("close conn", conn.RemoteAddr())
		conn.Close()
	}()
	//conn.SetReadDeadline(time.Now())

	// check version and nmethod
	err := s.handShake(conn)
	if err != nil {
		s.logger.Println("handShake", err)
		return
	}

	// get request cmd and addr
	addr, err := s.request(conn)
	if err != nil {
		s.logger.Println("request", err)
		return
	}

	// try to connect
	rconn, err := s.td("tcp", addr, s.timeout)
	if err != nil {
		s.logger.Println("dial", err)

		// reply error
		err = s.reply(conn, repHostUnreadchable)
		if err != nil {
			s.logger.Println("reply", err)
			return
		}
		return
	}
	//defer rconn.Close()
	defer func() {
		fmt.Println("close rconn", rconn.RemoteAddr())
		rconn.Close()
	}()
	//rconn.SetDeadline(time.Now().Add(s.timeout))

	// reply success
	err = s.reply(conn, repSucceed)
	if err != nil {
		s.logger.Println("reply", err)
		return
	}

	// connect and transfer data
	err = s.connect(rconn, conn)
	if err != nil {
		s.logger.Println("copy", err)
		return
	}
}

// handShake is used for check version
func (s *Server) handShake(conn net.Conn) (err error) {
	// version 1, nmethod 1, methods 255
	buf := s.pool.Get().([]byte)
	defer s.pool.Put(buf)

	// read at least 2 bytes (version and auth method)
	n, err := io.ReadAtLeast(conn, buf, 2)
	if err != nil {
		return
	}

	// check socks version
	if buf[0] != version5 {
		err = errVersion
		return
	}

	ml := int(buf[1]) + 2
	switch {
	case n == ml: // already read all
	case n < ml: // no more
		_, err = io.ReadFull(conn, buf[n:ml])
		if err != nil {
			return
		}
	default:
		err = errExtraData
		return
	}

	// TODO: check method no auth method list

	// TODO: reuse []byte
	// only support NO AUTH method
	buf[1] = methodNoAuth
	_, err = conn.Write(buf[:2])
	if err != nil {
		return
	}
	return
}

// handle request, get address
func (s *Server) request(conn net.Conn) (host string, err error) {
	// version 1, cmd 1, rsv 1, atyp 1, addr max domain length is 253, port 2
	buf := s.pool.Get().([]byte)
	defer s.pool.Put(buf)

	// read at least fetch ipv4
	n, err := io.ReadAtLeast(conn, buf, 10)
	if err != nil {
		return
	}
	// check version
	if buf[0] != version5 {
		err = errVersion
		return
	}
	// check cmd, support connect only
	switch buf[1] {
	case cmdConnect:
	default:
		err = errCmd
		return
	}

	// address type
	var (
		dstAddr string
		dstPort int
	)
	switch buf[3] {
	case atypIPV4: // alread read all
		// TODO: BigEndian
		// ipv4 start from 4, and ipv4 length is 4, port start from 8, total length is 10
		dstAddr = net.IP(buf[4 : 4+4]).String()
		dstPort = int(binary.BigEndian.Uint16(buf[8:10]))
	case atypIPV6: // read rest
		_, err = io.ReadFull(conn, buf[n:22])
		if err != nil {
			return
		}
		// ipv6 start from 4, and ipv6 lenght is 16, port start from 20, total length is 22
		dstAddr = net.IP(buf[4 : 4+16]).String()
		dstPort = int(binary.BigEndian.Uint16(buf[20:22]))
	case atypDomain: // read rest
		// domain length is 4, start from 5, total length is domain length + 7
		dstAddrLen := buf[4]
		_, err = io.ReadFull(conn, buf[n:dstAddrLen+7])
		if err != nil {
			return
		}
		dstAddr = string(buf[5 : 5+dstAddrLen])
		dstPort = int(binary.BigEndian.Uint16(buf[5+dstAddrLen : 7+dstAddrLen]))
	default:
		err = errAddrType
		return
	}
	host = net.JoinHostPort(dstAddr, strconv.Itoa(dstPort))
	return
}

// TODO
func (s *Server) reply(conn net.Conn, rep byte) (err error) {
	// version 1, rep 1, rsv 1, atyp 1, addr 4 or 16(ipv4 or ipv6), port 2
	buf := s.pool.Get().([]byte)
	defer s.pool.Put(buf)

	// TODO: support ipv6
	copy(buf[0:4], []byte{version5, rep, rsv, atypIPV4})
	// TODO ip empty
	copy(buf[4:8], []byte{0x00, 0x00, 0x00, 0x00})
	binary.BigEndian.PutUint16(buf[8:10], uint16(s.addr.Port))
	_, err = conn.Write(buf[:10])
	if err != nil {
		return
	}
	return
}

// connect transfer data between src and remote
// 1. client open, remote open: if occur any error, close both
// 2. client close, remote open: close remote
// 3. client open, remote close: read remote data and write to client, then close client
// 4. client close, remote close: rare condition
func (s *Server) connect(dst, src net.Conn) (err error) {
	errChan := make(chan error, 2)
	// read from src, write to remote
	go func() {
		_, err := s.copy(dst, src)
		errChan <- err
	}()

	// read from remote, write to src
	go func() {
		_, err := s.copy(src, dst)
		errChan <- err
	}()

	select {
	case err = <-errChan:
	}
	return
}

// copy data from src to dst
func (s *Server) copy(dst, src net.Conn) (writen int64, err error) {
	buf := s.pool.Get().([]byte)
	defer s.pool.Put(buf)

	for {
		// src will timeout
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				writen += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			//err = er
			break
		}
	}
	return
}
