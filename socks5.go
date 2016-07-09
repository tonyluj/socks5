package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

var (
	errAddrType = errors.New("unsupport address type")
	errVersion  = errors.New("unsupport socks version")
	errMethod   = errors.New("unsupport method")
	errCmd      = errors.New("unsupport command")
)

const (
	bufferSize = 4096

	methodNoAuth           = 0x00
	methodUsernamePassword = 0x02

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

type Server struct {
	addr    *net.TCPAddr
	pool    sync.Pool
	timeout time.Duration
	logger  *log.Logger
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

func (s *Server) Listen() (err error) {
	ln, err := net.ListenTCP("tcp", s.addr)
	if err != nil {
		return
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}

		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(s.timeout))

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
	rconn, err := net.DialTimeout("tcp", addr, s.timeout)
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
	defer rconn.Close()
	rconn.SetDeadline(time.Now().Add(s.timeout))

	// reply success
	err = s.reply(conn, repSucceed)
	if err != nil {
		s.logger.Println("reply", err)
		return
	}

	// connect and transfer data
	s.connect(rconn, conn)
}

// handShake is used for check version
func (s *Server) handShake(conn net.Conn) (err error) {
	b := s.pool.Get().([]byte)
	defer s.pool.Put(b)
	// version 1, nmethod 1, methods 255
	buf := b[:257]

	// read at least 2 bytes (version and auth method)
	_, err = io.ReadAtLeast(conn, buf, 2)
	if err != nil {
		return
	}
	// check socks version
	if buf[0] != version5 {
		s.logger.Println("handShake error", err, buf[0])
		err = errVersion
		return
	}

	// check method
	switch buf[1] {
	case methodNoAuth:
	default:
		//err = errMethod
		//return
	}

	// only support NO AUTH method
	_, err = conn.Write([]byte{version5, methodNoAuth})
	return
}

// handle request, get address
func (s *Server) request(conn net.Conn) (host string, err error) {
	b := s.pool.Get().([]byte)
	defer s.pool.Put(b)
	// version 1, cmd 1, rsv 1, atyp 1, addr max domain length is 253, port 2
	buf := b[:258]

	// read at least fetch ipv4
	_, err = io.ReadAtLeast(conn, buf, 10)
	if err != nil {
		return
	}
	// check version
	if buf[0] != version5 {
		s.logger.Println("request error", err)
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
	case atypIPV4:
		// ipv4 start from 4, and ipv4 length is 4, port start from 8, total length is 10
		dstAddr = net.IP(buf[4 : 4+4]).String()
		dstPort = int(binary.BigEndian.Uint16(buf[8:10]))
	case atypIPV6:
		// ipv6 start from 4, and ipv6 lenght is 16, port start from 20, total length is 22
		dstAddr = net.IP(buf[4 : 4+16]).String()
		dstPort = int(binary.BigEndian.Uint16(buf[20:22]))
	case atypDomain:
		// domain length is 4, start from 5, total length is domain length + 7
		dstAddrLen := buf[4]
		_, err = io.ReadFull(conn, buf[10:dstAddrLen+7])
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

func (s *Server) reply(conn net.Conn, rep byte) (err error) {
	// version 1, rep 1, rsv 1, atyp 1, addr 4 or 16(ipv4 or ipv6), port 2
	rb := make([]byte, 10)
	// TODO: support ipv6
	copy(rb[0:4], []byte{version5, rep, rsv, atypIPV4})
	// TODO ip empty
	copy(rb[4:8], []byte{0x00, 0x00, 0x00, 0x00})
	binary.BigEndian.PutUint16(rb[8:10], uint16(s.addr.Port))
	_, err = conn.Write(rb)
	if err != nil {
		return
	}
	return
}

func (s *Server) connect(dst, src net.Conn) (err error) {
	errChan := make(chan error, 1)
	wg := sync.WaitGroup{}
	wg.Add(2)
	// read from src, write to remote
	go func() {
		defer func() {
			wg.Done()
		}()

		b := s.pool.Get().([]byte)
		for {
			select {
			case <-errChan:
				dst.Write([]byte{0})
				s.pool.Put(b)
				return
			default:
				n, err := src.Read(b)
				if n > 0 {
					dst.Write(b[:n])
				}

				if err != nil {
					errChan <- err
					continue
				}
			}
		}
	}()

	// read from remote, write to src
	go func() {
		defer func() {
			wg.Done()
		}()

		b := s.pool.Get().([]byte)
		for {
			select {
			case <-errChan:
				src.Write([]byte{0})
				s.pool.Put(b)
				return
			default:
				n, err := dst.Read(b)
				if n > 0 {
					src.Write(b[:n])
				}

				if err != nil {
					errChan <- err
					continue
				}
			}
		}
	}()

	wg.Wait()
	return
}
