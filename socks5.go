package h2s

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
)

var (
	handshakeBufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 1+1+255)
		},
	}
	authBufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 1+1+255+1+255)
		},
	}
	reqBufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 1+1+1+1+255+2)
		},
	}
)

const (
	socksVersion      byte = 0x05
	socksNoAuth       byte = 0x00
	socksAuthUserpass byte = 0x02
	socksNoMethod     byte = 0xff
)

// As per RFC 1928
//
//     +----+----------+----------+
//     |VER | NMETHODS | METHODS  |
//     +----+----------+----------+
//     | 1  |    1     | 1 to 255 |
//     +----+----------+----------+
func (s *Server) handshake(conn io.ReadWriter) (err error) {
	buf := handshakeBufPool.Get().([]byte)
	defer handshakeBufPool.Put(buf)

	// VER + NMETHODS
	_, err = io.ReadFull(conn, buf[:2])
	if err != nil {
		return
	}

	// VER
	if buf[0] != socksVersion {
		return fmt.Errorf("unexpected SOCKS version 0x%02x", buf[0])
	}

	// NMETHODS
	nmethods := int(buf[1])

	// METHODS
	methods := buf[2 : 2+nmethods]
	_, err = io.ReadFull(conn, methods)
	if err != nil {
		return
	}

	targetMethod := socksAuthUserpass
	if !s.requireAuth {
		targetMethod = socksNoAuth
	}

	found := false
	for _, v := range methods {
		if v == targetMethod {
			found = true
			break
		}
	}

	if !found {
		conn.Write([]byte{socksVersion, socksNoMethod})
		return errors.New("no acceptable auth method")
	}
	_, err = conn.Write([]byte{socksVersion, targetMethod})
	if err != nil {
		return
	}

	// authentication
	if s.requireAuth {
		return s.auth(conn)
	}

	return
}

const (
	socksAuthVersion byte = 0x01
	socksAuthSuccess byte = 0x00
	socksAuthFail    byte = 0x01
)

// As per RFC 1929
//
//     +----+------+----------+------+----------+
//     |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//     +----+------+----------+------+----------+
//     | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
//     +----+------+----------+------+----------+
func (s *Server) auth(conn io.ReadWriter) (err error) {
	buf := authBufPool.Get().([]byte)
	defer authBufPool.Put(buf)

	// VER + ULEN
	_, err = io.ReadFull(conn, buf[:2])
	if err != nil {
		return
	}

	if buf[0] != socksAuthVersion {
		return fmt.Errorf("unexpected SOCKS authentication VER 0x%02x", buf[0])
	}

	// UNAME + PLEN
	usernameLen := int(buf[1])
	_, err = io.ReadFull(conn, buf[2:2+usernameLen+1])
	if err != nil {
		return
	}
	passwordLen := int(buf[2+usernameLen])

	// PASSWD
	_, err = io.ReadFull(conn, buf[2+usernameLen+1:2+usernameLen+1+passwordLen])
	if err != nil {
		return
	}

	// assume big endian
	username := buf[2 : 2+usernameLen]
	password := buf[2+usernameLen+1 : 2+usernameLen+1+passwordLen]

	found := false
	for _, v := range s.account {
		if hmac.Equal(v.username, username) {
			if hmac.Equal(v.password, password) {
				found = true
				break
			}
		}
	}

	if !found {
		conn.Write([]byte{socksAuthVersion, socksAuthFail})
		return errors.New("authentication failed")
	}
	_, err = conn.Write([]byte{socksAuthVersion, socksAuthSuccess})

	return
}

const (
	socksConnect        byte = 0x01
	socksUnsupportedCmd byte = 0x07
	socksAddrIpv4       byte = 0x01
	socksAddrDomain     byte = 0x03
	socksAddrIpv6       byte = 0x04
)

// As per RFC 1928
//
//     +----+-----+-------+------+----------+----------+
//     |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//     +----+-----+-------+------+----------+----------+
//     | 1  |  1  | X'00' |  1   | Variable |    2     |
//     +----+-----+-------+------+----------+----------+
func (s *Server) readRequest(conn io.ReadWriter) (target string, err error) {
	buf := reqBufPool.Get().([]byte)
	defer reqBufPool.Put(buf)

	// VER + CMD + RSV + ATYP
	_, err = io.ReadFull(conn, buf[:4])
	if err != nil {
		return
	}

	if buf[0] != socksVersion {
		err = fmt.Errorf("unexpected SOCKS version 0x%02x", buf[0])
		return
	}

	if buf[1] != socksConnect {
		// RFC didn't define this
		_, err = conn.Write([]byte{socksVersion, socksUnsupportedCmd})
		if err != nil {
			return
		}

		err = fmt.Errorf("unexpected command 0x%02x", buf[1])
		return
	}

	// DST.ADDR + DST.PORT
	host := ""
	validLen := 0
	switch buf[3] {
	case socksAddrIpv4:
		validLen = 4 + net.IPv4len + 2
		_, err = io.ReadFull(conn, buf[4:validLen])
		if err != nil {
			return
		}
		host = net.IPv4(buf[4+0], buf[4+1], buf[4+2], buf[4+3]).String()

	case socksAddrDomain:
		_, err = io.ReadFull(conn, buf[4:5])
		if err != nil {
			return
		}
		domainLen := int(buf[4])
		validLen = 5 + domainLen + 2
		_, err = io.ReadFull(conn, buf[5:validLen])
		if err != nil {
			return
		}
		host = string(buf[5 : 5+domainLen])

	case socksAddrIpv6:
		validLen = 4 + net.IPv6len + 2
		_, err = io.ReadFull(conn, buf[4:validLen])
		if err != nil {
			return
		}
		host = net.IP(buf[4 : 4+net.IPv6len]).String()

	default:
		_, err = conn.Write([]byte{socksVersion, socksUnsupportedCmd})
		if err != nil {
			return
		}

		err = fmt.Errorf("unexpected ATYP 0x%02x", buf[3])
		return
	}
	port := int(binary.BigEndian.Uint16(buf[validLen-2 : validLen]))

	// (ノ=Д=)ノ┻━┻
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		return
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	return addr, nil
}
