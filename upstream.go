package h2s

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
)

func (s *Server) dialUpstream() (conn net.Conn, u *internalUpstream, err error) {
	ok := false
	for tried := 0; tried <= s.retries; tried++ {
		u, ok = <-s.next
		if !ok {
			err = errors.New("h2s is already closed")
			return
		}

		if u.tlsConfig == nil {
			conn, err = tls.DialWithDialer(s.dialer, "tcp", u.address, u.tlsConfig)
		} else {
			conn, err = s.dialer.Dial("tcp", u.address)
		}

		if err == nil {
			return
		}
	}
	err = errors.New("max retry exceeded: " + err.Error())

	return
}

func (s *Server) handshakeUpstream(conn net.Conn, u *internalUpstream, target string) error {
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: u.header,
	}

	if err := req.Write(conn); err != nil {
		return err
	}

	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return err
	}

	if res.StatusCode != 200 {
		return errors.New(res.Status)
	}

	return nil
}
