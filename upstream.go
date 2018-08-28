package h2s

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
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
			conn, err = s.dialer.Dial("tcp", u.address)
			if err == nil {
				return
			}
		}

		tlsConn, terr := tls.DialWithDialer(s.dialer, "tcp", u.address, u.tlsConfig)
		if terr != nil {
			err = terr
			continue
		}
		if u.tlsFingerprint != nil {
			certs := tlsConn.ConnectionState().PeerCertificates
			if len(certs) < 1 {
				err = errors.New("the server gives no cert")
				continue
			}

			fin := sha256.Sum256(certs[0].Raw)
			if !hmac.Equal(fin[:], u.tlsFingerprint) {
				err = errors.New("fingerprint not matched")
				continue
			}
		}

		conn = tlsConn
		return
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
