// Package h2s provides a tool that wraps one or multiple HTTP or HTTPS proxies
// into a SOCKS5 proxy. It does something like polipo and privoxy do,
// but in a reversed way.
package h2s // import "ekyu.moe/h2s"

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Upstream is a HTTPS proxy upstream that must support CONNECT method as defined
// in RFC 7231 section 4.3.6.
type Upstream struct {
	Address  string `json:"address"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// TLSConfig can be null.
	TLSConfig *TLSConfig `json:"tlsConfig"`
}

// TLSConfig is a simplified version of tls.Config
type TLSConfig struct {
	// If empty, ServerName is set to the hostname from Address.
	// This is useful in some cases, for example a server behind Cloudflare,
	// since Cloudflare would simply reject CONNECT method.
	ServerName string `json:"serverName"`

	// If you prefer to set a fingerprint instead of providing certs, you can
	// set this to true.
	//
	// Do not set to true unless you know what you are doing.
	InsecureSkipVerify bool `json:"insecureSkipVerify"`
	// Server's SHA256 fingerprint, used to verify as an alternative to providing
	// the whole server certs.
	SHA256Fingerprint string `json:"sha256Fingerprint"`

	// For self-signed certs. Be careful.
	RootCA string `json:"rootCA"`

	// For client auth.
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// Account is used for SOCKS5 authentication.
type Account struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Config is used to configure an h2s Server.
type Config struct {
	// HTTP proxy upstreams.
	Upstreams []*Upstream `json:"upstreams"`

	// With no Accounts, authentication is disabled.
	Accounts []*Account `json:"accounts,omitempty"`

	// Timeout value when dialing to a upstream. Default "20s".
	Timeout string `json:"timeout"`

	// The max retries count of dialing to upstreams. Default 3.
	Retries *int `json:"retries"`
}

type internalUpstream struct {
	address   string
	header    http.Header
	tlsConfig *tls.Config
}

type internalAccount struct {
	username []byte
	password []byte
}

// Server is a SOCKS5 server that forward all incoming requests via Upstreams
// by HTTP/1.1 CONNECT.
type Server struct {
	next        chan *internalUpstream
	stop        chan struct{}
	requireAuth bool
	account     []*internalAccount
	retries     int
	dialer      *net.Dialer

	isClosed bool
	mu       sync.Mutex
}

// I know, I know
func basicauth(username, password string) http.Header {
	h := http.Header{}
	h.Set("User-Agent", "")
	if username != "" && password != "" {
		combined := username + ":" + password
		encoded := base64.StdEncoding.EncodeToString([]byte(combined))
		h.Set("Proxy-Authorization", "Basic "+encoded)
	}

	return h
}

// NewServer creates an h2s server instance.
func NewServer(c *Config) (*Server, error) {
	s := &Server{}

	if c.Timeout != "" {
		timeout, err := time.ParseDuration(c.Timeout)
		if err != nil {
			return nil, errors.New("parse timeout: " + err.Error())
		}
		s.dialer = &net.Dialer{Timeout: timeout}
	} else {
		s.dialer = &net.Dialer{Timeout: 20 * time.Second}
	}

	if c.Retries != nil {
		s.retries = *c.Retries
	} else {
		s.retries = 3
	}

	s.requireAuth = len(c.Accounts) > 0
	if s.requireAuth {
		s.account = make([]*internalAccount, len(c.Accounts))
		for i, v := range c.Accounts {
			s.account[i] = &internalAccount{
				username: []byte(v.Username),
				password: []byte(v.Password),
			}
		}
	}

	if len(c.Upstreams) == 0 {
		return nil, errors.New("no upstreams")
	}

	upstreams := make([]*internalUpstream, len(c.Upstreams))
	for i, v := range c.Upstreams {
		addr := v.Address
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			addr += ":80"
			host, port, err = net.SplitHostPort(addr)
			if err != nil {
				return nil, errors.New("invalid address " + v.Address)
			}
		}
		addr = net.JoinHostPort(host, port)

		tlsConfig := (*tls.Config)(nil)
		if t := v.TLSConfig; t != nil {
			tlsConfig = &tls.Config{
				NextProtos: []string{"http/1.1"},
			}

			if t.ServerName != "" {
				tlsConfig.ServerName = t.ServerName
			} else {
				u, err := url.Parse(v.Address)
				if err != nil {
					return nil, errors.New("tls: parse server name: " + err.Error())
				}
				tlsConfig.ServerName = u.Hostname()
			}

			tlsConfig.InsecureSkipVerify = t.InsecureSkipVerify
			if t.SHA256Fingerprint != "" {
				fin, err := hex.DecodeString(t.SHA256Fingerprint)
				if err != nil {
					return nil, errors.New("tls: failed to parse fingerprint")
				}
				if len(fin) != 32 {
					return nil, errors.New("tls: fingerprint: wrong length, not like a sha256 digest")
				}

				tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					if len(rawCerts) < 1 {
						return errors.New("server provides no cert")
					}

					sum := sha256.Sum256(rawCerts[0])
					if !hmac.Equal(sum[:], fin) {
						return errors.New("wrong fingerprint")
					}

					return nil
				}
			}

			if t.RootCA != "" {
				certPool := x509.NewCertPool()
				pem, err := ioutil.ReadFile(t.RootCA)
				if err != nil {
					return nil, errors.New("tls: read rootCAs: " + err.Error())
				}
				if !certPool.AppendCertsFromPEM(pem) {
					return nil, errors.New("tls: failed to load rootCAs")
				}
				tlsConfig.RootCAs = certPool
			}

			if t.CertFile != "" && t.KeyFile != "" {
				cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
				if err != nil {
					return nil, errors.New("tls: load key pair: " + err.Error())
				}
				tlsConfig.Certificates = []tls.Certificate{cert}
			}
		}

		upstreams[i] = &internalUpstream{
			address:   addr,
			header:    basicauth(v.Username, v.Password),
			tlsConfig: tlsConfig,
		}
	}

	s.next = make(chan *internalUpstream)
	s.stop = make(chan struct{})
	go func() {
		// simple round-robin
		for {
			for _, v := range upstreams {
				select {
				case s.next <- v:
				case <-s.stop:
					close(s.next)
					return
				}
			}
		}
	}()

	return s, nil
}

// Close closes s. Already established connections will not be affected.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.isClosed {
		return errors.New("server is already closed")
	}
	s.stop <- struct{}{}
	s.isClosed = true
	s.mu.Unlock()

	return nil
}

// Serve handles a net.Conn, reads request from it with SOCKS5 format, and dispatch
// the request via HTTP CONNECT. Serve closes conn whether an error occurs or
// connection is done. The caller must not use conn again.
func (s *Server) Serve(conn net.Conn) error {
	defer conn.Close()

	// this is bad
	s.mu.Lock()
	isClosed := s.isClosed
	s.mu.Unlock()
	if isClosed {
		return errors.New("server is closed")
	}

	if err := s.handshake(conn); err != nil {
		return errors.New("handshake: " + err.Error())
	}

	target, err := s.readRequest(conn)
	if err != nil {
		return errors.New("read request: " + err.Error())
	}

	out, u, err := s.dialUpstream()
	if err != nil {
		return errors.New("dial upstream: " + err.Error())
	}
	defer out.Close()

	if err := s.handshakeUpstream(out, u, target); err != nil {
		return errors.New("handshake upstream: " + err.Error())
	}

	// sync
	duplexPipe(out, conn)

	return nil
}
