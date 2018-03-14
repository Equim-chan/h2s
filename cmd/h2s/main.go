package main // import "ekyu.moe/h2s/cmd/h2s"

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"

	"ekyu.moe/h2s"
)

var (
	stdout = log.New(os.Stdout, "", log.Ldate|log.Lmicroseconds)
	stderr = log.New(os.Stderr, "", log.Ldate|log.Lmicroseconds)
)

type config struct {
	*h2s.Config

	Bind string `json:"bind"`
}

func main() {
	n, conf := configure()
	if n != 0 {
		os.Exit(0)
	}

	s, err := h2s.NewServer(conf.Config)
	if err != nil {
		stderr.Println(err)
		os.Exit(2)
	}
	defer s.Close()

	l, err := net.Listen("tcp", conf.Bind)
	if err != nil {
		stderr.Println("bind:", err)
		os.Exit(2)
	}
	stdout.Println("Listening on", l.Addr())

	for {
		conn, err := l.Accept()
		if err != nil {
			stderr.Println("accept:", err)
			continue
		}

		go func() {
			if err := s.Serve(conn); err != nil {
				stderr.Println(err)
			}
		}()
	}
}

func configure() (int, *config) {
	configFilename := ""
	flag.StringVar(&configFilename, "config", "h2s.json", "config file (json).")
	flag.Parse()

	f, err := os.Open(configFilename)
	if err != nil {
		stderr.Println("open config:", err)
		return 1, nil
	}
	defer f.Close()

	conf := &config{}
	if err := json.NewDecoder(f).Decode(conf); err != nil {
		stderr.Println("parse config:", err)
		return 1, nil
	}
	f.Close()

	if conf.Bind == "" {
		conf.Bind = "127.0.0.1:0"
	}

	return 0, conf
}
