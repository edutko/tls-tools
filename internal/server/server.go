package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"tls-cert-tools/internal/config"
	"tls-cert-tools/internal/pki"
)

func NewServerFromConfig(cfg config.Config) (*Server, error) {
	store, err := pki.NewStoreFromConfig(cfg.Certs)
	if err != nil {
		return nil, err
	}

	server := Server{}
	for addr, l := range cfg.Listeners {
		tc, err := l.ToTLSConfig()
		if err != nil {
			return nil, err
		}

		if len(l.Certs) == 0 {
			return nil, fmt.Errorf("no certs specified for %s", addr)
		}

		for _, name := range l.Certs {
			kac, ok := store[name]
			if !ok {
				return nil, fmt.Errorf("certificate not found: %s", name)
			}
			tc.Certificates = append(tc.Certificates, tls.Certificate{
				Certificate: kac.GetCertChainDER(),
				PrivateKey:  kac.GetPrivateKey(),
			})
		}

		server.ListenerConfigs = append(server.ListenerConfigs, ListenerConfig{
			Addr:    addr,
			TLSConf: tc,
		})
	}

	return &server, nil
}

type Server struct {
	ListenerConfigs []ListenerConfig
}

func (s *Server) Start(ctx context.Context) {
	wg := sync.WaitGroup{}
	for _, cfg := range s.ListenerConfigs {
		wg.Add(1)
		go listen(ctx, cfg, &wg)
	}
	wg.Wait()
}

func listen(ctx context.Context, cfg ListenerConfig, wg *sync.WaitGroup) {
	defer wg.Done()

	l, err := tls.Listen("tcp", cfg.Addr, cfg.TLSConf)
	if err != nil {
		log.Println(fmt.Errorf("tls.Listen: %w", err))
		return
	}

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					break
				}
				log.Println(err)
				continue
			}
			err = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if err != nil {
				log.Println(fmt.Errorf("c.SetDeadline: %w", err))
			}
			_, _ = c.Read(nil)
			err = c.Close()
			if err != nil {
				log.Println(fmt.Errorf("c.Close: %w", err))
			}
		}
	}()

	<-ctx.Done()
	err = l.Close()
	if err != nil {
		log.Println(fmt.Errorf("l.Close: %w", err))
	}
}

type ListenerConfig struct {
	Addr    string
	TLSConf *tls.Config
}
