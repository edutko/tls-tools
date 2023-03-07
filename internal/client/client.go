package client

import (
	"crypto/tls"
	"crypto/x509"
	"net"

	"tls-tools/internal/config"
	"tls-tools/internal/pki"
)

func NewClientPoolFromConfig(cfg config.Config) (*ClientPool, error) {
	store, err := pki.NewStoreFromConfig(cfg.Certs)
	if err != nil {
		return nil, err
	}

	pool := ClientPool{}
	for _, cc := range cfg.Clients {
		client, err := NewClientFromConfig(cc, store)
		if err != nil {
			return nil, err
		}
		pool.Clients = append(pool.Clients, client)
	}

	return &pool, nil
}

func NewClientFromConfig(cfg config.Client, store pki.Store) (*Client, error) {
	addr := cfg.Addr
	_, port, _ := net.SplitHostPort(addr)
	if port == "" {
		addr = net.JoinHostPort(addr, "443")
	}

	tc, err := cfg.ToTLSConfig()
	if err != nil {
		return nil, err
	}

	for _, kac := range store {
		if kac.IsRootCA() {
			if tc.RootCAs == nil {
				tc.RootCAs = x509.NewCertPool()
			}
			tc.RootCAs.AddCert(kac.GetCertificate())
		}
	}

	return &Client{addr, tc}, nil
}

type ClientPool struct {
	Clients []*Client
}

type Client struct {
	Addr      string
	TLSConfig *tls.Config
}

type TLSListenerInfo struct {
	Addr        string
	TLSVersion  uint16
	PeerCerts   []*x509.Certificate
	CipherSuite uint16
}

func (c *Client) GatherListenerInfo() (TLSListenerInfo, error) {
	conn, err := tls.Dial("tcp", c.Addr, c.TLSConfig)
	if err != nil {
		return TLSListenerInfo{}, err
	}

	err = conn.Handshake()
	if err != nil {
		_ = conn.Close()
		return TLSListenerInfo{}, err
	}

	cs := conn.ConnectionState()
	err = conn.Close()

	return TLSListenerInfo{
		Addr:        c.Addr,
		TLSVersion:  cs.Version,
		PeerCerts:   cs.PeerCertificates,
		CipherSuite: cs.CipherSuite,
	}, err
}
