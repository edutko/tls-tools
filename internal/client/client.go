package client

import (
	"crypto/tls"
	"crypto/x509"
	"net"

	"tls-tools/internal/config"
	"tls-tools/internal/pki"
)


func NewClientsFromConfig(cfg []config.Client, store pki.Store) (map[string]*Client, error) {
	clients := make(map[string]*Client, 0)

	for _, cc := range cfg {
		client, err := NewClientFromConfig(cc, store)
		if err != nil {
			return nil, err
		}
		clients[client.Addr] = client
	}

	return clients, nil
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
