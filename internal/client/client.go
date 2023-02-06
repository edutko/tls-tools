package client

import (
	"crypto/tls"
	"crypto/x509"
	"net"

	"tls-cert-tools/internal/config"
	"tls-cert-tools/internal/pki"
)

func NewClientFromConfig(cfg config.Config) (*Client, error) {
	store, err := pki.NewStoreFromConfig(cfg.Certs)
	if err != nil {
		return nil, err
	}

	addr := cfg.Clients[0].Addr
	_, port, _ := net.SplitHostPort(addr)
	if port == "" {
		addr = net.JoinHostPort(addr, "443")
	}

	tc, err := cfg.Clients[0].ToTLSConfig()
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
