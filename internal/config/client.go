package config

import (
	"crypto/tls"
	"strings"
)

func (c Client) ToTLSConfig() (*tls.Config, error) {
	tc := tls.Config{
		InsecureSkipVerify: true,
	}

	var err error
	if c.MinTLSVersion != "" {
		tc.MinVersion, err = parseTLSVersion(c.MinTLSVersion)
		if err != nil {
			return nil, err
		}
	}

	if c.MaxTLSVersion != "" {
		tc.MaxVersion, err = parseTLSVersion(c.MaxTLSVersion)
		if err != nil {
			return nil, err
		}
	}

	if c.CipherSuites != nil {
		for _, cs := range strings.Split(*c.CipherSuites, ",") {
			suite, err := parseCipherSuite(cs)
			if err != nil {
				return nil, err
			}
			tc.CipherSuites = append(tc.CipherSuites, suite.ID)
		}
	}

	return &tc, nil
}
