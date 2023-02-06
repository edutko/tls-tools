package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
)

func (l Listener) ToTLSConfig() (*tls.Config, error) {
	tc := tls.Config{}

	var err error
	if l.MinTLSVersion != "" {
		tc.MinVersion, err = parseTLSVersion(l.MinTLSVersion)
		if err != nil {
			return nil, err
		}
	}

	if l.MaxTLSVersion != "" {
		tc.MaxVersion, err = parseTLSVersion(l.MaxTLSVersion)
		if err != nil {
			return nil, err
		}
	}

	if l.CipherSuites != nil {
		for _, cs := range strings.Split(*l.CipherSuites, ",") {
			suite, err := parseCipherSuite(cs)
			if err != nil {
				return nil, err
			}
			tc.CipherSuites = append(tc.CipherSuites, suite.ID)
		}
	}

	return &tc, nil
}

func parseCipherSuite(s string) (*tls.CipherSuite, error) {
	normalizedName := strings.ToUpper(strings.TrimSpace(s))
	normalizedName = strings.ReplaceAll(normalizedName, "-", "_")
	normalizedName = strings.TrimPrefix(normalizedName, "AEAD_")
	normalizedName = strings.TrimPrefix(normalizedName, "TLS_")
	normalizedName = strings.ReplaceAll(normalizedName, "WITH_", "")
	normalizedName = strings.ReplaceAll(normalizedName, "AES256_", "AES_256_")
	normalizedName = strings.ReplaceAll(normalizedName, "AES128_", "AES_128_")
	normalizedName = "TLS_" + normalizedName

	for _, cs := range cipherSuites {
		candidateName := strings.ReplaceAll(cs.Name, "WITH_", "")
		if candidateName == normalizedName {
			return cs, nil
		}
	}
	return nil, errors.New("invalid or unsupported cipher suite")
}

func parseTLSVersion(s string) (uint16, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("invalid TLS version: %s", s)
	}
}
