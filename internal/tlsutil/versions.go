package tlsutil

import (
	"crypto/tls"
	"fmt"
)

var SslTlsVersions = []uint16{
	0x0200, 0x0300, tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13,
}

func TLSVersionString(v uint16) string {
	switch v {
	case 0x0200:
		return "SSL 2.0"
	case 0x0300:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown TLS version (0x%04x)", v)
	}
}
