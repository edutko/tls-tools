package config

import (
	"crypto/tls"
	"crypto/x509"
)

type Config struct {
	Certs     map[string]Cert     `json:"certs"`
	Clients   []Client            `json:"clients"`
	Listeners map[string]Listener `json:"listeners"`
}

const DefaultKeyType = "RSA-2048"
const DefaultPurpose = "server"

type Cert struct {
	KeyType   string   `json:"keyType"`
	Purpose   string   `json:"purpose"`
	Subject   *Subject `json:"subject"`   // default: first SAN or random strings
	Parent    string   `json:"parent"`    // default: self (self-signed)
	NotBefore string   `json:"notBefore"` // default: now
	NotAfter  string   `json:"notAfter"`  // default: now + 375 days

	// subject alternative names
	DNSNames       []string `json:"hostnames"`
	IPAddresses    []string `json:"ips"`
	EmailAddresses []string `json:"emails"`
	URIs           []string `json:"uris"`

	// advanced options
	OCSPServer            []string             `json:"ocspServer"`
	CRLDistributionPoints []string             `json:"crls"`
	CA                    bool                 `json:"ca"`
	MaxPathLen            *int                 `json:"maxPathLen"`
	SignatureAlg          string               `json:"signatureAlg"`
	KeyUsage              *string              `json:"keyUsage"`
	ExtKeyUsage           *string              `json:"extendedKeyUsage"`
	Extensions            map[string]Extension `json:"extensions"`

	// options for when you want to break things
	SerialNumber   *HexString `json:"serial"`
	SubjectKeyId   *HexString `json:"ski"`
	Issuer         *Subject   `json:"issuer"`
	AuthorityKeyId *HexString `json:"aki"`
}

type Client struct {
	Addr          string   `json:"addr"`
	Verify        bool     `json:"verify"`
	MinTLSVersion string   `json:"minTLSVersion"` // default: 1.0
	MaxTLSVersion string   `json:"maxTLSVersion"` // default: 1.3
	CipherSuites  *string  `json:"cipherSuites"`
	Certs         []string `json:"certs"`
}

type Listener struct {
	Certs         []string          `json:"certs"`
	SniOverrides  map[string]string `json:"sniOverrides"`
	MinTLSVersion string            `json:"minTLSVersion"` // default: 1.0
	MaxTLSVersion string            `json:"maxTLSVersion"` // default: 1.3
	CipherSuites  *string           `json:"cipherSuites"`
}

type Subject struct {
	C          *string           `json:"c"`
	O          *string           `json:"o"`
	OU         *string           `json:"ou"`
	L          *string           `json:"l"`
	ST         *string           `json:"st"`
	CN         *string           `json:"cn"`
	ExtraNames map[string]string `json:"extraNames"`
}

type Extension struct {
	Critical bool
	Value    string
}

var purposes = map[string]x509.Certificate{
	"root-ca": {
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	},
	"intermediate-ca": {
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	},
	"client": {
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:        false,
	},
	"server": {
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        false,
	},
}

var signatureAlgorithms = map[string]x509.SignatureAlgorithm{
	"md2withrsa":       x509.MD2WithRSA, // Unsupported.
	"md5withrsa":       x509.MD5WithRSA,
	"sha1withrsa":      x509.SHA1WithRSA,
	"sha256withrsa":    x509.SHA256WithRSA,
	"sha384withrsa":    x509.SHA384WithRSA,
	"sha512withrsa":    x509.SHA512WithRSA,
	"dsawithsha1":      x509.DSAWithSHA1,   // Unsupported.
	"dsawithsha256":    x509.DSAWithSHA256, // Unsupported.
	"ecdsawithsha1":    x509.ECDSAWithSHA1,
	"ecdsawithsha256":  x509.ECDSAWithSHA256,
	"ecdsawithsha384":  x509.ECDSAWithSHA384,
	"ecdsawithsha512":  x509.ECDSAWithSHA512,
	"sha256withrsapss": x509.SHA256WithRSAPSS,
	"sha384withrsapss": x509.SHA384WithRSAPSS,
	"sha512withrsapss": x509.SHA512WithRSAPSS,
	"ed25519":          x509.PureEd25519,
}

var keyUsages = map[string]x509.KeyUsage{
	"digitalsignature":  x509.KeyUsageDigitalSignature,
	"contentcommitment": x509.KeyUsageContentCommitment,
	"keyencipherment":   x509.KeyUsageKeyEncipherment,
	"dataencipherment":  x509.KeyUsageDataEncipherment,
	"keyagreement":      x509.KeyUsageKeyAgreement,
	"certsign":          x509.KeyUsageCertSign,
	"crlsign":           x509.KeyUsageCRLSign,
	"encipheronly":      x509.KeyUsageEncipherOnly,
	"decipheronly":      x509.KeyUsageDecipherOnly,
}

var extKeyUsages = map[string]x509.ExtKeyUsage{
	"any":                            x509.ExtKeyUsageAny,
	"serverauth":                     x509.ExtKeyUsageServerAuth,
	"clientauth":                     x509.ExtKeyUsageClientAuth,
	"codesigning":                    x509.ExtKeyUsageCodeSigning,
	"emailprotection":                x509.ExtKeyUsageEmailProtection,
	"ipsecendsystem":                 x509.ExtKeyUsageIPSECEndSystem,
	"ipsectunnel":                    x509.ExtKeyUsageIPSECTunnel,
	"ipsecuser":                      x509.ExtKeyUsageIPSECUser,
	"timestamping":                   x509.ExtKeyUsageTimeStamping,
	"ocspsigning":                    x509.ExtKeyUsageOCSPSigning,
	"microsoftservergatedcrypto":     x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	"netscapeservergatedcrypto":      x509.ExtKeyUsageNetscapeServerGatedCrypto,
	"microsoftcommercialcodesigning": x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
	"microsoftkernelcodesigning":     x509.ExtKeyUsageMicrosoftKernelCodeSigning,
}

var cipherSuites = append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
