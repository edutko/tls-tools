package pki

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
)

type KeyAndCert struct {
	certTemplate *x509.Certificate
	parentCert   string
	privateKey   crypto.Signer
	certificate  *x509.Certificate
	keyDER       []byte
	certDER      []byte
	certChainDER [][]byte
}

func (k KeyAndCert) GetPrivateKey() crypto.Signer {
	return k.privateKey
}

func (k KeyAndCert) GetCertificate() *x509.Certificate {
	return k.certificate
}

func (k KeyAndCert) IsRootCA() bool {
	return k.parentCert == "" && k.certificate.IsCA
}

func (k KeyAndCert) GetKeyDER() []byte {
	return k.keyDER
}

func (k KeyAndCert) GetKeyPEM() []byte {
	if len(k.keyDER) == 0 {
		return nil
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: k.keyDER,
	})
}

func (k KeyAndCert) GetCertDER() []byte {
	return k.certDER
}

func (k KeyAndCert) GetCertPEM() []byte {
	if len(k.certDER) == 0 {
		return nil
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: k.certDER,
	})
}

func (k KeyAndCert) GetCertChainDER() [][]byte {
	return append([][]byte{k.certDER}, k.certChainDER...)
}
