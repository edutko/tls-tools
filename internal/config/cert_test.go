package config

import (
	"bytes"
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCert_ToTemplate_defaults(t *testing.T) {
	cfg := Cert{}
	crt, err := cfg.ToTemplate()
	assert.Nil(t, err)
	assert.NotEmpty(t, crt.Subject)
	assert.Empty(t, crt.Issuer)
	assert.NotEmpty(t, crt.NotBefore)
	assert.NotEmpty(t, crt.NotAfter)
	assert.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, crt.KeyUsage)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, crt.ExtKeyUsage)
	assertValidSerial(t, crt.SerialNumber)
	assert.Empty(t, crt.DNSNames)
	assert.Empty(t, crt.IPAddresses)
	assert.Empty(t, crt.EmailAddresses)
	assert.Empty(t, crt.URIs)
	assert.False(t, crt.IsCA)
	assert.Empty(t, crt.BasicConstraintsValid)
	assert.Empty(t, crt.MaxPathLen)
	assert.Empty(t, crt.MaxPathLenZero)
}

func TestCert_ToTemplate_rootCA(t *testing.T) {
	cfg := Cert{Purpose: "root-ca"}
	crt, err := cfg.ToTemplate()
	assert.Nil(t, err)
	assert.NotEmpty(t, crt.Subject)
	assert.Empty(t, crt.Issuer)
	assert.NotEmpty(t, crt.NotBefore)
	assert.NotEmpty(t, crt.NotAfter)
	assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, crt.KeyUsage)
	assert.Empty(t, crt.ExtKeyUsage)
	assertValidSerial(t, crt.SerialNumber)
	assert.Empty(t, crt.DNSNames)
	assert.Empty(t, crt.IPAddresses)
	assert.Empty(t, crt.EmailAddresses)
	assert.Empty(t, crt.URIs)
	assert.True(t, crt.IsCA)
	assert.True(t, crt.BasicConstraintsValid)
	assert.Greater(t, crt.MaxPathLen, 0)
	assert.False(t, crt.MaxPathLenZero)
}

func TestCert_ToTemplate_intermediaCA(t *testing.T) {
	cfg := Cert{Purpose: "intermediate-ca"}
	crt, err := cfg.ToTemplate()
	assert.Nil(t, err)
	assert.NotEmpty(t, crt.Subject)
	assert.Empty(t, crt.Issuer)
	assert.NotEmpty(t, crt.NotBefore)
	assert.NotEmpty(t, crt.NotAfter)
	assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, crt.KeyUsage)
	assert.Empty(t, crt.ExtKeyUsage)
	assertValidSerial(t, crt.SerialNumber)
	assert.Empty(t, crt.DNSNames)
	assert.Empty(t, crt.IPAddresses)
	assert.Empty(t, crt.EmailAddresses)
	assert.Empty(t, crt.URIs)
	assert.True(t, crt.IsCA)
	assert.True(t, crt.BasicConstraintsValid)
	assert.Equal(t, crt.MaxPathLen, 0)
	assert.True(t, crt.MaxPathLenZero)
}

func TestCert_ToTemplate_server(t *testing.T) {
	cfg := Cert{Purpose: "server"}
	crt, err := cfg.ToTemplate()
	assert.Nil(t, err)
	assert.NotEmpty(t, crt.Subject)
	assert.Empty(t, crt.Issuer)
	assert.NotEmpty(t, crt.NotBefore)
	assert.NotEmpty(t, crt.NotAfter)
	assert.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, crt.KeyUsage)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, crt.ExtKeyUsage)
	assertValidSerial(t, crt.SerialNumber)
	assert.Empty(t, crt.DNSNames)
	assert.Empty(t, crt.IPAddresses)
	assert.Empty(t, crt.EmailAddresses)
	assert.Empty(t, crt.URIs)
	assert.False(t, crt.IsCA)
	assert.Empty(t, crt.BasicConstraintsValid)
	assert.Empty(t, crt.MaxPathLen)
	assert.Empty(t, crt.MaxPathLenZero)
}

func TestCert_ToTemplate_client(t *testing.T) {
	cfg := Cert{Purpose: "client"}
	crt, err := cfg.ToTemplate()
	assert.Nil(t, err)
	assert.NotEmpty(t, crt.Subject)
	assert.Empty(t, crt.Issuer)
	assert.NotEmpty(t, crt.NotBefore)
	assert.NotEmpty(t, crt.NotAfter)
	assert.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, crt.KeyUsage)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, crt.ExtKeyUsage)
	assertValidSerial(t, crt.SerialNumber)
	assert.Empty(t, crt.DNSNames)
	assert.Empty(t, crt.IPAddresses)
	assert.Empty(t, crt.EmailAddresses)
	assert.Empty(t, crt.URIs)
	assert.False(t, crt.IsCA)
	assert.Empty(t, crt.BasicConstraintsValid)
	assert.Empty(t, crt.MaxPathLen)
	assert.Empty(t, crt.MaxPathLenZero)
}

func assertValidSerial(t *testing.T, serial *big.Int) {
	assert.NotNil(t, serial)
	sb := serial.Bytes()
	assert.Greater(t, len(sb), 16)
	assert.Less(t, len(sb), 20)
	assert.NotEqual(t, sb, bytes.Repeat([]byte{0x00}, len(sb)))
}
