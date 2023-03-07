package config

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"tls-tools/internal/random"
)

func (c Cert) ToTemplate() (*x509.Certificate, error) {
	if c.Purpose == "" {
		c.Purpose = DefaultPurpose
	}
	tmpl, ok := purposes[strings.ToLower(strings.TrimSpace(c.Purpose))]
	if !ok {
		return nil, errors.New("invalid purpose")
	}

	var err error
	if c.Subject != nil {
		tmpl.Subject, err = c.Subject.ToPkixName()
		if err != nil {
			return nil, err
		}
	} else if len(c.DNSNames) > 0 {
		tmpl.Subject = pkix.Name{CommonName: c.DNSNames[0]}
	} else if len(c.EmailAddresses) > 0 {
		tmpl.Subject = pkix.Name{CommonName: c.EmailAddresses[0]}
	} else {
		tmpl.Subject = random.PkixName()
	}

	if c.NotBefore != "" {
		t, err := parseTime(strings.TrimSpace(c.NotBefore))
		if err != nil {
			return nil, err
		}
		tmpl.NotBefore = t
	} else {
		tmpl.NotBefore = time.Now().Add(-1 * time.Hour)
	}

	if c.NotAfter != "" {
		t, err := parseTime(strings.TrimSpace(c.NotAfter))
		if err != nil {
			return nil, err
		}
		tmpl.NotAfter = t
	} else {
		tmpl.NotAfter = time.Now().Add(375 * 24 * time.Hour)
	}

	if c.CA || c.MaxPathLen != nil {
		tmpl.BasicConstraintsValid = true
		tmpl.IsCA = true
		tmpl.MaxPathLen = 99
		if c.MaxPathLen != nil {
			tmpl.MaxPathLen = *c.MaxPathLen
			if *c.MaxPathLen == 0 {
				tmpl.MaxPathLenZero = true
			}
		}
	}

	if c.SignatureAlg != "" {
		tmpl.SignatureAlgorithm, ok = signatureAlgorithms[strings.ToLower(strings.TrimSpace(c.SignatureAlg))]
		if !ok {
			return nil, errors.New("invalid signature algorithm")
		}
	}

	if c.KeyUsage != nil {
		for _, u := range strings.Split(*c.KeyUsage, ",") {
			ku, err := parseKeyUsage(u)
			if err != nil {
				return nil, err
			}
			tmpl.KeyUsage |= ku
		}
	}

	if c.ExtKeyUsage != nil {
		for _, u := range strings.Split(*c.ExtKeyUsage, ",") {
			ku, err := parseExtKeyUsage(u)
			if err != nil {
				return nil, err
			}
			tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, ku)
		}
	}

	if c.SerialNumber != nil {
		tmpl.SerialNumber, ok = c.SerialNumber.ToBigInt()
		if !ok {
			return nil, fmt.Errorf("invalid serial number: %s", *c.SerialNumber)
		}
	} else {
		tmpl.SerialNumber = random.SerialNumber()
	}

	tmpl.DNSNames = c.DNSNames
	tmpl.EmailAddresses = c.EmailAddresses

	if c.IPAddresses != nil {
		tmpl.IPAddresses = make([]net.IP, len(c.IPAddresses))
		for i, s := range c.IPAddresses {
			tmpl.IPAddresses[i] = net.ParseIP(s)
		}
	}

	if c.URIs != nil {
		// TODO
	}

	tmpl.OCSPServer = c.OCSPServer
	tmpl.CRLDistributionPoints = c.CRLDistributionPoints

	if c.Issuer != nil {
		tmpl.Issuer, err = c.Issuer.ToPkixName()
		if err != nil {
			return nil, err
		}
	}

	if len(c.Extensions) > 0 {
		// TODO: ExtraExtensions
	}

	if c.SubjectKeyId != nil {
		tmpl.SubjectKeyId, ok = c.SubjectKeyId.ToBytes()
		if !ok {
			return nil, fmt.Errorf("invalid subkect key id: %s", *c.SubjectKeyId)
		}
	}

	if c.AuthorityKeyId != nil {
		tmpl.AuthorityKeyId, ok = c.AuthorityKeyId.ToBytes()
		if !ok {
			return nil, fmt.Errorf("invalid authority key id: %s", *c.AuthorityKeyId)
		}
	}

	return &tmpl, nil
}

func (c Cert) GetKeyType() string {
	if c.KeyType == "" {
		return DefaultKeyType
	}
	return c.KeyType
}

func (s Subject) ToPkixName() (pkix.Name, error) {
	n := pkix.Name{}
	if s.CN != nil {
		n.CommonName = *s.CN
	}
	if s.OU != nil {
		n.OrganizationalUnit = []string{*s.OU}
	}
	if s.O != nil {
		n.Organization = []string{*s.O}
	}
	if s.L != nil {
		n.Locality = []string{*s.L}
	}
	if s.ST != nil {
		n.Province = []string{*s.ST}
	}
	if s.C != nil {
		n.Country = []string{*s.C}
	}
	for oidString, value := range s.ExtraNames {
		oid, err := parseOid(oidString)
		if err != nil {
			return pkix.Name{}, err
		}
		n.ExtraNames = append(n.ExtraNames, pkix.AttributeTypeAndValue{Type: oid, Value: value})
	}
	return n, nil
}

func parseOid(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	oid := make([]int, len(parts))
	var err error
	for i, part := range parts {
		oid[i], err = strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid OID: %s", s)
		}
	}
	return oid, nil
}

func parseKeyUsage(s string) (x509.KeyUsage, error) {
	ku, ok := keyUsages[strings.ToLower(strings.TrimSpace(s))]
	if ok {
		return ku, nil
	}
	return 0, errors.New("invalid key usage")
}

func parseExtKeyUsage(s string) (x509.ExtKeyUsage, error) {
	eku, ok := extKeyUsages[strings.ToLower(s)]
	if ok {
		return eku, nil
	}
	return 0, errors.New("invalid extended key usage")
}
