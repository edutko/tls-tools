package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"tls-tools/internal/config"
)

type Store map[string]KeyAndCert

func NewStoreFromConfig(cfg map[string]config.Cert) (Store, error) {
	store := Store{}
	needSignatures := make([]string, 0)

	for name, crt := range cfg {
		tmpl, err := crt.ToTemplate()
		if err != nil {
			return nil, err
		}

		priv, err := NewKeypair(crt.GetKeyType())
		if err != nil {
			return nil, err
		}
		tmpl.PublicKey = priv.Public()

		keyDer, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}

		if crt.SubjectKeyId == nil {
			pubBytes, err := marshalPublicKey(priv.Public())
			if err != nil {
				return nil, err
			}
			pubHash := sha1.Sum(pubBytes)
			tmpl.SubjectKeyId = pubHash[:]
		}

		kac := KeyAndCert{
			privateKey: priv,
			keyDER:     keyDer,
			template:   tmpl,
			parentCert: crt.Parent,
		}

		if kac.parentCert == "" {
			kac, err = signSelf(kac)
			if err != nil {
				return nil, err
			}
		} else {
			needSignatures = append(needSignatures, name)
		}

		store[name] = kac
	}

	for _, name := range needSignatures {
		err := store.signCertAndAncestors(name, 5)
		if err != nil {
			return nil, err
		}
	}

	return store, nil
}

func (s *Store) signCertAndAncestors(name string, maxDepth int) error {
	c, ok := (*s)[name]
	if !ok {
		return fmt.Errorf("failed to find cert named %s", name)
	}

	if c.certDER != nil {
		return nil
	}

	var err error
	if c.parentCert == "" {
		(*s)[name], err = signSelf(c)
		return err
	}

	if maxDepth == 0 {
		return errors.New("failed to find root cert (chain too long)")
	}

	parent, ok := (*s)[c.parentCert]
	if !ok {
		return fmt.Errorf("failed to find cert named %s", name)
	}

	if parent.certDER == nil {
		err = s.signCertAndAncestors(c.parentCert, maxDepth-1)
		if err != nil {
			return err
		}
		parent = (*s)[c.parentCert]
	}

	(*s)[name], err = sign(c, parent)
	return err
}

func signSelf(c KeyAndCert) (KeyAndCert, error) {
	var err error

	c.certDER, err = x509.CreateCertificate(rand.Reader, c.template, c.template, c.privateKey.Public(), c.privateKey)
	if err != nil {
		return c, err
	}

	c.certificate, _ = x509.ParseCertificate(c.certDER)
	c.template = nil

	return c, nil
}

func sign(c, parent KeyAndCert) (KeyAndCert, error) {
	var err error

	c.certChainDER = append(parent.certChainDER, parent.certDER)

	// Trick Go into preserving the overridden AKI, if provided
	savedParentSKI := parent.certificate.SubjectKeyId
	if len(c.template.AuthorityKeyId) > 0 {
		parent.certificate.SubjectKeyId = c.template.AuthorityKeyId
	}
	c.certDER, err = x509.CreateCertificate(rand.Reader, c.template, parent.certificate, c.privateKey.Public(),
		parent.privateKey)
	if len(c.template.AuthorityKeyId) > 0 {
		parent.certificate.SubjectKeyId = savedParentSKI
	}
	if err != nil {
		return c, err
	}

	c.certificate, _ = x509.ParseCertificate(c.certDER)
	c.template = nil

	return c, nil
}

func marshalPublicKey(pk any) (publicKeyBytes []byte, err error) {
	switch pub := pk.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err = asn1.Marshal(rsaPublicKey{N: pub.N, E: pub.E})

	case *ecdsa.PublicKey:
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)

	case ed25519.PublicKey:
		publicKeyBytes = pub

	default:
		err = fmt.Errorf("x509: unsupported public key type: %T", pub)
	}

	return
}

type rsaPublicKey struct {
	N *big.Int
	E int
}
