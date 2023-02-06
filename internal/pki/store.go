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

	"tls-cert-tools/internal/config"
)

type Store map[string]KeyAndCert

func NewStoreFromConfig(cfg map[string]config.Cert) (Store, error) {
	store := Store{}

	needSignature := make([]string, 0)
	for name, crt := range cfg {
		tmpl, err := crt.ToTemplate()
		if err != nil {
			return nil, err
		}

		if tmpl.SerialNumber == nil {
			tmpl.SerialNumber, err = rand.Int(rand.Reader, big.NewInt(2^64))
			if err != nil {
				return nil, err
			}
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
			privateKey:   priv,
			keyDER:       keyDer,
			certTemplate: tmpl,
			parentCert:   crt.Parent,
		}

		if kac.parentCert == "" {
			kac.certDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
			if err != nil {
				return nil, err
			}
			kac.certificate, _ = x509.ParseCertificate(kac.certDER)
		} else {
			needSignature = append(needSignature, name)
		}

		store[name] = kac
	}

	for _, name := range needSignature {
		err := store.signCert(name, 5)
		if err != nil {
			return nil, err
		}
	}

	return store, nil
}

func (s *Store) signCert(name string, maxDepth int) error {
	c, ok := (*s)[name]
	if !ok {
		return fmt.Errorf("failed to find cert named %s", name)
	}

	if c.certDER != nil {
		return nil
	}

	var err error
	if c.parentCert == "" {
		c.certDER, err = x509.CreateCertificate(rand.Reader, c.certTemplate, c.certTemplate, c.privateKey.Public(),
			c.privateKey)
		if err != nil {
			return err
		}
		c.certificate, _ = x509.ParseCertificate(c.certDER)
		(*s)[name] = c
		return nil
	}

	if maxDepth == 0 {
		return errors.New("failed to find root cert (chain too long)")
	}

	parent, ok := (*s)[c.parentCert]
	if !ok {
		return fmt.Errorf("failed to find cert named %s", name)
	}

	if parent.certDER == nil {
		err = s.signCert(c.parentCert, maxDepth-1)
		if err != nil {
			return err
		}
		parent = (*s)[c.parentCert]
	}

	// Trick Go into preserving the overridden AKI, if provided
	savedParentSKI := parent.certificate.SubjectKeyId
	if len(c.certTemplate.AuthorityKeyId) > 0 {
		parent.certificate.SubjectKeyId = c.certTemplate.AuthorityKeyId
	}
	c.certChainDER = append(parent.certChainDER, parent.certDER)
	c.certDER, err = x509.CreateCertificate(rand.Reader, c.certTemplate, parent.certificate, c.privateKey.Public(),
		parent.privateKey)
	c.certificate, _ = x509.ParseCertificate(c.certDER)
	if len(c.certTemplate.AuthorityKeyId) > 0 {
		parent.certificate.SubjectKeyId = savedParentSKI
	}
	if err != nil {
		return err
	}

	(*s)[name] = c

	return nil
}

func marshalPublicKey(pk any) (publicKeyBytes []byte, err error) {
	switch pub := pk.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err = asn1.Marshal(struct {
			N *big.Int
			E int
		}{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, err
		}
	case *ecdsa.PublicKey:
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	case ed25519.PublicKey:
		publicKeyBytes = pub
	default:
		return nil, fmt.Errorf("x509: unsupported public key type: %T", pub)
	}

	return publicKeyBytes, nil
}
