package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strconv"
	"strings"
)

func NewKeypair(keyType string) (crypto.Signer, error) {
	kt := strings.ToLower(strings.TrimSpace(keyType))

	if strings.HasPrefix(kt, "rsa") {
		b := strings.ReplaceAll(kt, "-", "")
		b = strings.TrimPrefix(b, "rsa")

		bits, err := strconv.Atoi(b)
		if err != nil || bits < 4 || bits > 16000 {
			return nil, fmt.Errorf("invalid RSA key size: %s", kt)
		}

		return rsa.GenerateKey(rand.Reader, bits)
	}

	switch kt {
	case "p224", "p-224", "secp224r1":
		return ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "p256", "p-256", "prime256v1":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384", "p-384", "secp384r1":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p512", "p-521", "secp521r1":
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "ed25519", "curve25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kt)
	}
}
