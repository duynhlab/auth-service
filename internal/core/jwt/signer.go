// Package jwt mints RS256 access JWTs and serves the matching JWKS.
//
// It runs ALONGSIDE the existing opaque session token (dual-issue): the opaque
// token remains the authoritative east-west credential (validated via
// auth.GetMe), while the signed JWT is an additive, self-contained access token.
package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Signer signs RS256 access tokens and exposes its public key as a JWKS.
type Signer struct {
	privateKey *rsa.PrivateKey
	kid        string
	issuer     string
	audience   string
	accessTTL  time.Duration
}

// NewSigner builds a Signer.
//
// The returned bool reports whether an EPHEMERAL key was generated: when
// privateKeyPEM is empty a fresh 2048-bit RSA key is generated (ephemeral=true).
// Otherwise the PEM is parsed (PKCS#1 "RSA PRIVATE KEY" or PKCS#8 "PRIVATE
// KEY"); a parse failure returns an error.
//
// The kid is the base64url (no padding) of SHA-256 over the PKIX DER bytes of
// the public key, so it is stable for a given key.
func NewSigner(privateKeyPEM, issuer, audience string, accessTTL time.Duration) (*Signer, bool, error) {
	var (
		key       *rsa.PrivateKey
		ephemeral bool
	)

	if privateKeyPEM == "" {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, false, fmt.Errorf("generate ephemeral RSA key: %w", err)
		}
		key = k
		ephemeral = true
	} else {
		k, err := parsePrivateKeyPEM([]byte(privateKeyPEM))
		if err != nil {
			return nil, false, err
		}
		key = k
	}

	kid, err := computeKid(&key.PublicKey)
	if err != nil {
		return nil, ephemeral, err
	}

	return &Signer{
		privateKey: key,
		kid:        kid,
		issuer:     issuer,
		audience:   audience,
		accessTTL:  accessTTL,
	}, ephemeral, nil
}

// parsePrivateKeyPEM decodes a PEM block and parses it as PKCS#1 or PKCS#8.
func parsePrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("parse private key PEM: no PEM block found")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key PEM: %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("parse private key PEM: not an RSA key (%T)", parsed)
	}
	return rsaKey, nil
}

// computeKid derives a stable key ID from the public key's PKIX DER bytes.
func computeKid(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// MintAccess issues an RS256 access token for the given identity. expiresIn is
// the access TTL in whole seconds.
func (s *Signer) MintAccess(userID, username, email string) (token string, expiresIn int, err error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":      s.issuer,
		"aud":      s.audience,
		"sub":      userID,
		"exp":      now.Add(s.accessTTL).Unix(),
		"iat":      now.Unix(),
		"nbf":      now.Unix(),
		"jti":      uuid.NewString(),
		"username": username,
		"email":    email,
		"roles":    []string{},
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = s.kid

	signed, err := t.SignedString(s.privateKey)
	if err != nil {
		return "", 0, fmt.Errorf("sign access token: %w", err)
	}
	return signed, int(s.accessTTL.Seconds()), nil
}

// jwk is a single RSA public key in JWK form.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// JWKS returns the JSON Web Key Set (one key) for this signer's public key.
func (s *Signer) JWKS() ([]byte, error) {
	pub := &s.privateKey.PublicKey

	eBytes := big.NewInt(int64(pub.E)).Bytes()

	set := jwks{
		Keys: []jwk{{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: s.kid,
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(eBytes),
		}},
	}

	out, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("marshal JWKS: %w", err)
	}
	return out, nil
}

// Kid returns the key ID of this signer's key.
func (s *Signer) Kid() string {
	return s.kid
}
