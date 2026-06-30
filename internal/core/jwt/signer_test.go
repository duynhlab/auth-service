package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// mustECKey returns an ECDSA key, used to assert non-RSA PKCS8 is rejected.
func mustECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return k
}

const (
	testIssuer   = "https://issuer.test"
	testAudience = "test-aud"
)

// pkcs8PEM marshals a key to a PKCS#8 PEM string.
func pkcs8PEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// pkcs1PEM marshals a key to a PKCS#1 PEM string.
func pkcs1PEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

func TestNewSigner_Ephemeral(t *testing.T) {
	s, ephemeral, err := NewSigner("", testIssuer, testAudience, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if !ephemeral {
		t.Error("expected ephemeral=true for empty PEM")
	}
	if s.Kid() == "" {
		t.Error("expected non-empty kid")
	}
}

func TestNewSigner_ParsesPKCS8AndKidStable(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pemStr := pkcs8PEM(t, key)

	s1, ephemeral, err := NewSigner(pemStr, testIssuer, testAudience, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner PKCS8: %v", err)
	}
	if ephemeral {
		t.Error("expected ephemeral=false when PEM provided")
	}
	// Re-parsing the same key must yield the same kid (stable).
	s2, _, err := NewSigner(pemStr, testIssuer, testAudience, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner second parse: %v", err)
	}
	if s1.Kid() != s2.Kid() {
		t.Errorf("kid not stable: %q vs %q", s1.Kid(), s2.Kid())
	}
}

func TestNewSigner_ParsesPKCS1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, ephemeral, err := NewSigner(pkcs1PEM(t, key), testIssuer, testAudience, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner PKCS1: %v", err)
	}
	if ephemeral {
		t.Error("expected ephemeral=false for PKCS1 PEM")
	}
	if s.Kid() == "" {
		t.Error("expected non-empty kid")
	}
}

func TestNewSigner_BadPEM(t *testing.T) {
	cases := map[string]string{
		"not a pem":        "this is not pem",
		"garbage in block": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")})),
	}
	for name, pemStr := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := NewSigner(pemStr, testIssuer, testAudience, time.Hour); err == nil {
				t.Error("expected error for bad PEM, got nil")
			}
		})
	}
}

func TestNewSigner_NonRSAPKCS8(t *testing.T) {
	// An EC key in PKCS8 must be rejected as not-RSA.
	der, err := x509.MarshalPKCS8PrivateKey(mustECKey(t))
	if err != nil {
		t.Fatalf("marshal EC PKCS8: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if _, _, err := NewSigner(pemStr, testIssuer, testAudience, time.Hour); err == nil {
		t.Error("expected error for non-RSA key, got nil")
	}
}

func TestMintAccess_VerifiesAndHasClaims(t *testing.T) {
	s, _, err := NewSigner("", testIssuer, testAudience, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	token, expiresIn, err := s.MintAccess("42", "alice", "alice@example.com")
	if err != nil {
		t.Fatalf("MintAccess: %v", err)
	}
	if expiresIn != int(time.Hour.Seconds()) {
		t.Errorf("expiresIn = %d, want %d", expiresIn, int(time.Hour.Seconds()))
	}

	parsed, err := gojwt.Parse(token, func(tok *gojwt.Token) (any, error) {
		if _, ok := tok.Method.(*gojwt.SigningMethodRSA); !ok {
			t.Fatalf("unexpected signing method: %v", tok.Header["alg"])
		}
		if tok.Header["kid"] != s.Kid() {
			t.Errorf("header kid = %v, want %q", tok.Header["kid"], s.Kid())
		}
		return &s.privateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse minted token: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("token not valid")
	}

	claims, ok := parsed.Claims.(gojwt.MapClaims)
	if !ok {
		t.Fatalf("unexpected claims type %T", parsed.Claims)
	}
	if claims["iss"] != testIssuer {
		t.Errorf("iss = %v, want %q", claims["iss"], testIssuer)
	}
	if claims["aud"] != testAudience {
		t.Errorf("aud = %v, want %q", claims["aud"], testAudience)
	}
	if claims["sub"] != "42" {
		t.Errorf("sub = %v, want 42", claims["sub"])
	}
	if claims["username"] != "alice" {
		t.Errorf("username = %v, want alice", claims["username"])
	}
	if claims["email"] != "alice@example.com" {
		t.Errorf("email = %v, want alice@example.com", claims["email"])
	}
	for _, c := range []string{"exp", "iat", "nbf", "jti"} {
		if _, present := claims[c]; !present {
			t.Errorf("claim %q missing", c)
		}
	}
	// roles is an empty array placeholder.
	roles, present := claims["roles"]
	if !present {
		t.Fatal("roles claim missing")
	}
	arr, ok := roles.([]any)
	if !ok {
		t.Fatalf("roles type = %T, want array", roles)
	}
	if len(arr) != 0 {
		t.Errorf("roles len = %d, want 0", len(arr))
	}
}

func TestMintAccess_ExpiredTokenRejected(t *testing.T) {
	// Negative TTL => exp in the past => Parse must reject it.
	s, _, err := NewSigner("", testIssuer, testAudience, -time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	token, _, err := s.MintAccess("1", "bob", "bob@example.com")
	if err != nil {
		t.Fatalf("MintAccess: %v", err)
	}
	_, err = gojwt.Parse(token, func(_ *gojwt.Token) (any, error) {
		return &s.privateKey.PublicKey, nil
	})
	if err == nil {
		t.Error("expected expired token to be rejected, got nil error")
	}
}

func TestJWKS_RoundTrip(t *testing.T) {
	s, _, err := NewSigner("", testIssuer, testAudience, time.Hour)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	body, err := s.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	var set struct {
		Keys []struct {
			Kty, Use, Alg, Kid, N, E string
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("keys len = %d, want 1", len(set.Keys))
	}
	k := set.Keys[0]
	if k.Kty != "RSA" || k.Use != "sig" || k.Alg != "RS256" {
		t.Errorf("unexpected JWK fields: %+v", k)
	}
	if k.Kid != s.Kid() {
		t.Errorf("JWK kid = %q, want %q", k.Kid, s.Kid())
	}

	// n/e must decode back to the signer's public key.
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		t.Fatalf("decode e: %v", err)
	}
	pub := &s.privateKey.PublicKey
	if new(big.Int).SetBytes(nBytes).Cmp(pub.N) != 0 {
		t.Error("decoded modulus does not match public key")
	}
	if int(new(big.Int).SetBytes(eBytes).Int64()) != pub.E {
		t.Errorf("decoded exponent = %d, want %d", new(big.Int).SetBytes(eBytes).Int64(), pub.E)
	}
}
