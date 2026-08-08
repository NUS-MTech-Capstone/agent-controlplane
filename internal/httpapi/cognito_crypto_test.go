package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

type cryptoRoundTripFunc func(*http.Request) (*http.Response, error)

func (f cryptoRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestALBJWTVerifierValidTokenAndKeyCache(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	fetches := 0
	client := &http.Client{Transport: cryptoRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		fetches++
		if req.URL.Path != "/kid-1" {
			t.Fatalf("key path = %q", req.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(publicPEM))), Header: make(http.Header)}, nil
	})}
	verifier, err := NewALBJWTVerifier(ALBJWTVerifierConfig{
		Region: "ap-southeast-1", ALBARN: "arn:alb", Issuer: "https://issuer", ClientID: "client",
		PublicKeyBaseURL: "https://keys.example/", HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("NewALBJWTVerifier() error = %v", err)
	}
	token := signedALBToken(t, privateKey, map[string]any{
		"alg": "ES256", "kid": "kid-1", "signer": "arn:alb", "iss": "https://issuer", "client": "client", "exp": time.Now().Add(time.Minute).Unix(),
	}, map[string]any{"sub": "user-1", "email": "user@example.com"})
	for range 2 {
		claims, err := verifier.Verify(context.Background(), token)
		if err != nil || claims["sub"] != "user-1" {
			t.Fatalf("Verify() claims=%#v error=%v", claims, err)
		}
	}
	if fetches != 1 {
		t.Fatalf("public key fetches = %d, want 1", fetches)
	}
}

func TestALBJWTVerifierRejectsInvalidInputs(t *testing.T) {
	if _, err := NewALBJWTVerifier(ALBJWTVerifierConfig{}); err == nil {
		t.Fatal("missing configuration accepted")
	}
	verifier, err := NewALBJWTVerifier(ALBJWTVerifierConfig{Region: "r", ALBARN: "a", Issuer: "i", ClientID: "c"})
	if err != nil {
		t.Fatal(err)
	}
	if verifier.publicKeyBaseURL != "https://public-keys.auth.elb.r.amazonaws.com" || verifier.httpClient == nil {
		t.Fatalf("defaults = %#v", verifier)
	}
	invalid := []string{"", "abc", "a.b", "a.b.c.d"}
	for _, token := range invalid {
		if _, err := verifier.Verify(context.Background(), token); err == nil {
			t.Fatalf("invalid token %q accepted", token)
		}
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user"}`))
	if _, err := verifier.Verify(context.Background(), header+"."+body+".bad"); err == nil {
		t.Fatal("unexpected header accepted")
	}
	for _, keyID := range []string{"", "../secret", "with space", strings.Repeat("a", 257)} {
		if validALBKeyID(keyID) {
			t.Fatalf("validALBKeyID(%q) = true", keyID)
		}
	}
	for _, keyID := range []string{"abc", "A_B-9"} {
		if !validALBKeyID(keyID) {
			t.Fatalf("validALBKeyID(%q) = false", keyID)
		}
	}
	if err := decodeJWTPart("%%%", &map[string]any{}); err == nil {
		t.Fatal("invalid base64 accepted")
	}
}

func TestALBPublicKeyResponseValidation(t *testing.T) {
	responses := []struct {
		name   string
		status int
		body   string
	}{
		{name: "http error", status: http.StatusNotFound, body: "missing"},
		{name: "invalid pem", status: http.StatusOK, body: "not pem"},
	}
	for _, tc := range responses {
		t.Run(tc.name, func(t *testing.T) {
			verifier := &ALBJWTVerifier{publicKeyBaseURL: "https://keys.example", httpClient: &http.Client{Transport: cryptoRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
			})}, keys: map[string]*ecdsa.PublicKey{}}
			if _, err := verifier.publicKey(context.Background(), "kid"); err == nil {
				t.Fatal("invalid public key response accepted")
			}
		})
	}

	rsaDER, err := x509.MarshalPKIXPublicKey(big.NewInt(1))
	if err == nil {
		t.Fatal("unexpectedly marshaled unsupported public key")
	}
	_ = rsaDER
}

func signedALBToken(t *testing.T, key *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	sum := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}
