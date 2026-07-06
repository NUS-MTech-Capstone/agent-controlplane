package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type cognitoUserContextKey struct{}

type CognitoUser struct {
	Subject string
	Email   string
	Groups  []string
	Claims  map[string]any
}

type IdentityVerifier interface {
	Verify(context.Context, string) (map[string]any, error)
}

type ALBJWTVerifierConfig struct {
	Region           string
	ALBARN           string
	Issuer           string
	ClientID         string
	PublicKeyBaseURL string
	HTTPClient       *http.Client
}

type ALBJWTVerifier struct {
	albARN           string
	issuer           string
	clientID         string
	publicKeyBaseURL string
	httpClient       *http.Client
	mu               sync.RWMutex
	keys             map[string]*ecdsa.PublicKey
}

func NewALBJWTVerifier(cfg ALBJWTVerifierConfig) (*ALBJWTVerifier, error) {
	if cfg.Region == "" || cfg.ALBARN == "" || cfg.Issuer == "" || cfg.ClientID == "" {
		return nil, errors.New("ALB_ARN, COGNITO_ISSUER, COGNITO_CLIENT_ID, and AWS_REGION are required")
	}
	baseURL := cfg.PublicKeyBaseURL
	if baseURL == "" {
		baseURL = "https://public-keys.auth.elb." + cfg.Region + ".amazonaws.com"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &ALBJWTVerifier{
		albARN: cfg.ALBARN, issuer: cfg.Issuer, clientID: cfg.ClientID,
		publicKeyBaseURL: strings.TrimRight(baseURL, "/"),
		httpClient:       client, keys: make(map[string]*ecdsa.PublicKey),
	}, nil
}

func (v *ALBJWTVerifier) Verify(ctx context.Context, token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Signer    string `json:"signer"`
		Issuer    string `json:"iss"`
		ClientID  string `json:"client"`
		ExpiresAt int64  `json:"exp"`
	}
	if err := decodeJWTPart(parts[0], &header); err != nil {
		return nil, err
	}
	if header.Algorithm != "ES256" || header.KeyID == "" || header.Signer != v.albARN ||
		header.Issuer != v.issuer || header.ClientID != v.clientID || header.ExpiresAt <= time.Now().Unix() {
		return nil, errors.New("unexpected or expired ALB JWT header")
	}
	key, err := v.publicKey(ctx, header.KeyID)
	if err != nil {
		return nil, err
	}
	signature, err := decodeBase64URL(parts[2])
	if err != nil || len(signature) != 64 {
		return nil, errors.New("invalid ES256 signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, sum[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return nil, errors.New("invalid ALB JWT signature")
	}
	var claims map[string]any
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (v *ALBJWTVerifier) publicKey(ctx context.Context, keyID string) (*ecdsa.PublicKey, error) {
	if !validALBKeyID(keyID) {
		return nil, errors.New("invalid ALB public key id")
	}
	v.mu.RLock()
	key := v.keys[keyID]
	v.mu.RUnlock()
	if key != nil {
		return key, nil
	}
	keyURL, err := url.JoinPath(v.publicKeyBaseURL, keyID)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keyURL, nil) // #nosec G107 -- trusted base URL plus validated path segment.
	if err != nil {
		return nil, err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch ALB public key: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, errors.New("decode ALB public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("ALB public key is not ECDSA")
	}
	v.mu.Lock()
	v.keys[keyID] = publicKey
	v.mu.Unlock()
	return publicKey, nil
}

func validALBKeyID(keyID string) bool {
	if keyID == "" || len(keyID) > 256 {
		return false
	}
	for _, r := range keyID {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func cognitoMiddleware(verifier IdentityVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := cognitoUserFromALBHeaders(r, verifier)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "missing or invalid Cognito identity")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), cognitoUserContextKey{}, user)))
	})
}

func cognitoUserFromALBHeaders(r *http.Request, verifier IdentityVerifier) (CognitoUser, error) {
	claims, err := verifier.Verify(r.Context(), r.Header.Get("x-amzn-oidc-data"))
	if err != nil {
		return CognitoUser{}, err
	}
	subject, _ := claims["sub"].(string)
	if subject == "" {
		return CognitoUser{}, errors.New("sub claim is required")
	}
	identity := r.Header.Get("x-amzn-oidc-identity")
	if identity == "" || identity != subject {
		return CognitoUser{}, errors.New("ALB identity does not match signed subject")
	}
	email, _ := claims["email"].(string)
	groups := groupsFromClaims(claims)
	if len(groups) == 0 {
		groups = groupsFromJWT(r.Header.Get("x-amzn-oidc-accesstoken"))
	}
	return CognitoUser{Subject: subject, Email: email, Groups: groups, Claims: claims}, nil
}

func cognitoUserFromContext(ctx context.Context) (CognitoUser, bool) {
	user, ok := ctx.Value(cognitoUserContextKey{}).(CognitoUser)
	return user, ok
}

func groupsFromJWT(token string) []string {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil
	}
	var claims map[string]any
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		return nil
	}
	return groupsFromClaims(claims)
}

func groupsFromClaims(claims map[string]any) []string {
	raw, ok := claims["cognito:groups"]
	if !ok {
		raw = claims["groups"]
	}
	switch groups := raw.(type) {
	case []any:
		out := make([]string, 0, len(groups))
		for _, group := range groups {
			if value, ok := group.(string); ok && value != "" {
				out = append(out, value)
			}
		}
		return out
	case []string:
		return groups
	case string:
		if groups == "" {
			return nil
		}
		return strings.Split(groups, ",")
	default:
		return nil
	}
}

func decodeJWTPart(value string, target any) error {
	data, err := decodeBase64URL(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func decodeBase64URL(value string) ([]byte, error) {
	if data, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return data, nil
	}
	return base64.URLEncoding.DecodeString(value)
}
