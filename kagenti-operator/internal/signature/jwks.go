/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package signature

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	agentv1alpha1 "github.com/kagenti/operator/api/v1alpha1"
	"golang.org/x/sync/singleflight"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	jwksLogger = ctrl.Log.WithName("signature").WithName("jwks")
)

// JWKSProvider verifies JWS signatures using a JWKS (JSON Web Key Set) endpoint
type JWKSProvider struct {
	jwksURL    string
	httpClient *http.Client
	auditMode  bool

	// Cache for JWKS keys
	keysMutex sync.RWMutex
	keysCache map[string]*JWK
	lastFetch time.Time
	cacheTTL  time.Duration

	// singleflight prevents concurrent refreshes (thundering herd on cache expiry)
	refreshGroup singleflight.Group

	// Rate-limit forced refreshes (cache-miss → re-fetch) to prevent a burst of
	// unknown kid values from hammering the JWKS endpoint.
	lastForcedRefresh time.Time
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid"` // Key ID
	Kty string `json:"kty"` // Key Type (RSA, EC, etc.)
	Use string `json:"use"` // Use (sig, enc)
	Alg string `json:"alg"` // Algorithm
	N   string `json:"n"`   // RSA modulus
	E   string `json:"e"`   // RSA exponent
	X   string `json:"x"`   // EC x coordinate
	Y   string `json:"y"`   // EC y coordinate
	Crv string `json:"crv"` // EC curve
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// DefaultJWKSCacheTTL is the default cache duration for JWKS keys
const DefaultJWKSCacheTTL = 5 * time.Minute

// maxJWKSResponseSize caps the maximum size of a JWKS response to prevent
// a malicious endpoint from causing an OOM with an unbounded body.
const maxJWKSResponseSize = 1 << 20 // 1 MiB

// forcedRefreshCooldown is the minimum interval between forced refreshes
// triggered by cache misses on unknown kid values. This prevents a burst
// of requests with bogus kid values from hammering the JWKS endpoint.
const forcedRefreshCooldown = 30 * time.Second

// NewJWKSProvider creates a new JWKS-based signature verification provider
func NewJWKSProvider(config *Config) (Provider, error) {
	if config.JWKSURL == "" {
		return nil, fmt.Errorf("JWKS URL is required")
	}

	cacheTTL := config.JWKSCacheTTL
	if cacheTTL <= 0 {
		cacheTTL = DefaultJWKSCacheTTL
	}

	if !strings.HasPrefix(config.JWKSURL, "https://") {
		jwksLogger.V(0).Info("SECURITY WARNING: JWKS URL does not use HTTPS — keys may be intercepted in transit. "+
			"Use an HTTPS endpoint in production.",
			"url", config.JWKSURL)
	}

	return &JWKSProvider{
		jwksURL: config.JWKSURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		auditMode: config.AuditMode,
		keysCache: make(map[string]*JWK),
		cacheTTL:  cacheTTL,
	}, nil
}

// VerifySignature verifies JWS signatures using keys from a JWKS endpoint.
// Iterates over the signatures array; returns success on the first verified signature.
func (p *JWKSProvider) VerifySignature(ctx context.Context, cardData *agentv1alpha1.AgentCardData, signatures []agentv1alpha1.AgentCardSignature) (*VerificationResult, error) {
	jwksLogger.Info("Verifying JWS signature using JWKS", "url", p.jwksURL)

	if len(signatures) == 0 {
		result := &VerificationResult{
			Verified: false,
			Details:  "AgentCard does not contain any signatures",
		}
		if p.auditMode {
			jwksLogger.Info("Audit mode: AgentCard has no signatures, allowing anyway", "card", cardData.Name)
			result.Verified = true
			result.Details = "AgentCard has no signatures (audit mode: allowed)"
			return result, nil
		}
		return result, nil
	}

	// Fetch JWKS keys
	if err := p.refreshKeysIfNeeded(ctx); err != nil {
		if p.auditMode {
			jwksLogger.Error(err, "Audit mode: Failed to fetch JWKS, allowing anyway")
			return &VerificationResult{
				Verified: true,
				Details:  fmt.Sprintf("Failed to fetch JWKS (audit mode: allowed): %v", err),
			}, nil
		}
		return &VerificationResult{
			Verified: false,
			Details:  fmt.Sprintf("Failed to fetch JWKS: %v", err),
		}, err
	}

	// Try each signature in the array
	for i := range signatures {
		sig := &signatures[i]

		// Decode protected header to get kid
		header, headerErr := DecodeProtectedHeader(sig.Protected)
		if headerErr != nil {
			jwksLogger.Info("Skipping signature with invalid protected header",
				"index", i, "error", headerErr)
			continue
		}

		kid := header.KeyID

		// Find the key with matching kid
		jwk := p.findKey(kid)
		if jwk == nil {
			// Force refresh in case of key rotation, but rate-limit to prevent
			// a burst of unknown kid values from hammering the JWKS endpoint.
			p.keysMutex.RLock()
			canRefresh := time.Since(p.lastForcedRefresh) > forcedRefreshCooldown
			p.keysMutex.RUnlock()

			if canRefresh {
				jwksLogger.Info("Key not found in cache, forcing JWKS refresh", "keyID", kid)
				if refreshErr := p.fetchKeys(ctx); refreshErr != nil {
					jwksLogger.Error(refreshErr, "Failed to refresh JWKS after cache miss")
				} else {
					p.keysMutex.Lock()
					p.lastForcedRefresh = time.Now()
					p.keysMutex.Unlock()
					jwk = p.findKey(kid)
				}
			} else {
				jwksLogger.Info("Key not found in cache; forced refresh on cooldown",
					"keyID", kid, "cooldown", forcedRefreshCooldown)
			}
		}

		if jwk == nil {
			jwksLogger.Info("Key not found in JWKS after refresh", "keyID", kid)
			continue
		}

		// Convert JWK to PEM
		publicKeyPEM, err := p.jwkToPublicKeyPEM(jwk)
		if err != nil {
			jwksLogger.Error(err, "Failed to convert JWK to PEM", "keyID", kid)
			continue
		}

		// Verify the signature
		result, verifyErr := VerifyJWS(cardData, sig, publicKeyPEM)
		if verifyErr == nil && result != nil && result.Verified {
			return result, nil
		}
	}

	// No signature verified
	err := fmt.Errorf("JWS signature verification failed with all JWKS keys")
	if p.auditMode {
		jwksLogger.Error(err, "Audit mode: Verification failed, allowing anyway")
		return &VerificationResult{
			Verified: true,
			Details:  fmt.Sprintf("Signature verification failed (audit mode: allowed): %v", err),
		}, nil
	}
	return &VerificationResult{
		Verified: false,
		Details:  err.Error(),
	}, err
}

// refreshKeysIfNeeded fetches JWKS keys if cache is stale.
// Uses singleflight to prevent thundering herd when multiple goroutines
// see the cache as expired simultaneously.
//
// Note on context cancellation: singleflight.Do executes the function once
// and shares the result across all callers. The context passed here belongs
// to the first caller; if that caller's context is cancelled, the HTTP request
// inside fetchKeys will be aborted and all waiters receive the error. This is
// acceptable because callers will retry on the next reconcile cycle. If this
// becomes an issue, consider using context.WithoutCancel (Go 1.21+) to
// detach the fetch from any single caller's lifetime.
func (p *JWKSProvider) refreshKeysIfNeeded(ctx context.Context) error {
	p.keysMutex.RLock()
	needsRefresh := time.Since(p.lastFetch) > p.cacheTTL
	p.keysMutex.RUnlock()

	if !needsRefresh {
		return nil
	}

	_, err, _ := p.refreshGroup.Do("jwks-refresh", func() (interface{}, error) {
		return nil, p.fetchKeys(ctx)
	})
	return err
}

// fetchKeys fetches keys from JWKS endpoint
func (p *JWKSProvider) fetchKeys(ctx context.Context) error {
	jwksLogger.Info("Fetching JWKS keys", "url", p.jwksURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxJWKSResponseSize))
		return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSResponseSize))
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Update cache
	p.keysMutex.Lock()
	defer p.keysMutex.Unlock()

	p.keysCache = make(map[string]*JWK)
	for i := range jwks.Keys {
		jwk := &jwks.Keys[i]
		if jwk.Kid != "" {
			p.keysCache[jwk.Kid] = jwk
		}
	}
	p.lastFetch = time.Now()

	jwksLogger.Info("Successfully fetched JWKS keys", "count", len(p.keysCache))
	return nil
}

// findKey finds a key by kid
func (p *JWKSProvider) findKey(kid string) *JWK {
	p.keysMutex.RLock()
	defer p.keysMutex.RUnlock()
	return p.keysCache[kid]
}

// jwkToPublicKeyPEM converts a JWK to PEM format
func (p *JWKSProvider) jwkToPublicKeyPEM(jwk *JWK) ([]byte, error) {
	switch jwk.Kty {
	case "RSA":
		return p.rsaJWKToPEM(jwk)
	case "EC":
		return p.ecJWKToPEM(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

// rsaJWKToPEM converts an RSA JWK to PEM format.
// Validates that the modulus is at least 2048 bits and the exponent is
// representable as a Go int to prevent insecure keys and overflows.
func (p *JWKSProvider) rsaJWKToPEM(jwk *JWK) ([]byte, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Reject RSA keys smaller than 2048 bits — anything less is cryptographically insecure.
	if len(nBytes) < 256 { // 2048 bits = 256 bytes
		return nil, fmt.Errorf("RSA modulus too small: %d bits (minimum 2048)", len(nBytes)*8)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Guard against exponent overflow: standard RSA exponents (e.g. 65537)
	// fit in 3 bytes; anything beyond 8 bytes is malformed.
	if len(eBytes) > 8 {
		return nil, fmt.Errorf("RSA exponent too large: %d bytes (maximum 8)", len(eBytes))
	}

	var eInt int
	for _, b := range eBytes {
		eInt = eInt<<8 + int(b)
	}

	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}

	return marshalPublicKeyToPEM(publicKey)
}

// ecJWKToPEM converts an EC JWK to PEM format.
// Validates that the decoded (X, Y) point lies on the specified curve to
// prevent invalid-curve attacks where a malicious JWKS endpoint serves
// off-curve points that could cause ecdsa.Verify to behave unpredictably.
func (p *JWKSProvider) ecJWKToPEM(jwk *JWK) ([]byte, error) {
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC x coordinate: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC y coordinate: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Reject points not on the curve to prevent invalid-curve attacks.
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("EC point (X, Y) is not on curve %s — possible invalid-curve attack", jwk.Crv)
	}

	publicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return marshalPublicKeyToPEM(publicKey)
}

// marshalPublicKeyToPEM marshals any public key to PKIX PEM format
func marshalPublicKeyToPEM(publicKey interface{}) ([]byte, error) {
	pkixBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkixBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// Name returns the provider name
func (p *JWKSProvider) Name() string {
	return "jwks"
}
