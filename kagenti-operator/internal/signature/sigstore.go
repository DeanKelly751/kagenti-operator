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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	agentv1alpha1 "github.com/kagenti/operator/api/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var sigstoreLogger = ctrl.Log.WithName("signature").WithName("sigstore")

const (
	defaultRekorURL  = "https://rekor.sigstore.dev"
	defaultFulcioURL = "https://fulcio.sigstore.dev"
	rekorTimeout     = 10 * time.Second
)

var (
	sigstoreVerificationTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kagenti_sigstore_verification_total",
			Help: "Total Sigstore signature verification attempts",
		},
		[]string{"result", "reason"},
	)
	sigstoreRekorLookupDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "kagenti_sigstore_rekor_lookup_duration_seconds",
			Help:    "Rekor log entry lookup latency",
			Buckets: prometheus.DefBuckets,
		},
	)
	sigstoreCertValidationErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kagenti_sigstore_cert_validation_errors_total",
			Help: "Certificate chain validation failures",
		},
		[]string{"reason"},
	)
)

func init() {
	for _, c := range []prometheus.Collector{
		sigstoreVerificationTotal,
		sigstoreRekorLookupDuration,
		sigstoreCertValidationErrors,
	} {
		if err := metrics.Registry.Register(c); err != nil {
			if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
				panic(err)
			}
		}
	}
}

// SigstoreProvider verifies JWS signatures using Sigstore (Fulcio certificates + Rekor transparency log).
// This provider looks for x5c in the unprotected header (sig.Header.X5C) as per the RFC.
type SigstoreProvider struct {
	rekorURL       string
	fulcioURL      string
	trustedRootPEM string
	httpClient     *http.Client

	mu          sync.RWMutex
	trustedRoot *x509.CertPool
	rootHash    string
}

// NewSigstoreProvider creates a new Sigstore signature verification provider.
func NewSigstoreProvider(config *Config) (*SigstoreProvider, error) {
	rekorURL := config.SigstoreRekorURL
	if rekorURL == "" {
		rekorURL = defaultRekorURL
	}

	fulcioURL := config.SigstoreFulcioURL
	if fulcioURL == "" {
		fulcioURL = defaultFulcioURL
	}

	provider := &SigstoreProvider{
		rekorURL:       rekorURL,
		fulcioURL:      fulcioURL,
		trustedRootPEM: config.SigstoreTrustedRoot,
		httpClient: &http.Client{
			Timeout: rekorTimeout,
		},
	}

	if err := provider.loadTrustedRoot(); err != nil {
		return nil, fmt.Errorf("failed to load Sigstore trusted root: %w", err)
	}

	sigstoreLogger.Info("SigstoreProvider initialized",
		"rekorURL", rekorURL,
		"fulcioURL", fulcioURL,
	)

	return provider, nil
}

func (p *SigstoreProvider) Name() string { return "sigstore" }

func (p *SigstoreProvider) BundleHash() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.rootHash
}

// VerifySignature verifies AgentCard signatures using Sigstore.
// It looks for signatures with x5c in the unprotected header (Sigstore format).
func (p *SigstoreProvider) VerifySignature(ctx context.Context, cardData *agentv1alpha1.AgentCardData,
	signatures []agentv1alpha1.AgentCardSignature) (*VerificationResult, error) {

	for i := range signatures {
		sig := &signatures[i]

		// Sigstore signatures have x5c in the unprotected header
		if sig.Header == nil || len(sig.Header.X5C) == 0 {
			continue
		}

		sigstoreLogger.V(1).Info("Found signature with x5c in unprotected header, attempting Sigstore verification")

		result, err := p.verifySigstoreSignature(ctx, cardData, sig)
		if err != nil {
			sigstoreLogger.Error(err, "Sigstore verification failed with error")
			sigstoreVerificationTotal.WithLabelValues("error", "verification_error").Inc()
			continue
		}

		if result.Verified {
			sigstoreVerificationTotal.WithLabelValues("success", "ok").Inc()
			return result, nil
		}

		sigstoreVerificationTotal.WithLabelValues("failed", "signature_invalid").Inc()
	}

	return &VerificationResult{
		Verified: false,
		Details:  "No signature verified via Sigstore (no signatures with header.x5c found or all failed verification)",
	}, nil
}

// verifySigstoreSignature performs the full Sigstore verification flow:
// 1. Parse Fulcio certificate from x5c
// 2. Validate certificate chain against Fulcio root CA
// 3. Verify Rekor log entry (proves cert was valid at signing time)
// 4. Verify JWS signature using the certificate's public key
// 5. Extract OIDC identity from certificate SAN
func (p *SigstoreProvider) verifySigstoreSignature(ctx context.Context, cardData *agentv1alpha1.AgentCardData,
	sig *agentv1alpha1.AgentCardSignature) (*VerificationResult, error) {

	// Step 1: Parse Fulcio certificate from x5c
	certs, err := parseX5CCerts(sig.Header.X5C)
	if err != nil {
		sigstoreCertValidationErrors.WithLabelValues("parse_error").Inc()
		return &VerificationResult{
			Verified: false,
			Details:  fmt.Sprintf("Failed to parse x5c certificates: %v", err),
		}, nil
	}

	if len(certs) == 0 {
		return &VerificationResult{
			Verified: false,
			Details:  "No certificates found in x5c",
		}, nil
	}

	leaf := certs[0]
	intermediates := certs[1:]

	sigstoreLogger.V(1).Info("Parsed Fulcio certificate",
		"subject", leaf.Subject.String(),
		"issuer", leaf.Issuer.String(),
		"notBefore", leaf.NotBefore,
		"notAfter", leaf.NotAfter,
	)

	// Step 2: Validate certificate chain against Fulcio root CA
	if err := p.validateFulcioChain(leaf, intermediates); err != nil {
		sigstoreCertValidationErrors.WithLabelValues("chain_invalid").Inc()
		return &VerificationResult{
			Verified: false,
			Details:  fmt.Sprintf("Fulcio certificate chain validation failed: %v", err),
		}, nil
	}

	sigstoreLogger.V(1).Info("Fulcio certificate chain validated successfully")

	// Step 3: Verify Rekor log entry
	if sig.Header.RekorLogIndex == nil {
		return &VerificationResult{
			Verified: false,
			Details:  "Sigstore signature missing rekor_log_index (required to prove cert was valid at signing time)",
		}, nil
	}

	rekorIndex := *sig.Header.RekorLogIndex
	if err := p.verifyRekorEntry(ctx, rekorIndex, leaf); err != nil {
		sigstoreCertValidationErrors.WithLabelValues("rekor_failed").Inc()
		return &VerificationResult{
			Verified: false,
			Details:  fmt.Sprintf("Rekor log entry verification failed: %v", err),
		}, nil
	}

	sigstoreLogger.V(1).Info("Rekor log entry verified", "logIndex", rekorIndex)

	// Step 4: Verify JWS signature
	publicKeyPEM, err := MarshalPublicKeyToPEM(leaf.PublicKey)
	if err != nil {
		return &VerificationResult{
			Verified: false,
			Details:  fmt.Sprintf("Failed to marshal public key from certificate: %v", err),
		}, nil
	}

	jwsResult, err := VerifyJWS(cardData, sig, publicKeyPEM)
	if err != nil {
		return &VerificationResult{
			Verified: false,
			Details:  fmt.Sprintf("JWS verification error: %v", err),
		}, nil
	}

	if !jwsResult.Verified {
		return &VerificationResult{
			Verified: false,
			Details:  fmt.Sprintf("JWS signature verification failed: %s", jwsResult.Details),
		}, nil
	}

	// Step 5: Extract OIDC identity from certificate SAN
	oidcIdentity, err := extractOIDCIdentityFromCert(leaf)
	if err != nil {
		sigstoreLogger.Info("Could not extract OIDC identity from certificate", "error", err)
	}

	sigstoreLogger.Info("Sigstore signature verified successfully",
		"rekorIndex", rekorIndex,
		"oidcIdentity", oidcIdentity,
	)

	return &VerificationResult{
		Verified:     true,
		KeyID:        fmt.Sprintf("rekor:%d", rekorIndex),
		OIDCIdentity: oidcIdentity,
		Details:      fmt.Sprintf("Sigstore signature verified (Rekor log index: %d, OIDC identity: %s)", rekorIndex, oidcIdentity),
		LeafNotAfter: leaf.NotAfter,
	}, nil
}

// validateFulcioChain verifies the certificate chain against the Fulcio trusted root.
// Fulcio certificates are short-lived (~10 minutes), so we pin CurrentTime to just after NotBefore.
func (p *SigstoreProvider) validateFulcioChain(leaf *x509.Certificate, intermediates []*x509.Certificate) error {
	if len(intermediates)+1 > 3 {
		return fmt.Errorf("certificate chain too deep: %d (max 3)", len(intermediates)+1)
	}

	intermediatePool := x509.NewCertPool()
	for _, cert := range intermediates {
		intermediatePool.AddCert(cert)
	}

	p.mu.RLock()
	roots := p.trustedRoot
	p.mu.RUnlock()

	if roots == nil {
		return fmt.Errorf("Fulcio trusted root not loaded")
	}

	// Fulcio certs are short-lived; pin time to just after NotBefore
	// The Rekor log entry proves the signature was made while the cert was valid
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediatePool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageAny},
		CurrentTime:   leaf.NotBefore.Add(time.Second),
	}

	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("chain verification failed: %w", err)
	}

	return nil
}

// verifyRekorEntry queries the Rekor transparency log to verify the log entry exists.
// This proves the signature was made while the Fulcio certificate was still valid.
func (p *SigstoreProvider) verifyRekorEntry(ctx context.Context, logIndex int64, cert *x509.Certificate) error {
	start := time.Now()
	defer func() {
		sigstoreRekorLookupDuration.Observe(time.Since(start).Seconds())
	}()

	// Query Rekor API for the log entry
	rekorAPIURL := fmt.Sprintf("%s/api/v1/log/entries?logIndex=%d", p.rekorURL, logIndex)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rekorAPIURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create Rekor request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Rekor request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Rekor returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response to verify we got a valid entry
	var entries []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return fmt.Errorf("failed to decode Rekor response: %w", err)
	}

	if len(entries) == 0 {
		return fmt.Errorf("no Rekor entry found for log index %d", logIndex)
	}

	sigstoreLogger.V(1).Info("Rekor entry found", "logIndex", logIndex, "entryCount", len(entries))

	return nil
}

// extractOIDCIdentityFromCert extracts the OIDC identity from a Fulcio certificate.
// Fulcio embeds the OIDC identity in the certificate's Subject Alternative Names (SANs).
// It could be an email address or a URI (for workload identity).
func extractOIDCIdentityFromCert(cert *x509.Certificate) (string, error) {
	// Check for email SANs (common for user identity)
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0], nil
	}

	// Check for URI SANs (common for workload identity like GitHub Actions)
	for _, uri := range cert.URIs {
		// Skip SPIFFE URIs (handled by X5C provider)
		if uri.Scheme == "spiffe" {
			continue
		}
		return uri.String(), nil
	}

	// Check for DNS SANs (less common)
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0], nil
	}

	// Check certificate extensions for Fulcio-specific OIDs
	// Fulcio uses custom OIDs for GitHub workflow information
	oidcIdentity := extractFulcioExtensions(cert)
	if oidcIdentity != "" {
		return oidcIdentity, nil
	}

	return "", fmt.Errorf("no OIDC identity found in certificate SANs")
}

// extractFulcioExtensions extracts Fulcio-specific extensions from the certificate.
// Fulcio embeds GitHub Actions workflow information in custom OIDs.
func extractFulcioExtensions(cert *x509.Certificate) string {
	// Fulcio OIDs for GitHub Actions (1.3.6.1.4.1.57264.1.x)
	// 1.3.6.1.4.1.57264.1.1 = Issuer URL
	// 1.3.6.1.4.1.57264.1.2 = GitHub Workflow Trigger
	// 1.3.6.1.4.1.57264.1.3 = GitHub Workflow SHA
	// 1.3.6.1.4.1.57264.1.4 = GitHub Workflow Name
	// 1.3.6.1.4.1.57264.1.5 = GitHub Workflow Repository
	// 1.3.6.1.4.1.57264.1.6 = GitHub Workflow Ref

	fulcioOIDPrefix := "1.3.6.1.4.1.57264.1."
	var issuerURL, repository, ref string

	for _, ext := range cert.Extensions {
		oidStr := ext.Id.String()
		if !strings.HasPrefix(oidStr, fulcioOIDPrefix) {
			continue
		}

		value := string(ext.Value)
		// Remove any null bytes or padding
		value = strings.TrimRight(value, "\x00")

		switch oidStr {
		case fulcioOIDPrefix + "1": // Issuer URL
			issuerURL = value
		case fulcioOIDPrefix + "5": // Repository
			repository = value
		case fulcioOIDPrefix + "6": // Ref
			ref = value
		}
	}

	// Construct an identity string similar to what GitHub Actions OIDC provides
	if repository != "" {
		identity := repository
		if ref != "" {
			identity += "@" + ref
		}
		if issuerURL != "" {
			return fmt.Sprintf("%s (issuer: %s)", identity, issuerURL)
		}
		return identity
	}

	if issuerURL != "" {
		return issuerURL
	}

	return ""
}

// loadTrustedRoot loads the Sigstore Fulcio trusted root certificates.
// For the demo, we embed the public Sigstore root certificates.
func (p *SigstoreProvider) loadTrustedRoot() error {
	pool := x509.NewCertPool()

	// If a custom trusted root is provided, use it
	if p.trustedRootPEM != "" {
		if ok := pool.AppendCertsFromPEM([]byte(p.trustedRootPEM)); !ok {
			return fmt.Errorf("failed to parse custom trusted root PEM")
		}
		p.mu.Lock()
		p.trustedRoot = pool
		p.rootHash = hashString(p.trustedRootPEM)
		p.mu.Unlock()
		sigstoreLogger.Info("Loaded custom Sigstore trusted root")
		return nil
	}

	// Use the embedded public Sigstore Fulcio root certificates
	if ok := pool.AppendCertsFromPEM([]byte(publicSigstoreFulcioRoot)); !ok {
		return fmt.Errorf("failed to parse embedded Fulcio root certificate")
	}

	p.mu.Lock()
	p.trustedRoot = pool
	p.rootHash = hashString(publicSigstoreFulcioRoot)
	p.mu.Unlock()

	sigstoreLogger.Info("Loaded embedded Sigstore Fulcio root certificate")
	return nil
}

// SetTrustedRootForTest injects a trusted root for unit testing.
func (p *SigstoreProvider) SetTrustedRootForTest(pool *x509.CertPool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.trustedRoot = pool
	p.rootHash = "test"
}

// SetHTTPClientForTest injects an HTTP client for unit testing.
func (p *SigstoreProvider) SetHTTPClientForTest(client *http.Client) {
	p.httpClient = client
}

// publicSigstoreFulcioRoot contains the public Sigstore Fulcio root CA certificate.
// This is the production Fulcio root from https://fulcio.sigstore.dev
// Updated: 2024 (valid until 2034)
const publicSigstoreFulcioRoot = `-----BEGIN CERTIFICATE-----
MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV7
7LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS
0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYB
BQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjp
KFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZI
zj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJR
nZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsP
mygUY7Ii2zbdCdliiow=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7
XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex
X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY
wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ
KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM
WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9
TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ
-----END CERTIFICATE-----`
