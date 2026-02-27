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
	"fmt"
	"time"

	agentv1alpha1 "github.com/kagenti/operator/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// VerificationResult holds the outcome of a signature verification.
//
// Error contract: a non-nil error from Provider.VerifySignature indicates an
// infrastructure failure (retriable). Cryptographic failures set Verified=false
// with a nil error.
type VerificationResult struct {
	Verified     bool
	KeyID        string
	SpiffeID     string    // from leaf cert SAN URI (SPIRE/X5C provider)
	OIDCIdentity string    // from Fulcio cert SAN (Sigstore provider)
	Details      string
	LeafNotAfter time.Time // leaf cert expiry
}

// Provider verifies A2A AgentCard JWS signatures (spec section 8.4).
type Provider interface {
	// VerifySignature returns success if at least one signature verifies.
	VerifySignature(ctx context.Context, cardData *agentv1alpha1.AgentCardData, signatures []agentv1alpha1.AgentCardSignature) (*VerificationResult, error)
	Name() string
	// BundleHash returns a hash of the current trust bundle for change detection.
	BundleHash() string
}

type ProviderType string

const (
	ProviderTypeX5C      ProviderType = "x5c"
	ProviderTypeSigstore ProviderType = "sigstore"
)

// Config holds configuration for the signature verification provider.
type Config struct {
	Type ProviderType

	// X5C provider config (SPIRE trust bundle)
	TrustBundleConfigMapName   string // ConfigMap name (SPIFFE JSON format)
	TrustBundleConfigMapNS     string
	TrustBundleConfigMapKey    string        // default: "bundle.spiffe"
	TrustBundleRefreshInterval time.Duration // default: 5m

	// Sigstore provider config
	SigstoreRekorURL    string // default: https://rekor.sigstore.dev
	SigstoreFulcioURL   string // default: https://fulcio.sigstore.dev
	SigstoreTrustedRoot string // optional: path to custom trusted root JSON

	Client client.Client
}

func NewProvider(config *Config) (Provider, error) {
	if config == nil {
		return nil, fmt.Errorf("provider config cannot be nil")
	}

	switch config.Type {
	case ProviderTypeX5C:
		return NewX5CProvider(config)
	case ProviderTypeSigstore:
		return NewSigstoreProvider(config)
	default:
		return nil, fmt.Errorf("unknown provider type: %s (supported: 'x5c', 'sigstore')", config.Type)
	}
}
