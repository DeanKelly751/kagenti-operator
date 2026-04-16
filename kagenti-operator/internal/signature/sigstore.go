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
	"bytes"
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/verify"
	tuffetcher "github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

// SigstoreConfig configures public-good or custom-trust-root Sigstore verification.
type SigstoreConfig struct {
	CertificateIdentity   string
	CertificateOIDCIssuer string
	// TrustRootJSON is optional Sigstore trusted root JSON (protobuf JSON). When nil, the public TUF repo is used.
	TrustRootJSON []byte
}

type sigstoreVerifier struct {
	cfg             SigstoreConfig
	trustedMaterial root.TrustedMaterial
	trustOnce       sync.Once
	trustErr        error
}

// NewSigstoreVerifier returns a BundleVerifier backed by sigstore-go.
func NewSigstoreVerifier(cfg *SigstoreConfig) (BundleVerifier, error) {
	if cfg == nil {
		return nil, fmt.Errorf("sigstore config cannot be nil")
	}
	if cfg.CertificateIdentity == "" || cfg.CertificateOIDCIssuer == "" {
		return nil, fmt.Errorf("sigstore certificate identity and OIDC issuer are required")
	}
	return &sigstoreVerifier{cfg: *cfg}, nil
}

func (s *sigstoreVerifier) Name() string {
	return "sigstore"
}

func (s *sigstoreVerifier) ensureTrust(ctx context.Context) error {
	_ = ctx
	s.trustOnce.Do(func() {
		if len(s.cfg.TrustRootJSON) > 0 {
			var tr *root.TrustedRoot
			tr, s.trustErr = root.NewTrustedRootFromJSON(s.cfg.TrustRootJSON)
			if s.trustErr != nil {
				return
			}
			s.trustedMaterial = tr
			return
		}
		opts := tuf.DefaultOptions()
		opts.DisableLocalCache = true
		f := tuffetcher.NewDefaultFetcher()
		f.SetHTTPUserAgent(util.ConstructUserAgent())
		opts.Fetcher = f
		client, err := tuf.New(opts)
		if err != nil {
			s.trustErr = err
			return
		}
		jsonBytes, err := client.GetTarget("trusted_root.json")
		if err != nil {
			s.trustErr = err
			return
		}
		var tr *root.TrustedRoot
		tr, s.trustErr = root.NewTrustedRootFromJSON(jsonBytes)
		if s.trustErr != nil {
			return
		}
		s.trustedMaterial = tr
	})
	return s.trustErr
}

func (s *sigstoreVerifier) VerifyBundle(ctx context.Context, artifactBytes, bundleBytes []byte, certificateIdentity, certificateOIDCIssuer string) (*VerificationResult, error) {
	b := &bundle.Bundle{}
	if err := b.UnmarshalJSON(bundleBytes); err != nil {
		return &VerificationResult{
			Verified: false,
			Details:  fmt.Sprintf("invalid sigstore bundle: %v", err),
		}, nil
	}
	if err := s.ensureTrust(ctx); err != nil {
		return nil, err
	}
	tr := s.trustedMaterial
	opts := []verify.VerifierOption{verify.WithSignedCertificateTimestamps(1)}
	ts, _ := b.Timestamps()
	if len(tr.TimestampingAuthorities()) > 0 && len(ts) > 0 {
		opts = append(opts, verify.WithSignedTimestamps(1))
	}
	if len(tr.RekorLogs()) > 0 {
		opts = append(opts, verify.WithTransparencyLog(1))
		if b.HasInclusionPromise() {
			opts = append(opts, verify.WithIntegratedTimestamps(1))
		}
	}
	v, err := verify.NewVerifier(tr, opts...)
	if err != nil {
		return nil, fmt.Errorf("sigstore verifier: %w", err)
	}
	id, iss := s.cfg.CertificateIdentity, s.cfg.CertificateOIDCIssuer
	if certificateIdentity != "" {
		id = certificateIdentity
	}
	if certificateOIDCIssuer != "" {
		iss = certificateOIDCIssuer
	}
	certID, err := verify.NewShortCertificateIdentity(iss, "", id, "")
	if err != nil {
		return nil, err
	}
	pol := verify.NewPolicy(verify.WithArtifact(bytes.NewReader(artifactBytes)), verify.WithCertificateIdentity(certID))
	libRes, err := v.Verify(b, pol)
	if err != nil {
		return &VerificationResult{
			Verified: false,
			Details:  err.Error(),
		}, nil
	}
	out := &VerificationResult{
		Verified: true,
		Details:  "sigstore bundle verified",
	}
	if libRes.VerifiedIdentity != nil {
		out.SigstoreCertificateIdentity = libRes.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName
	}
	if entries, err := b.TlogEntries(); err == nil && len(entries) > 0 {
		out.RekorLogIndex = strconv.FormatInt(entries[0].LogIndex(), 10)
	}
	return out, nil
}
