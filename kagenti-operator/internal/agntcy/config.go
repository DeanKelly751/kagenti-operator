package agntcy

// PocOptions is populated from operator flags and passed to the AgntcyPoc reconciler.
// Empty Address/URL fields mean that sub-feature is a no-op (status explains why).
type PocOptions struct {
	// Directory gRPC address (e.g. host:8888) for agntcy/dir. Uses insecure
	// transport when AuthMode is "insecure" or "none" (dev / in-cluster with known network).
	DirAddress  string
	DirAuthMode string
	// Optional HTTP(S) URL for a simple health probe to an identity service
	// (e.g. https://identity.example/healthz). Not a full VC integration.
	IdentityProbeURL string
}
