package injector

// Label constants used by the precedence evaluator.
const (
	// Per-sidecar workload labels — set value to "false" to disable injection
	LabelEnvoyProxyInject   = "kagenti.io/envoy-proxy-inject"
	LabelSpiffeHelperInject = "kagenti.io/spiffe-helper-inject"

	// LabelClientRegistrationInject — legacy sidecar opt-in: set to "true" to inject;
	// default is operator-managed Keycloak credentials (no sidecar).
	LabelClientRegistrationInject = "kagenti.io/client-registration-inject"
)

// AuthBridge deployment mode annotation.
// Controls which image variant and injection pattern is used.
const (
	AnnotationAuthBridgeMode = "kagenti.io/authbridge-mode"

	// Mode values
	ModeEnvoySidecar = "envoy-sidecar" // default: iptables + Envoy + ext_proc
	ModeProxySidecar = "proxy-sidecar" // HTTP_PROXY env + lightweight authbridge
	ModeWaypoint     = "waypoint"      // standalone deployment (not injected)

	// Container name for proxy-sidecar mode
	AuthBridgeProxyContainerName = "authbridge-proxy"

	// Identity type constants
	IdentityTypeSpiffe         = "spiffe"
	ClientAuthTypeFederatedJWT = "federated-jwt"
)
