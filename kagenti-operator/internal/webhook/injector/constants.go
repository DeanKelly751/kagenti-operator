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
