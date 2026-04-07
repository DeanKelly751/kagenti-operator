package injector

import (
	"github.com/kagenti/operator/internal/webhook/config"
)

const (
	labelValueTrue  = "true"
	labelValueFalse = "false"
)

// PrecedenceEvaluator determines which sidecars should be injected for a workload
// by evaluating a per-sidecar precedence chain. Each layer can short-circuit with "no".
//
// Precedence order (highest to lowest):
//  1. Per-sidecar feature gate (featureGates.<sidecar>=false disables cluster-wide)
//  2. Workload label (kagenti.io/<sidecar>-inject=false) — per-sidecar opt-out
//
// Global and workload-level pre-filtering (globalEnabled kill switch, type check,
// injectTools gate, kagenti.io/inject=disabled opt-out) is handled upstream in
// PodMutator before this evaluator is reached.
type PrecedenceEvaluator struct {
	featureGates *config.FeatureGates
}

// NewPrecedenceEvaluator creates a new evaluator with the given feature gates.
func NewPrecedenceEvaluator(fg *config.FeatureGates) *PrecedenceEvaluator {
	if fg == nil {
		fg = config.DefaultFeatureGates()
	}
	return &PrecedenceEvaluator{
		featureGates: fg,
	}
}

// Evaluate determines which sidecars should be injected for a given workload.
//
// Parameters:
//   - workloadLabels: labels from the pod template or workload metadata
func (e *PrecedenceEvaluator) Evaluate(
	workloadLabels map[string]string,
) InjectionDecision {
	decision := InjectionDecision{
		EnvoyProxy: e.evaluateSidecar(
			"envoy-proxy",
			e.featureGates.EnvoyProxy,
			workloadLabels[LabelEnvoyProxyInject],
		),
		SpiffeHelper: e.evaluateSidecar(
			"spiffe-helper",
			e.featureGates.SpiffeHelper,
			workloadLabels[LabelSpiffeHelperInject],
		),
		ClientRegistration: e.evaluateClientRegistration(
			workloadLabels[LabelClientRegistrationInject],
		),
	}

	// proxy-init always follows envoy-proxy
	decision.ProxyInit = SidecarDecision{
		Inject: decision.EnvoyProxy.Inject,
		Reason: "follows envoy-proxy decision",
		Layer:  decision.EnvoyProxy.Layer,
	}

	return decision
}

// evaluateClientRegistration applies feature gate then opt-in label semantics: the legacy
// client-registration sidecar (or combined authbridge registration slice) injects only when
// kagenti.io/client-registration-inject is exactly "true". Otherwise kagenti-operator is
// expected to register the client and supply credentials via pod template annotation.
func (e *PrecedenceEvaluator) evaluateClientRegistration(workloadLabelValue string) SidecarDecision {
	if !e.featureGates.ClientRegistration {
		return SidecarDecision{
			Inject: false,
			Reason: "client-registration feature gate disabled",
			Layer:  "feature-gate",
		}
	}
	if workloadLabelValue == labelValueTrue {
		return SidecarDecision{
			Inject: true,
			Reason: "workload opted in to legacy client-registration (kagenti.io/client-registration-inject=true)",
			Layer:  "workload-label",
		}
	}
	return SidecarDecision{
		Inject: false,
		Reason: "operator-managed client registration is default; set kagenti.io/client-registration-inject=true for legacy sidecar",
		Layer:  "default",
	}
}

// evaluateSidecar evaluates the two-layer precedence chain for a single sidecar.
func (e *PrecedenceEvaluator) evaluateSidecar(
	sidecarName string,
	featureGateEnabled bool,
	workloadLabelValue string, // "" or "false"
) SidecarDecision {
	// Layer 1: Per-sidecar feature gate
	if !featureGateEnabled {
		return SidecarDecision{
			Inject: false,
			Reason: sidecarName + " feature gate disabled",
			Layer:  "feature-gate",
		}
	}

	// Layer 2: Per-sidecar workload opt-out label
	if workloadLabelValue == labelValueFalse {
		return SidecarDecision{
			Inject: false,
			Reason: "workload label disabled " + sidecarName,
			Layer:  "workload-label",
		}
	}

	return SidecarDecision{
		Inject: true,
		Reason: "all gates passed",
		Layer:  "default",
	}
}
