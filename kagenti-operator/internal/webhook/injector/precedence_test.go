package injector

import (
	"testing"

	"github.com/kagenti/operator/internal/webhook/config"
)

func allEnabledGates() *config.FeatureGates {
	return config.DefaultFeatureGates()
}

func allEnabledConfig() *config.PlatformConfig {
	return config.CompiledDefaults()
}

func noLabels() map[string]string {
	return map[string]string{}
}

func TestPrecedenceEvaluator(t *testing.T) {
	tests := []struct {
		name             string
		featureGates     *config.FeatureGates
		platformConfig   *config.PlatformConfig
		workloadLabels   map[string]string
		expectEnvoy      bool
		expectProxyInit  bool
		expectSpiffe     bool
		expectClientReg  bool
		expectEnvoyLayer string
	}{
		// === Per-sidecar feature gate tests ===
		{
			name: "per-sidecar gate off - envoy skipped",
			featureGates: &config.FeatureGates{
				GlobalEnabled:      true,
				EnvoyProxy:         false,
				SpiffeHelper:       true,
				ClientRegistration: true,
			},
			platformConfig:   allEnabledConfig(),
			workloadLabels:   noLabels(),
			expectEnvoy:      false,
			expectProxyInit:  false, // follows envoy
			expectSpiffe:     true,
			expectClientReg:  false, // opt-in: no label → not injected
			expectEnvoyLayer: "feature-gate",
		},
		{
			name: "per-sidecar gate off - spiffe skipped",
			featureGates: &config.FeatureGates{
				GlobalEnabled:      true,
				EnvoyProxy:         true,
				SpiffeHelper:       false,
				ClientRegistration: true,
			},
			platformConfig:  allEnabledConfig(),
			workloadLabels:  noLabels(),
			expectEnvoy:     true,
			expectProxyInit: true,
			expectSpiffe:    false,
			expectClientReg: false, // opt-in: no label → not injected
		},
		{
			name: "per-sidecar gate off - client-registration skipped",
			featureGates: &config.FeatureGates{
				GlobalEnabled:      true,
				EnvoyProxy:         true,
				SpiffeHelper:       true,
				ClientRegistration: false,
			},
			platformConfig:  allEnabledConfig(),
			workloadLabels:  noLabels(),
			expectEnvoy:     true,
			expectProxyInit: true,
			expectSpiffe:    true,
			expectClientReg: false,
		},

		// === Workload label tests ===
		{
			name:             "workload label disables envoy - envoy and proxy-init skipped",
			featureGates:     allEnabledGates(),
			platformConfig:   allEnabledConfig(),
			workloadLabels:   map[string]string{LabelEnvoyProxyInject: "false"},
			expectEnvoy:      false,
			expectProxyInit:  false,
			expectSpiffe:     true,
			expectClientReg:  false, // opt-in: no label → not injected
			expectEnvoyLayer: "workload-label",
		},
		{
			name:            "workload label disables spiffe only",
			featureGates:    allEnabledGates(),
			platformConfig:  allEnabledConfig(),
			workloadLabels:  map[string]string{LabelSpiffeHelperInject: "false"},
			expectEnvoy:     true,
			expectProxyInit: true,
			expectSpiffe:    false,
			expectClientReg: false, // opt-in: no label → not injected
		},
		{
			name:            "workload label disables client-registration explicitly",
			featureGates:    allEnabledGates(),
			platformConfig:  allEnabledConfig(),
			workloadLabels:  map[string]string{LabelClientRegistrationInject: "false"},
			expectEnvoy:     true,
			expectProxyInit: true,
			expectSpiffe:    true,
			expectClientReg: false,
		},
		{
			name:            "client-registration label true - opt-in sidecar injected",
			featureGates:    allEnabledGates(),
			platformConfig:  allEnabledConfig(),
			workloadLabels:  map[string]string{LabelClientRegistrationInject: "true"},
			expectEnvoy:     true,
			expectProxyInit: true,
			expectSpiffe:    true,
			expectClientReg: true,
		},
		{
			name:            "workload label true value on envoy - no effect on others",
			featureGates:    allEnabledGates(),
			platformConfig:  allEnabledConfig(),
			workloadLabels:  map[string]string{LabelEnvoyProxyInject: "true"},
			expectEnvoy:     true,
			expectProxyInit: true,
			expectSpiffe:    true,
			expectClientReg: false, // opt-in: no client-reg label → not injected
		},
		{
			name:            "workload labels absent - envoy+spiffe injected, client-reg not (opt-in)",
			featureGates:    allEnabledGates(),
			platformConfig:  allEnabledConfig(),
			workloadLabels:  noLabels(),
			expectEnvoy:     true,
			expectProxyInit: true,
			expectSpiffe:    true,
			expectClientReg: false, // opt-in: default is operator-managed
		},
		{
			name:           "all workload opt-out labels set - all skipped",
			featureGates:   allEnabledGates(),
			platformConfig: allEnabledConfig(),
			workloadLabels: map[string]string{
				LabelEnvoyProxyInject:         "false",
				LabelSpiffeHelperInject:       "false",
				LabelClientRegistrationInject: "false",
			},
			expectEnvoy:      false,
			expectProxyInit:  false,
			expectSpiffe:     false,
			expectClientReg:  false,
			expectEnvoyLayer: "workload-label",
		},
		{
			name:           "all labels opt-in - everything injected",
			featureGates:   allEnabledGates(),
			platformConfig: allEnabledConfig(),
			workloadLabels: map[string]string{
				LabelClientRegistrationInject: "true",
			},
			expectEnvoy:     true,
			expectProxyInit: true,
			expectSpiffe:    true,
			expectClientReg: true,
		},

		// === Precedence ordering: feature gate beats workload label ===
		{
			name: "feature gate off + workload label absent - skipped (gate wins)",
			featureGates: &config.FeatureGates{
				GlobalEnabled:      true,
				EnvoyProxy:         false,
				SpiffeHelper:       true,
				ClientRegistration: true,
			},
			platformConfig:   allEnabledConfig(),
			workloadLabels:   map[string]string{LabelEnvoyProxyInject: "true"},
			expectEnvoy:      false,
			expectProxyInit:  false,
			expectSpiffe:     true,
			expectClientReg:  false, // opt-in: no label → not injected
			expectEnvoyLayer: "feature-gate",
		},
		{
			name: "client-reg feature gate off beats opt-in label",
			featureGates: &config.FeatureGates{
				GlobalEnabled:      true,
				EnvoyProxy:         true,
				SpiffeHelper:       true,
				ClientRegistration: false,
			},
			platformConfig:  allEnabledConfig(),
			workloadLabels:  map[string]string{LabelClientRegistrationInject: "true"},
			expectEnvoy:     true,
			expectProxyInit: true,
			expectSpiffe:    true,
			expectClientReg: false, // gate off overrides opt-in label
		},
		{
			name:             "all gates pass, no client-reg label - envoy+spiffe injected",
			featureGates:     allEnabledGates(),
			platformConfig:   allEnabledConfig(),
			workloadLabels:   noLabels(),
			expectEnvoy:      true,
			expectProxyInit:  true,
			expectSpiffe:     true,
			expectClientReg:  false, // opt-in: default is not injected
			expectEnvoyLayer: "default",
		},

		// === proxy-init coupling tests ===
		{
			name: "envoy skipped via feature gate - proxy-init also skipped",
			featureGates: &config.FeatureGates{
				GlobalEnabled:      true,
				EnvoyProxy:         false,
				SpiffeHelper:       true,
				ClientRegistration: true,
			},
			platformConfig:  allEnabledConfig(),
			workloadLabels:  noLabels(),
			expectEnvoy:     false,
			expectProxyInit: false,
			expectSpiffe:    true,
			expectClientReg: false, // opt-in: no label
		},
		{
			name:            "envoy skipped via workload label - proxy-init also skipped",
			featureGates:    allEnabledGates(),
			platformConfig:  allEnabledConfig(),
			workloadLabels:  map[string]string{LabelEnvoyProxyInject: "false"},
			expectEnvoy:     false,
			expectProxyInit: false,
			expectSpiffe:    true,
			expectClientReg: false, // opt-in: no label
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := NewPrecedenceEvaluator(tt.featureGates, tt.platformConfig)
			decision := evaluator.Evaluate(tt.workloadLabels)

			if decision.EnvoyProxy.Inject != tt.expectEnvoy {
				t.Errorf("EnvoyProxy.Inject = %v, want %v (reason: %s, layer: %s)",
					decision.EnvoyProxy.Inject, tt.expectEnvoy,
					decision.EnvoyProxy.Reason, decision.EnvoyProxy.Layer)
			}
			if decision.ProxyInit.Inject != tt.expectProxyInit {
				t.Errorf("ProxyInit.Inject = %v, want %v (reason: %s, layer: %s)",
					decision.ProxyInit.Inject, tt.expectProxyInit,
					decision.ProxyInit.Reason, decision.ProxyInit.Layer)
			}
			if decision.SpiffeHelper.Inject != tt.expectSpiffe {
				t.Errorf("SpiffeHelper.Inject = %v, want %v (reason: %s, layer: %s)",
					decision.SpiffeHelper.Inject, tt.expectSpiffe,
					decision.SpiffeHelper.Reason, decision.SpiffeHelper.Layer)
			}
			if decision.ClientRegistration.Inject != tt.expectClientReg {
				t.Errorf("ClientRegistration.Inject = %v, want %v (reason: %s, layer: %s)",
					decision.ClientRegistration.Inject, tt.expectClientReg,
					decision.ClientRegistration.Reason, decision.ClientRegistration.Layer)
			}
			if tt.expectEnvoyLayer != "" && decision.EnvoyProxy.Layer != tt.expectEnvoyLayer {
				t.Errorf("EnvoyProxy.Layer = %q, want %q", decision.EnvoyProxy.Layer, tt.expectEnvoyLayer)
			}
		})
	}
}

func TestAnyInjected(t *testing.T) {
	tests := []struct {
		name     string
		decision InjectionDecision
		want     bool
	}{
		{
			name: "all injected",
			decision: InjectionDecision{
				EnvoyProxy:         SidecarDecision{Inject: true},
				SpiffeHelper:       SidecarDecision{Inject: true},
				ClientRegistration: SidecarDecision{Inject: true},
			},
			want: true,
		},
		{
			name: "only envoy injected",
			decision: InjectionDecision{
				EnvoyProxy:         SidecarDecision{Inject: true},
				SpiffeHelper:       SidecarDecision{Inject: false},
				ClientRegistration: SidecarDecision{Inject: false},
			},
			want: true,
		},
		{
			name: "none injected",
			decision: InjectionDecision{
				EnvoyProxy:         SidecarDecision{Inject: false},
				SpiffeHelper:       SidecarDecision{Inject: false},
				ClientRegistration: SidecarDecision{Inject: false},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.decision.AnyInjected(); got != tt.want {
				t.Errorf("AnyInjected() = %v, want %v", got, tt.want)
			}
		})
	}
}
