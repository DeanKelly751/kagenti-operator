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

package injector

import (
	"context"
	"testing"

	agentv1alpha1 "github.com/kagenti/operator/api/v1alpha1"
	"github.com/kagenti/operator/internal/webhook/config"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// newAgentRuntime creates a minimal AgentRuntime CR targeting the given workload name.
func newAgentRuntime(namespace, targetName string) *agentv1alpha1.AgentRuntime {
	return &agentv1alpha1.AgentRuntime{
		ObjectMeta: metav1.ObjectMeta{
			Name:      targetName + "-runtime",
			Namespace: namespace,
		},
		Spec: agentv1alpha1.AgentRuntimeSpec{
			Type: agentv1alpha1.RuntimeTypeAgent,
			TargetRef: agentv1alpha1.TargetRef{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       targetName,
			},
		},
	}
}

func newTestMutator(objs ...client.Object) *PodMutator {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = agentv1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	return &PodMutator{
		Client:                   fakeClient,
		EnableClientRegistration: true,
		GetPlatformConfig:        config.CompiledDefaults,
		GetFeatureGates:          config.DefaultFeatureGates,
	}
}

func TestEnsureServiceAccount_CreatesNew(t *testing.T) {
	m := newTestMutator()
	ctx := context.Background()

	if err := m.ensureServiceAccount(ctx, "test-ns", "my-agent"); err != nil {
		t.Fatalf("ensureServiceAccount() returned error: %v", err)
	}

	sa := &corev1.ServiceAccount{}
	if err := m.Client.Get(ctx, client.ObjectKey{Namespace: "test-ns", Name: "my-agent"}, sa); err != nil {
		t.Fatalf("expected ServiceAccount to be created, got error: %v", err)
	}
	if sa.Labels[managedByLabel] != managedByValue {
		t.Errorf("expected label %s=%s, got %s", managedByLabel, managedByValue, sa.Labels[managedByLabel])
	}
}

func TestEnsureServiceAccount_AlreadyExistsWithLabel(t *testing.T) {
	existing := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-agent",
			Namespace: "test-ns",
			Labels:    map[string]string{managedByLabel: managedByValue},
		},
	}
	m := newTestMutator(existing)
	ctx := context.Background()

	if err := m.ensureServiceAccount(ctx, "test-ns", "my-agent"); err != nil {
		t.Fatalf("ensureServiceAccount() returned error: %v", err)
	}
}

func TestEnsureServiceAccount_AlreadyExistsWithoutLabel(t *testing.T) {
	existing := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-agent",
			Namespace: "test-ns",
			Labels:    map[string]string{"app": "something-else"},
		},
	}
	m := newTestMutator(existing)
	ctx := context.Background()

	// Should still succeed (returns nil) but logs a warning internally.
	if err := m.ensureServiceAccount(ctx, "test-ns", "my-agent"); err != nil {
		t.Fatalf("ensureServiceAccount() returned error: %v", err)
	}

	sa := &corev1.ServiceAccount{}
	if err := m.Client.Get(ctx, client.ObjectKey{Namespace: "test-ns", Name: "my-agent"}, sa); err != nil {
		t.Fatalf("expected ServiceAccount to still exist, got error: %v", err)
	}
	if sa.Labels[managedByLabel] == managedByValue {
		t.Error("existing SA should NOT have been updated with the managed-by label")
	}
}

func TestEnsureServiceAccount_AlreadyExistsNoLabels(t *testing.T) {
	existing := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-agent",
			Namespace: "test-ns",
		},
	}
	m := newTestMutator(existing)
	ctx := context.Background()

	if err := m.ensureServiceAccount(ctx, "test-ns", "my-agent"); err != nil {
		t.Fatalf("ensureServiceAccount() returned error: %v", err)
	}
}

func TestInjectAuthBridge_NoAgentRuntime_InjectsWithDefaults(t *testing.T) {
	// Agent pod with correct labels but no AgentRuntime CR → inject with
	// defaults-only config (platform + namespace defaults, no CR overrides).
	m := newTestMutator()
	ctx := context.Background()

	podSpec := &corev1.PodSpec{}
	labels := map[string]string{
		KagentiTypeLabel: KagentiTypeAgent,
	}

	injected, err := m.InjectAuthBridge(ctx, podSpec, "test-ns", "my-agent", labels, nil)
	if err != nil {
		t.Fatalf("InjectAuthBridge() returned error: %v", err)
	}
	if !injected {
		t.Fatal("expected InjectAuthBridge to return true with defaults-only config")
	}

	// Verify specific sidecar containers are present
	if !containerExists(podSpec.Containers, EnvoyProxyContainerName) {
		t.Errorf("expected %s container to be injected", EnvoyProxyContainerName)
	}
	if !containerExists(podSpec.Containers, SpiffeHelperContainerName) {
		t.Errorf("expected %s container to be injected", SpiffeHelperContainerName)
	}
	if !containerExists(podSpec.InitContainers, ProxyInitContainerName) {
		t.Errorf("expected %s init container to be injected", ProxyInitContainerName)
	}
}

func TestInjectAuthBridge_SetsServiceAccountName(t *testing.T) {
	// Opt-out model: agent workloads are injected by default (no inject label needed).
	m := newTestMutator(newAgentRuntime("test-ns", "my-agent"))
	ctx := context.Background()

	podSpec := &corev1.PodSpec{}
	labels := map[string]string{
		KagentiTypeLabel: KagentiTypeAgent,
	}

	injected, err := m.InjectAuthBridge(ctx, podSpec, "test-ns", "my-agent", labels, nil)
	if err != nil {
		t.Fatalf("InjectAuthBridge() returned error: %v", err)
	}
	if !injected {
		t.Fatal("expected InjectAuthBridge to return true")
	}
	if podSpec.ServiceAccountName != "my-agent" {
		t.Errorf("expected ServiceAccountName=%q, got %q", "my-agent", podSpec.ServiceAccountName)
	}

	sa := &corev1.ServiceAccount{}
	if err := m.Client.Get(ctx, client.ObjectKey{Namespace: "test-ns", Name: "my-agent"}, sa); err != nil {
		t.Fatalf("expected ServiceAccount to be created, got error: %v", err)
	}
}

func TestInjectAuthBridge_RespectsExistingServiceAccountName(t *testing.T) {
	m := newTestMutator(newAgentRuntime("test-ns", "my-agent"))
	ctx := context.Background()

	podSpec := &corev1.PodSpec{
		ServiceAccountName: "custom-sa",
	}
	labels := map[string]string{
		KagentiTypeLabel: KagentiTypeAgent,
	}

	injected, err := m.InjectAuthBridge(ctx, podSpec, "test-ns", "my-agent", labels, nil)
	if err != nil {
		t.Fatalf("InjectAuthBridge() returned error: %v", err)
	}
	if !injected {
		t.Fatal("expected InjectAuthBridge to return true")
	}
	if podSpec.ServiceAccountName != "custom-sa" {
		t.Errorf("expected ServiceAccountName to remain %q, got %q", "custom-sa", podSpec.ServiceAccountName)
	}
}

func TestInjectAuthBridge_NoSACreationWhenSpiffeHelperDisabled(t *testing.T) {
	// Spiffe-helper is injected by default for agents. SA creation is skipped
	// when spiffe-helper is explicitly opted out via its per-sidecar label.
	m := newTestMutator(newAgentRuntime("test-ns", "my-agent"))
	ctx := context.Background()

	podSpec := &corev1.PodSpec{}
	labels := map[string]string{
		KagentiTypeLabel:        KagentiTypeAgent,
		LabelSpiffeHelperInject: "false", // explicitly opt out of spiffe-helper
	}

	injected, err := m.InjectAuthBridge(ctx, podSpec, "test-ns", "my-agent", labels, nil)
	if err != nil {
		t.Fatalf("InjectAuthBridge() returned error: %v", err)
	}
	if !injected {
		t.Fatal("expected InjectAuthBridge to return true (other sidecars still inject)")
	}
	if podSpec.ServiceAccountName != "" {
		t.Errorf("expected ServiceAccountName to be empty when spiffe-helper is disabled, got %q", podSpec.ServiceAccountName)
	}

	sa := &corev1.ServiceAccount{}
	err = m.Client.Get(ctx, client.ObjectKey{Namespace: "test-ns", Name: "my-agent"}, sa)
	if err == nil {
		t.Error("expected ServiceAccount to NOT be created when spiffe-helper is disabled")
	}
}

func TestInjectAuthBridge_Tool_SkipsInjectionByDefault(t *testing.T) {
	// Tool workloads are not injected by default — the injectTools feature gate
	// is false unless explicitly enabled. No inject label needed to confirm this.
	m := newTestMutator()
	ctx := context.Background()

	podSpec := &corev1.PodSpec{}
	labels := map[string]string{
		KagentiTypeLabel: KagentiTypeTool,
	}

	injected, err := m.InjectAuthBridge(ctx, podSpec, "test-ns", "my-tool", labels, nil)
	if err != nil {
		t.Fatalf("InjectAuthBridge() returned error: %v", err)
	}
	if injected {
		t.Fatal("expected InjectAuthBridge to return false: injectTools gate is false by default")
	}
	if len(podSpec.Containers) != 0 || len(podSpec.InitContainers) != 0 {
		t.Errorf("expected no containers injected, got containers=%v initContainers=%v",
			podSpec.Containers, podSpec.InitContainers)
	}
}

func TestInjectAuthBridge_GlobalOptOut_Agent(t *testing.T) {
	// Agent workloads are injected by default; kagenti.io/inject=disabled opts out.
	m := newTestMutator()
	ctx := context.Background()

	podSpec := &corev1.PodSpec{}
	labels := map[string]string{
		KagentiTypeLabel:      KagentiTypeAgent,
		AuthBridgeInjectLabel: AuthBridgeDisabledValue,
	}

	injected, err := m.InjectAuthBridge(ctx, podSpec, "test-ns", "my-agent", labels, nil)
	if err != nil {
		t.Fatalf("InjectAuthBridge() returned error: %v", err)
	}
	if injected {
		t.Fatal("expected InjectAuthBridge to return false when kagenti.io/inject=disabled")
	}
	if len(podSpec.Containers) != 0 || len(podSpec.InitContainers) != 0 {
		t.Errorf("expected no containers to be injected, got containers=%v initContainers=%v",
			podSpec.Containers, podSpec.InitContainers)
	}
}

func TestInjectAuthBridge_Tool_SkippedByGateRegardlessOfOptOut(t *testing.T) {
	// Tool workloads are blocked by the injectTools gate (false by default)
	// before the opt-out label is even evaluated.
	m := newTestMutator()
	ctx := context.Background()

	podSpec := &corev1.PodSpec{}
	labels := map[string]string{
		KagentiTypeLabel:      KagentiTypeTool,
		AuthBridgeInjectLabel: AuthBridgeDisabledValue,
	}

	injected, err := m.InjectAuthBridge(ctx, podSpec, "test-ns", "my-tool", labels, nil)
	if err != nil {
		t.Fatalf("InjectAuthBridge() returned error: %v", err)
	}
	if injected {
		t.Fatal("expected InjectAuthBridge to return false: tool blocked by injectTools gate")
	}
	if len(podSpec.Containers) != 0 || len(podSpec.InitContainers) != 0 {
		t.Errorf("expected no containers to be injected, got containers=%v initContainers=%v",
			podSpec.Containers, podSpec.InitContainers)
	}
}

func TestInjectAuthBridge_DefaultSAOverridden(t *testing.T) {
	m := newTestMutator(newAgentRuntime("test-ns", "my-agent"))
	ctx := context.Background()

	podSpec := &corev1.PodSpec{
		ServiceAccountName: "default",
	}
	labels := map[string]string{
		KagentiTypeLabel: KagentiTypeAgent,
	}

	injected, err := m.InjectAuthBridge(ctx, podSpec, "test-ns", "my-agent", labels, nil)
	if err != nil {
		t.Fatalf("InjectAuthBridge() returned error: %v", err)
	}
	if !injected {
		t.Fatal("expected InjectAuthBridge to return true")
	}
	if podSpec.ServiceAccountName != "my-agent" {
		t.Errorf("expected ServiceAccountName=%q (overriding 'default'), got %q", "my-agent", podSpec.ServiceAccountName)
	}
}

func TestInjectAuthBridge_OutboundPortsExcludeAnnotation(t *testing.T) {
	m := newTestMutator(newAgentRuntime("test-ns", "my-agent"))
	ctx := context.Background()

	podSpec := &corev1.PodSpec{}
	labels := map[string]string{
		KagentiTypeLabel: KagentiTypeAgent,
	}
	annotations := map[string]string{
		OutboundPortsExcludeAnnotation: "11434",
	}

	injected, err := m.InjectAuthBridge(ctx, podSpec, "test-ns", "my-agent", labels, annotations)
	if err != nil {
		t.Fatalf("InjectAuthBridge() returned error: %v", err)
	}
	if !injected {
		t.Fatal("expected InjectAuthBridge to return true")
	}

	for _, ic := range podSpec.InitContainers {
		if ic.Name != ProxyInitContainerName {
			continue
		}
		for _, env := range ic.Env {
			if env.Name == "OUTBOUND_PORTS_EXCLUDE" {
				if env.Value != "8080,11434" {
					t.Errorf("OUTBOUND_PORTS_EXCLUDE = %q, want %q", env.Value, "8080,11434")
				}
				return
			}
		}
		t.Fatal("proxy-init container missing OUTBOUND_PORTS_EXCLUDE env var")
	}
	t.Fatal("proxy-init container not found in initContainers")
}

func TestInjectAuthBridge_InboundPortsExcludeAnnotation(t *testing.T) {
	m := newTestMutator(newAgentRuntime("test-ns", "my-agent"))
	ctx := context.Background()

	podSpec := &corev1.PodSpec{}
	labels := map[string]string{
		KagentiTypeLabel: KagentiTypeAgent,
	}
	annotations := map[string]string{
		OutboundPortsExcludeAnnotation: "11434",
		InboundPortsExcludeAnnotation:  "8443,18789",
	}

	injected, err := m.InjectAuthBridge(ctx, podSpec, "test-ns", "my-agent", labels, annotations)
	if err != nil {
		t.Fatalf("InjectAuthBridge() returned error: %v", err)
	}
	if !injected {
		t.Fatal("expected InjectAuthBridge to return true")
	}

	for _, ic := range podSpec.InitContainers {
		if ic.Name != ProxyInitContainerName {
			continue
		}
		var foundOutbound, foundInbound bool
		for _, env := range ic.Env {
			if env.Name == "OUTBOUND_PORTS_EXCLUDE" {
				foundOutbound = true
				if env.Value != "8080,11434" {
					t.Errorf("OUTBOUND_PORTS_EXCLUDE = %q, want %q", env.Value, "8080,11434")
				}
			}
			if env.Name == "INBOUND_PORTS_EXCLUDE" {
				foundInbound = true
				if env.Value != "8443,18789" {
					t.Errorf("INBOUND_PORTS_EXCLUDE = %q, want %q", env.Value, "8443,18789")
				}
			}
		}
		if !foundOutbound {
			t.Fatal("proxy-init container missing OUTBOUND_PORTS_EXCLUDE env var")
		}
		if !foundInbound {
			t.Fatal("proxy-init container missing INBOUND_PORTS_EXCLUDE env var")
		}
		return
	}
	t.Fatal("proxy-init container not found in initContainers")
}

// ========================================
// Combined sidecar mode tests
// ========================================

func newTestMutatorWithCombinedSidecar(objs ...client.Object) *PodMutator {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = agentv1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	return &PodMutator{
		Client:                   fakeClient,
		EnableClientRegistration: true,
		GetPlatformConfig:        config.CompiledDefaults,
		GetFeatureGates: func() *config.FeatureGates {
			fg := config.DefaultFeatureGates()
			fg.CombinedSidecar = true
			return fg
		},
	}
}

func TestInjectAuthBridge_CombinedMode_SingleContainer(t *testing.T) {
	m := newTestMutatorWithCombinedSidecar(newAgentRuntime("test-ns", "my-agent"))
	ctx := context.Background()

	podSpec := &corev1.PodSpec{}
	labels := map[string]string{
		KagentiTypeLabel: KagentiTypeAgent,
	}

	injected, err := m.InjectAuthBridge(ctx, podSpec, "test-ns", "my-agent", labels, nil)
	if err != nil {
		t.Fatalf("InjectAuthBridge() returned error: %v", err)
	}
	if !injected {
		t.Fatal("expected InjectAuthBridge to return true")
	}

	// Should have exactly 1 sidecar container (authbridge) — NOT envoy-proxy, spiffe-helper, or client-registration
	if !containerExists(podSpec.Containers, AuthBridgeContainerName) {
		t.Error("expected authbridge container to be injected")
	}
	if containerExists(podSpec.Containers, EnvoyProxyContainerName) {
		t.Error("unexpected envoy-proxy container in combined mode")
	}
	if containerExists(podSpec.Containers, SpiffeHelperContainerName) {
		t.Error("unexpected spiffe-helper container in combined mode")
	}
	if containerExists(podSpec.Containers, ClientRegistrationContainerName) {
		t.Error("unexpected client-registration container in combined mode")
	}

	// Should still have proxy-init
	if !containerExists(podSpec.InitContainers, ProxyInitContainerName) {
		t.Error("expected proxy-init init container to be injected")
	}
}

func TestInjectAuthBridge_CombinedMode_EnvoyDisabled_NoInjection(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = agentv1alpha1.AddToScheme(scheme)
	ar := newAgentRuntime("test-ns", "my-agent")
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ar).Build()
	m := &PodMutator{
		Client:                   fakeClient,
		EnableClientRegistration: true,
		GetPlatformConfig:        config.CompiledDefaults,
		GetFeatureGates: func() *config.FeatureGates {
			fg := config.DefaultFeatureGates()
			fg.CombinedSidecar = true
			fg.EnvoyProxy = false
			return fg
		},
	}
	ctx := context.Background()

	podSpec := &corev1.PodSpec{}
	labels := map[string]string{
		KagentiTypeLabel: KagentiTypeAgent,
	}

	injected, err := m.InjectAuthBridge(ctx, podSpec, "test-ns", "my-agent", labels, nil)
	if err != nil {
		t.Fatalf("InjectAuthBridge() returned error: %v", err)
	}
	// With envoy-proxy disabled, the combined container should NOT be present
	if containerExists(podSpec.Containers, AuthBridgeContainerName) {
		t.Error("authbridge container should not be injected when envoy-proxy is disabled")
	}
	_ = injected
}

func TestInjectAuthBridge_CombinedMode_SpiffeDisabled_FlagPassed(t *testing.T) {
	m := newTestMutatorWithCombinedSidecar(newAgentRuntime("test-ns", "my-agent"))
	ctx := context.Background()

	podSpec := &corev1.PodSpec{}
	labels := map[string]string{
		KagentiTypeLabel:        KagentiTypeAgent,
		LabelSpiffeHelperInject: "false",
	}

	injected, err := m.InjectAuthBridge(ctx, podSpec, "test-ns", "my-agent", labels, nil)
	if err != nil {
		t.Fatalf("InjectAuthBridge() returned error: %v", err)
	}
	if !injected {
		t.Fatal("expected InjectAuthBridge to return true")
	}

	// authbridge container should be present with SPIRE_ENABLED=false
	if !containerExists(podSpec.Containers, AuthBridgeContainerName) {
		t.Fatal("expected authbridge container to be injected")
	}

	for _, c := range podSpec.Containers {
		if c.Name != AuthBridgeContainerName {
			continue
		}
		for _, env := range c.Env {
			if env.Name == "SPIRE_ENABLED" {
				if env.Value != "false" {
					t.Errorf("SPIRE_ENABLED = %q, want %q", env.Value, "false")
				}
				return
			}
		}
		t.Fatal("missing SPIRE_ENABLED env var on authbridge container")
	}
}

func TestInjectAuthBridge_CombinedMode_Idempotency(t *testing.T) {
	m := newTestMutatorWithCombinedSidecar(newAgentRuntime("test-ns", "my-agent"))
	ctx := context.Background()

	podSpec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: AuthBridgeContainerName, Image: "authbridge:test"},
		},
	}
	labels := map[string]string{
		KagentiTypeLabel: KagentiTypeAgent,
	}

	injected, err := m.InjectAuthBridge(ctx, podSpec, "test-ns", "my-agent", labels, nil)
	if err != nil {
		t.Fatalf("InjectAuthBridge() returned error: %v", err)
	}
	if !injected {
		t.Fatal("expected InjectAuthBridge to return true")
	}

	// Should still be exactly 1 authbridge container
	count := 0
	for _, c := range podSpec.Containers {
		if c.Name == AuthBridgeContainerName {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 authbridge container, got %d", count)
	}
}

func TestInjectAuthBridge_NilAnnotations(t *testing.T) {
	m := newTestMutator(newAgentRuntime("test-ns", "my-agent"))
	ctx := context.Background()

	podSpec := &corev1.PodSpec{}
	labels := map[string]string{
		KagentiTypeLabel: KagentiTypeAgent,
	}

	injected, err := m.InjectAuthBridge(ctx, podSpec, "test-ns", "my-agent", labels, nil)
	if err != nil {
		t.Fatalf("InjectAuthBridge() returned error: %v", err)
	}
	if !injected {
		t.Fatal("expected InjectAuthBridge to return true")
	}

	for _, ic := range podSpec.InitContainers {
		if ic.Name != ProxyInitContainerName {
			continue
		}
		for _, env := range ic.Env {
			if env.Name == "OUTBOUND_PORTS_EXCLUDE" {
				if env.Value != "8080" {
					t.Errorf("OUTBOUND_PORTS_EXCLUDE = %q, want %q (nil annotations should default to 8080 only)", env.Value, "8080")
				}
				return
			}
		}
		t.Fatal("proxy-init container missing OUTBOUND_PORTS_EXCLUDE env var")
	}
	t.Fatal("proxy-init container not found in initContainers")
}

// ========================================
// Mode-aware injection tests
// ========================================

func TestInjectAuthBridge_WaypointMode_SkipsInjection(t *testing.T) {
	m := newTestMutator()
	ctx := context.Background()

	podSpec := &corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "agent", Image: "my-agent:latest"},
		},
	}
	labels := map[string]string{
		KagentiTypeLabel: KagentiTypeAgent,
	}
	annotations := map[string]string{
		AnnotationAuthBridgeMode: ModeWaypoint,
	}

	mutated, err := m.InjectAuthBridge(ctx, podSpec, "team1", "my-agent", labels, annotations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mutated {
		t.Error("waypoint mode should not mutate the pod (returns false)")
	}
	if len(podSpec.Containers) != 1 {
		t.Errorf("expected 1 container (agent only), got %d", len(podSpec.Containers))
	}
}

func TestInjectAuthBridge_ProxySidecarMode_InjectsCorrectly(t *testing.T) {
	m := newTestMutator()
	ctx := context.Background()

	podSpec := &corev1.PodSpec{
		ServiceAccountName: "my-agent",
		Containers: []corev1.Container{
			{Name: "agent", Image: "my-agent:latest"},
		},
	}
	labels := map[string]string{
		KagentiTypeLabel: KagentiTypeAgent,
	}
	annotations := map[string]string{
		AnnotationAuthBridgeMode: ModeProxySidecar,
	}

	mutated, err := m.InjectAuthBridge(ctx, podSpec, "team1", "my-agent", labels, annotations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mutated {
		t.Error("proxy-sidecar mode should mutate the pod")
	}

	// Should have authbridge-proxy container
	proxyFound := false
	for _, c := range podSpec.Containers {
		if c.Name == AuthBridgeProxyContainerName {
			proxyFound = true
			if c.Image != config.CompiledDefaults().Images.AuthBridgeLight {
				t.Errorf("proxy container image = %q, want authbridge-light", c.Image)
			}
		}
	}
	if !proxyFound {
		t.Error("authbridge-proxy container not found")
	}

	// Should NOT have proxy-init (no iptables in proxy-sidecar mode)
	for _, c := range podSpec.InitContainers {
		if c.Name == ProxyInitContainerName {
			t.Error("proxy-init should not be injected in proxy-sidecar mode")
		}
	}

	// Should NOT have envoy-proxy container
	for _, c := range podSpec.Containers {
		if c.Name == EnvoyProxyContainerName {
			t.Error("envoy-proxy should not be injected in proxy-sidecar mode")
		}
	}

	// Agent container should have HTTP_PROXY env vars
	for _, c := range podSpec.Containers {
		if c.Name == "agent" {
			httpProxy := ""
			httpsProxy := ""
			noProxy := ""
			for _, env := range c.Env {
				switch env.Name {
				case "HTTP_PROXY":
					httpProxy = env.Value
				case "HTTPS_PROXY":
					httpsProxy = env.Value
				case "NO_PROXY":
					noProxy = env.Value
				}
			}
			if httpProxy != "http://127.0.0.1:8081" {
				t.Errorf("HTTP_PROXY = %q, want http://127.0.0.1:8081", httpProxy)
			}
			if httpsProxy != "http://127.0.0.1:8081" {
				t.Errorf("HTTPS_PROXY = %q, want http://127.0.0.1:8081", httpsProxy)
			}
			if noProxy != "127.0.0.1,localhost" {
				t.Errorf("NO_PROXY = %q, want 127.0.0.1,localhost", noProxy)
			}
		}
	}
}

func TestInjectHTTPProxyEnv_DoesNotDuplicate(t *testing.T) {
	c := &corev1.Container{
		Name: "agent",
		Env: []corev1.EnvVar{
			{Name: "HTTP_PROXY", Value: "http://existing-proxy:3128"},
		},
	}

	injectHTTPProxyEnv(c, 8081)

	count := 0
	for _, env := range c.Env {
		if env.Name == "HTTP_PROXY" {
			count++
			if env.Value != "http://existing-proxy:3128" {
				t.Errorf("HTTP_PROXY should keep existing value, got %q", env.Value)
			}
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 HTTP_PROXY env var, got %d", count)
	}

	// HTTPS_PROXY and NO_PROXY should be added since they didn't exist
	httpsFound := false
	noProxyFound := false
	for _, env := range c.Env {
		if env.Name == "HTTPS_PROXY" {
			httpsFound = true
		}
		if env.Name == "NO_PROXY" {
			noProxyFound = true
		}
	}
	if !httpsFound {
		t.Error("HTTPS_PROXY should be added")
	}
	if !noProxyFound {
		t.Error("NO_PROXY should be added")
	}
}

func TestInjectAuthBridge_ProxySidecarMode_PortCollision(t *testing.T) {
	m := newTestMutator()
	ctx := context.Background()

	// Agent uses ports 8000 and 8001 — agent should move to 8002, not 8001
	podSpec := &corev1.PodSpec{
		ServiceAccountName: "my-agent",
		Containers: []corev1.Container{
			{
				Name:  "agent",
				Image: "my-agent:latest",
				Ports: []corev1.ContainerPort{
					{Name: "http", ContainerPort: 8000},
					{Name: "grpc", ContainerPort: 8001},
				},
			},
		},
	}
	labels := map[string]string{
		KagentiTypeLabel: KagentiTypeAgent,
	}
	annotations := map[string]string{
		AnnotationAuthBridgeMode: ModeProxySidecar,
	}

	mutated, err := m.InjectAuthBridge(ctx, podSpec, "team1", "my-agent", labels, annotations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mutated {
		t.Fatal("expected mutation")
	}

	// Agent's first port should be moved past 8001 to 8002
	for _, c := range podSpec.Containers {
		if c.Name == "agent" {
			if c.Ports[0].ContainerPort == 8001 {
				t.Error("agent port should not be 8001 (collision with gRPC port)")
			}
			if c.Ports[0].ContainerPort != 8002 {
				t.Errorf("agent port = %d, want 8002 (first free port after 8000)", c.Ports[0].ContainerPort)
			}
			// Second port (gRPC) should be unchanged
			if c.Ports[1].ContainerPort != 8001 {
				t.Errorf("gRPC port should remain 8001, got %d", c.Ports[1].ContainerPort)
			}
		}
	}

	// Reverse proxy should be on 8000 (original agent port)
	for _, c := range podSpec.Containers {
		if c.Name == AuthBridgeProxyContainerName {
			for _, p := range c.Ports {
				if p.Name == "reverse-proxy" && p.ContainerPort != 8000 {
					t.Errorf("reverse-proxy port = %d, want 8000", p.ContainerPort)
				}
			}
		}
	}
}

func TestInjectAuthBridge_ProxySidecarMode_ForwardProxyCollision(t *testing.T) {
	m := newTestMutator()
	ctx := context.Background()

	// Agent uses port 8081 — forward proxy should use 8082 instead of default 8081
	podSpec := &corev1.PodSpec{
		ServiceAccountName: "my-agent",
		Containers: []corev1.Container{
			{
				Name:  "agent",
				Image: "my-agent:latest",
				Ports: []corev1.ContainerPort{
					{Name: "http", ContainerPort: 8000},
					{Name: "metrics", ContainerPort: 8081},
				},
			},
		},
	}
	labels := map[string]string{
		KagentiTypeLabel: KagentiTypeAgent,
	}
	annotations := map[string]string{
		AnnotationAuthBridgeMode: ModeProxySidecar,
	}

	mutated, err := m.InjectAuthBridge(ctx, podSpec, "team1", "my-agent", labels, annotations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mutated {
		t.Fatal("expected mutation")
	}

	// Forward proxy should NOT be on 8081 (collision with metrics)
	for _, c := range podSpec.Containers {
		if c.Name == AuthBridgeProxyContainerName {
			for _, p := range c.Ports {
				if p.Name == "forward-proxy" {
					if p.ContainerPort == 8081 {
						t.Error("forward-proxy should not be 8081 (collision with agent metrics)")
					}
					if p.ContainerPort != 8082 {
						t.Errorf("forward-proxy port = %d, want 8082", p.ContainerPort)
					}
				}
			}
		}
	}

	// HTTP_PROXY should use the actual forward proxy port, not hardcoded 8081
	for _, c := range podSpec.Containers {
		if c.Name == "agent" {
			for _, env := range c.Env {
				if env.Name == "HTTP_PROXY" {
					if env.Value == "http://127.0.0.1:8081" {
						t.Error("HTTP_PROXY should not use 8081 (collides with agent metrics)")
					}
					if env.Value != "http://127.0.0.1:8082" {
						t.Errorf("HTTP_PROXY = %q, want http://127.0.0.1:8082", env.Value)
					}
				}
			}
		}
	}
}

func TestSetOrAddEnv_OverwritesExisting(t *testing.T) {
	c := &corev1.Container{
		Name: "agent",
		Env: []corev1.EnvVar{
			{Name: "PORT", Value: "8000"},
			{Name: "HOST", Value: "0.0.0.0"},
		},
	}

	setOrAddEnv(c, "PORT", "8002")

	count := 0
	for _, env := range c.Env {
		if env.Name == "PORT" {
			count++
			if env.Value != "8002" {
				t.Errorf("PORT = %q, want 8002", env.Value)
			}
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 PORT env var, got %d", count)
	}
	// HOST should be unchanged
	for _, env := range c.Env {
		if env.Name == "HOST" && env.Value != "0.0.0.0" {
			t.Errorf("HOST should be unchanged, got %q", env.Value)
		}
	}
}

func TestSetOrAddEnv_AddsNew(t *testing.T) {
	c := &corev1.Container{
		Name: "agent",
		Env: []corev1.EnvVar{
			{Name: "HOST", Value: "0.0.0.0"},
		},
	}

	setOrAddEnv(c, "PORT", "8002")

	found := false
	for _, env := range c.Env {
		if env.Name == "PORT" && env.Value == "8002" {
			found = true
		}
	}
	if !found {
		t.Error("PORT env var should be added")
	}
	if len(c.Env) != 2 {
		t.Errorf("expected 2 env vars, got %d", len(c.Env))
	}
}
