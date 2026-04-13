/*
Copyright 2026.

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

	"github.com/kagenti/operator/internal/controller"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newReconcilerScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	return scheme
}

func newDefaultsReconciler(objs ...client.Object) *DefaultsConfigReconciler {
	scheme := newReconcilerScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	return &DefaultsConfigReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}
}

func newLabeledDeployment(name, namespace string, extraLabels map[string]string) *appsv1.Deployment {
	labels := map[string]string{
		KagentiTypeLabel: KagentiTypeAgent,
	}
	for k, v := range extraLabels {
		labels[k] = v
	}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": name},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": name},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "agent", Image: "agent:latest"},
					},
				},
			},
		},
	}
}

func newLabeledStatefulSet(name, namespace string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				KagentiTypeLabel: KagentiTypeAgent,
			},
		},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": name},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": name},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "agent", Image: "agent:latest"},
					},
				},
			},
		},
	}
}

func newClusterDefaultsConfigMap(data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      controller.ClusterDefaultsConfigMapName,
			Namespace: controller.ClusterDefaultsNamespace,
		},
		Data: data,
	}
}

func newNamespaceDefaultsConfigMap(namespace string, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ns-defaults",
			Namespace: namespace,
			Labels: map[string]string{
				controller.LabelNamespaceDefaults: "true",
			},
		},
		Data: data,
	}
}

func TestDefaultsConfigReconciler_SkipsManagedWorkload(t *testing.T) {
	dep := newLabeledDeployment("my-agent", "team1", map[string]string{
		controller.LabelManagedBy: controller.LabelManagedByValue,
	})
	cm := newClusterDefaultsConfigMap(map[string]string{"key": "val"})

	r := newDefaultsReconciler(dep, cm)
	ctx := context.Background()

	_, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      controller.ClusterDefaultsConfigMapName,
			Namespace: controller.ClusterDefaultsNamespace,
		},
	})
	if err != nil {
		t.Fatalf("Reconcile() returned error: %v", err)
	}

	// Verify config-hash was NOT set (workload is managed by AgentRuntime)
	updated := &appsv1.Deployment{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(dep), updated); err != nil {
		t.Fatalf("failed to get deployment: %v", err)
	}
	if hash := updated.Spec.Template.Annotations[controller.AnnotationConfigHash]; hash != "" {
		t.Errorf("expected no config-hash on managed workload, got %q", hash)
	}
}

func TestDefaultsConfigReconciler_UpdatesUnmanagedWorkload(t *testing.T) {
	dep := newLabeledDeployment("my-agent", "team1", nil)
	cm := newClusterDefaultsConfigMap(map[string]string{"key": "val"})

	r := newDefaultsReconciler(dep, cm)
	ctx := context.Background()

	_, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      controller.ClusterDefaultsConfigMapName,
			Namespace: controller.ClusterDefaultsNamespace,
		},
	})
	if err != nil {
		t.Fatalf("Reconcile() returned error: %v", err)
	}

	updated := &appsv1.Deployment{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(dep), updated); err != nil {
		t.Fatalf("failed to get deployment: %v", err)
	}
	hash := updated.Spec.Template.Annotations[controller.AnnotationConfigHash]
	if hash == "" {
		t.Fatal("expected config-hash to be set on unmanaged workload")
	}
}

func TestDefaultsConfigReconciler_IdempotentWhenHashUnchanged(t *testing.T) {
	dep := newLabeledDeployment("my-agent", "team1", nil)
	cm := newClusterDefaultsConfigMap(map[string]string{"key": "val"})

	r := newDefaultsReconciler(dep, cm)
	ctx := context.Background()

	// First reconcile — sets the hash
	_, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      controller.ClusterDefaultsConfigMapName,
			Namespace: controller.ClusterDefaultsNamespace,
		},
	})
	if err != nil {
		t.Fatalf("first Reconcile() returned error: %v", err)
	}

	updated := &appsv1.Deployment{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(dep), updated); err != nil {
		t.Fatalf("failed to get deployment: %v", err)
	}
	rvAfterFirst := updated.ResourceVersion

	// Second reconcile — should be a no-op
	_, err = r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      controller.ClusterDefaultsConfigMapName,
			Namespace: controller.ClusterDefaultsNamespace,
		},
	})
	if err != nil {
		t.Fatalf("second Reconcile() returned error: %v", err)
	}

	if err := r.Get(ctx, client.ObjectKeyFromObject(dep), updated); err != nil {
		t.Fatalf("failed to get deployment: %v", err)
	}
	if updated.ResourceVersion != rvAfterFirst {
		t.Error("expected no update on second reconcile (hash unchanged)")
	}
}

func TestDefaultsConfigReconciler_HandlesNamespaceDefaults(t *testing.T) {
	dep := newLabeledDeployment("my-agent", "team1", nil)
	cm := newNamespaceDefaultsConfigMap("team1", map[string]string{"ns-key": "ns-val"})

	r := newDefaultsReconciler(dep, cm)
	ctx := context.Background()

	_, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "ns-defaults",
			Namespace: "team1",
		},
	})
	if err != nil {
		t.Fatalf("Reconcile() returned error: %v", err)
	}

	updated := &appsv1.Deployment{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(dep), updated); err != nil {
		t.Fatalf("failed to get deployment: %v", err)
	}
	hash := updated.Spec.Template.Annotations[controller.AnnotationConfigHash]
	if hash == "" {
		t.Fatal("expected config-hash to be set for namespace defaults change")
	}
}

func TestDefaultsConfigReconciler_IgnoresIrrelevantConfigMap(t *testing.T) {
	dep := newLabeledDeployment("my-agent", "team1", nil)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unrelated-config",
			Namespace: "team1",
		},
		Data: map[string]string{"foo": "bar"},
	}

	r := newDefaultsReconciler(dep, cm)
	ctx := context.Background()

	_, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "unrelated-config",
			Namespace: "team1",
		},
	})
	if err != nil {
		t.Fatalf("Reconcile() returned error: %v", err)
	}

	updated := &appsv1.Deployment{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(dep), updated); err != nil {
		t.Fatalf("failed to get deployment: %v", err)
	}
	if hash := updated.Spec.Template.Annotations[controller.AnnotationConfigHash]; hash != "" {
		t.Errorf("expected no config-hash update for irrelevant ConfigMap, got %q", hash)
	}
}

func TestDefaultsConfigReconciler_HandlesStatefulSet(t *testing.T) {
	ss := newLabeledStatefulSet("my-agent", "team1")
	cm := newClusterDefaultsConfigMap(map[string]string{"key": "val"})

	r := newDefaultsReconciler(ss, cm)
	ctx := context.Background()

	_, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      controller.ClusterDefaultsConfigMapName,
			Namespace: controller.ClusterDefaultsNamespace,
		},
	})
	if err != nil {
		t.Fatalf("Reconcile() returned error: %v", err)
	}

	updated := &appsv1.StatefulSet{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(ss), updated); err != nil {
		t.Fatalf("failed to get statefulset: %v", err)
	}
	hash := updated.Spec.Template.Annotations[controller.AnnotationConfigHash]
	if hash == "" {
		t.Fatal("expected config-hash to be set on unmanaged StatefulSet")
	}
}

func TestDefaultsConfigReconciler_ConfigMapNotFound(t *testing.T) {
	r := newDefaultsReconciler()
	ctx := context.Background()

	_, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "nonexistent",
			Namespace: "team1",
		},
	})
	if err != nil {
		t.Fatalf("Reconcile() should not error on NotFound, got: %v", err)
	}
}

func TestDefaultsConfigReconciler_ConfigMapDeleted_UpdatesWorkloads(t *testing.T) {
	// When a namespace defaults ConfigMap is deleted, the defaults-only hash
	// changes (one input is gone). The reconciler should still update workloads.
	dep := newLabeledDeployment("my-agent", "team1", nil)
	// Pre-set a stale hash to verify it gets updated
	dep.Spec.Template.Annotations = map[string]string{
		controller.AnnotationConfigHash: "stale-hash-value",
	}

	// No ConfigMap in the fake client — simulates deletion
	r := newDefaultsReconciler(dep)
	ctx := context.Background()

	_, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "ns-defaults",
			Namespace: "team1",
		},
	})
	if err != nil {
		t.Fatalf("Reconcile() returned error: %v", err)
	}

	updated := &appsv1.Deployment{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(dep), updated); err != nil {
		t.Fatalf("failed to get deployment: %v", err)
	}
	hash := updated.Spec.Template.Annotations[controller.AnnotationConfigHash]
	if hash == "stale-hash-value" {
		t.Error("expected config-hash to be updated after ConfigMap deletion")
	}
	if hash == "" {
		t.Error("expected config-hash to be set to defaults-only hash")
	}
}

func TestDefaultsConfigReconciler_ClusterConfigMapDeleted_UpdatesAllNamespaces(t *testing.T) {
	dep1 := newLabeledDeployment("agent-1", "team1", nil)
	dep1.Spec.Template.Annotations = map[string]string{
		controller.AnnotationConfigHash: "stale-hash",
	}
	dep2 := newLabeledDeployment("agent-2", "team2", nil)
	dep2.Spec.Template.Annotations = map[string]string{
		controller.AnnotationConfigHash: "stale-hash",
	}

	// No cluster ConfigMap — simulates deletion
	r := newDefaultsReconciler(dep1, dep2)
	ctx := context.Background()

	_, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      controller.ClusterDefaultsConfigMapName,
			Namespace: controller.ClusterDefaultsNamespace,
		},
	})
	if err != nil {
		t.Fatalf("Reconcile() returned error: %v", err)
	}

	for _, dep := range []*appsv1.Deployment{dep1, dep2} {
		updated := &appsv1.Deployment{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(dep), updated); err != nil {
			t.Fatalf("failed to get deployment %s: %v", dep.Name, err)
		}
		hash := updated.Spec.Template.Annotations[controller.AnnotationConfigHash]
		if hash == "stale-hash" || hash == "" {
			t.Errorf("deployment %s/%s: expected config-hash to be updated, got %q",
				dep.Namespace, dep.Name, hash)
		}
	}
}

func TestDefaultsConfigReconciler_MixedManagedAndUnmanaged(t *testing.T) {
	// Both managed and unmanaged workloads in the same namespace — only
	// the unmanaged one should get its config-hash updated.
	managed := newLabeledDeployment("managed-agent", "team1", map[string]string{
		controller.LabelManagedBy: controller.LabelManagedByValue,
	})
	unmanaged := newLabeledDeployment("orphan-agent", "team1", nil)
	cm := newClusterDefaultsConfigMap(map[string]string{"key": "val"})

	r := newDefaultsReconciler(managed, unmanaged, cm)
	ctx := context.Background()

	_, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      controller.ClusterDefaultsConfigMapName,
			Namespace: controller.ClusterDefaultsNamespace,
		},
	})
	if err != nil {
		t.Fatalf("Reconcile() returned error: %v", err)
	}

	// Managed workload should NOT be updated
	updatedManaged := &appsv1.Deployment{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(managed), updatedManaged); err != nil {
		t.Fatalf("failed to get managed deployment: %v", err)
	}
	if hash := updatedManaged.Spec.Template.Annotations[controller.AnnotationConfigHash]; hash != "" {
		t.Errorf("expected no config-hash on managed workload, got %q", hash)
	}

	// Unmanaged workload should be updated
	updatedUnmanaged := &appsv1.Deployment{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(unmanaged), updatedUnmanaged); err != nil {
		t.Fatalf("failed to get unmanaged deployment: %v", err)
	}
	if hash := updatedUnmanaged.Spec.Template.Annotations[controller.AnnotationConfigHash]; hash == "" {
		t.Error("expected config-hash on unmanaged workload")
	}
}

func TestDefaultsConfigReconciler_MultiNamespaceFanOut(t *testing.T) {
	// Cluster ConfigMap change should update workloads across multiple namespaces.
	dep1 := newLabeledDeployment("agent-a", "ns1", nil)
	dep2 := newLabeledDeployment("agent-b", "ns2", nil)
	dep3 := newLabeledDeployment("agent-c", "ns3", nil)
	cm := newClusterDefaultsConfigMap(map[string]string{"key": "val"})

	r := newDefaultsReconciler(dep1, dep2, dep3, cm)
	ctx := context.Background()

	_, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      controller.ClusterDefaultsConfigMapName,
			Namespace: controller.ClusterDefaultsNamespace,
		},
	})
	if err != nil {
		t.Fatalf("Reconcile() returned error: %v", err)
	}

	for _, dep := range []*appsv1.Deployment{dep1, dep2, dep3} {
		updated := &appsv1.Deployment{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(dep), updated); err != nil {
			t.Fatalf("failed to get deployment %s/%s: %v", dep.Namespace, dep.Name, err)
		}
		hash := updated.Spec.Template.Annotations[controller.AnnotationConfigHash]
		if hash == "" {
			t.Errorf("deployment %s/%s: expected config-hash to be set", dep.Namespace, dep.Name)
		}
	}
}

func TestDefaultsConfigReconciler_FeatureGatesConfigMapTrigger(t *testing.T) {
	dep := newLabeledDeployment("my-agent", "team1", nil)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      controller.ClusterFeatureGatesConfigMapName,
			Namespace: controller.ClusterDefaultsNamespace,
		},
		Data: map[string]string{"globalEnabled": "true"},
	}

	r := newDefaultsReconciler(dep, cm)
	ctx := context.Background()

	_, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      controller.ClusterFeatureGatesConfigMapName,
			Namespace: controller.ClusterDefaultsNamespace,
		},
	})
	if err != nil {
		t.Fatalf("Reconcile() returned error: %v", err)
	}

	updated := &appsv1.Deployment{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(dep), updated); err != nil {
		t.Fatalf("failed to get deployment: %v", err)
	}
	hash := updated.Spec.Template.Annotations[controller.AnnotationConfigHash]
	if hash == "" {
		t.Fatal("expected config-hash to be set for feature-gates ConfigMap change")
	}
}

func TestIsClusterConfigMapKey(t *testing.T) {
	tests := []struct {
		name     string
		key      types.NamespacedName
		expected bool
	}{
		{
			name:     "platform config",
			key:      types.NamespacedName{Name: controller.ClusterDefaultsConfigMapName, Namespace: controller.ClusterDefaultsNamespace},
			expected: true,
		},
		{
			name:     "feature gates",
			key:      types.NamespacedName{Name: controller.ClusterFeatureGatesConfigMapName, Namespace: controller.ClusterDefaultsNamespace},
			expected: true,
		},
		{
			name:     "wrong namespace",
			key:      types.NamespacedName{Name: controller.ClusterDefaultsConfigMapName, Namespace: "other-ns"},
			expected: false,
		},
		{
			name:     "random configmap",
			key:      types.NamespacedName{Name: "random", Namespace: "random-ns"},
			expected: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isClusterConfigMapKey(tc.key); got != tc.expected {
				t.Errorf("isClusterConfigMapKey() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestIsClusterConfigMap(t *testing.T) {
	tests := []struct {
		name      string
		cm        *corev1.ConfigMap
		expected  bool
	}{
		{
			name: "platform config",
			cm: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      controller.ClusterDefaultsConfigMapName,
					Namespace: controller.ClusterDefaultsNamespace,
				},
			},
			expected: true,
		},
		{
			name: "feature gates",
			cm: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      controller.ClusterFeatureGatesConfigMapName,
					Namespace: controller.ClusterDefaultsNamespace,
				},
			},
			expected: true,
		},
		{
			name: "wrong namespace",
			cm: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      controller.ClusterDefaultsConfigMapName,
					Namespace: "other-ns",
				},
			},
			expected: false,
		},
		{
			name: "wrong name",
			cm: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "other-config",
					Namespace: controller.ClusterDefaultsNamespace,
				},
			},
			expected: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isClusterConfigMap(tc.cm); got != tc.expected {
				t.Errorf("isClusterConfigMap() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestIsNamespaceDefaultsConfigMap(t *testing.T) {
	tests := []struct {
		name     string
		cm       *corev1.ConfigMap
		expected bool
	}{
		{
			name: "has defaults label",
			cm: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ns-defaults",
					Namespace: "team1",
					Labels: map[string]string{
						controller.LabelNamespaceDefaults: "true",
					},
				},
			},
			expected: true,
		},
		{
			name: "no labels",
			cm: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ns-defaults",
					Namespace: "team1",
				},
			},
			expected: false,
		},
		{
			name: "wrong label value",
			cm: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ns-defaults",
					Namespace: "team1",
					Labels: map[string]string{
						controller.LabelNamespaceDefaults: "false",
					},
				},
			},
			expected: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNamespaceDefaultsConfigMap(tc.cm); got != tc.expected {
				t.Errorf("isNamespaceDefaultsConfigMap() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestIsManagedByAgentRuntime(t *testing.T) {
	tests := []struct {
		name     string
		labels   map[string]string
		expected bool
	}{
		{
			name: "managed",
			labels: map[string]string{
				controller.LabelManagedBy: controller.LabelManagedByValue,
			},
			expected: true,
		},
		{
			name:     "not managed - no labels",
			labels:   nil,
			expected: false,
		},
		{
			name: "not managed - different value",
			labels: map[string]string{
				controller.LabelManagedBy: "other",
			},
			expected: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dep := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "test",
					Labels: tc.labels,
				},
			}
			if got := isManagedByAgentRuntime(dep); got != tc.expected {
				t.Errorf("isManagedByAgentRuntime() = %v, want %v", got, tc.expected)
			}
		})
	}
}
