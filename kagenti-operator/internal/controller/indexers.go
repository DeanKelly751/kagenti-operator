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

package controller

import (
	"context"
	"fmt"
	"sync"

	agentv1alpha1 "github.com/kagenti/operator/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TargetRefNameIndex is the shared field index key for .spec.targetRef.name.
// Used by AgentCardReconciler, AgentCardNetworkPolicyReconciler, and
// AgentCardSyncReconciler to look up AgentCards by targetRef name without
// listing every card in the namespace.
const TargetRefNameIndex = ".spec.targetRef.name"

// registerTargetRefIndexOnce ensures the field indexer is registered exactly once,
// even if multiple controllers call RegisterAgentCardTargetRefIndex.
var registerTargetRefIndexOnce sync.Once

// registerTargetRefIndexErr stores any error from the one-time registration.
var registerTargetRefIndexErr error

// RegisterAgentCardTargetRefIndex registers a field indexer for AgentCard on
// .spec.targetRef.name. It is safe to call from multiple controllers — only
// the first call performs the registration; subsequent calls are no-ops.
func RegisterAgentCardTargetRefIndex(mgr ctrl.Manager) error {
	registerTargetRefIndexOnce.Do(func() {
		registerTargetRefIndexErr = mgr.GetFieldIndexer().IndexField(
			context.Background(),
			&agentv1alpha1.AgentCard{},
			TargetRefNameIndex,
			func(obj client.Object) []string {
				card := obj.(*agentv1alpha1.AgentCard)
				if card.Spec.TargetRef != nil && card.Spec.TargetRef.Name != "" {
					return []string{card.Spec.TargetRef.Name}
				}
				return nil
			},
		)
		if registerTargetRefIndexErr != nil {
			registerTargetRefIndexErr = fmt.Errorf("failed to create field indexer for %s: %w",
				TargetRefNameIndex, registerTargetRefIndexErr)
		}
	})
	return registerTargetRefIndexErr
}
