/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	agentv1alpha1 "github.com/kagenti/operator/api/v1alpha1"
	"github.com/kagenti/operator/internal/agntcy"
)

// AgntcyPocReconciler is an optional, opt-in path for AGNTCY PoC (Directory, identity
// probe, SLIM placeholder). OASF validation is implemented on the main AgentCard
// reconciler (spec.oasf and --oasf-schema-base-url).
// +kubebuilder:rbac:groups=agent.kagenti.dev,resources=agentcards,verbs=get;list;watch
// +kubebuilder:rbac:groups=agent.kagenti.dev,resources=agentcards/status,verbs=get;update;patch
type AgntcyPocReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Poc    agntcy.PocOptions

	initOnce   sync.Once
	dirPusher  *agntcy.DirPusher
	initErr    error
	initLogged bool
}

func (r *AgntcyPocReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	agentCard := &agentv1alpha1.AgentCard{}
	if err := r.Get(ctx, req.NamespacedName, agentCard); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !agntcy.PocResourceOptIn(agentCard.Labels) {
		return ctrl.Result{}, nil
	}
	if err := r.lazyInit(ctx, logger); err != nil {
		return r.patchStatusWithMessage(ctx, agentCard, "InitFailed", err.Error(), metav1.ConditionFalse)
	}
	if agentCard.Status.Card == nil {
		applyPocCond := func(ctype, reason, msg string) {
			meta.SetStatusCondition(&agentCard.Status.Conditions, metav1.Condition{
				Type:               ctype,
				Status:             metav1.ConditionUnknown,
				Reason:             reason,
				Message:            msg,
				LastTransitionTime: metav1.Now(),
			})
		}
		applyPocCond(agntcy.CondDirPublished, "WaitingForCard", "card not yet synced by AgentCard controller")
		applyPocCond(agntcy.CondIdentityPoc, "WaitingForCard", "card not yet synced by AgentCard controller")
		applyPocCond(agntcy.CondSlimPoc, agntcy.ReasonSlimPoc, "SLIM sidecar: not in scope for this PoC; see kagenti.io/agntcy-poc and operator docs")
		_ = r.updateStatus(ctx, agentCard) //nolint:errcheck
		return ctrl.Result{RequeueAfter: 20 * time.Second}, nil
	}
	logger.V(1).Info("reconciling AGNTCY PoC for AgentCard")

	dirSt := metav1.ConditionTrue
	dirR := agntcy.ReasonDirPublished
	dirM := "Directory push skipped (no --agntcy-dir-address)"
	if r.Poc.DirAddress != "" && r.dirPusher != nil {
		rec, recErr := agntcy.AgentRecord(agentCard.Status.Card)
		if recErr != nil {
			dirSt, dirR, dirM = metav1.ConditionFalse, agntcy.ReasonDirFailed, recErr.Error()
		} else {
			cid, derr := r.dirPusher.PushRecord(ctx, rec)
			if derr != nil {
				dirSt, dirR, dirM = metav1.ConditionFalse, agntcy.ReasonDirFailed, derr.Error()
			} else {
				dirM = "pushed to dir, cid=" + cid
			}
		}
	}
	meta.SetStatusCondition(&agentCard.Status.Conditions, metav1.Condition{
		Type:               agntcy.CondDirPublished,
		Status:             dirSt,
		Reason:             dirR,
		Message:            dirM,
		ObservedGeneration: agentCard.Generation,
		LastTransitionTime: metav1.Now(),
	})

	idSt := metav1.ConditionTrue
	idR := agntcy.ReasonIdentityOK
	idM := "Identity probe skipped (no --agntcy-identity-probe-url)"
	if r.Poc.IdentityProbeURL != "" {
		if err := agntcy.ProbeIdentityURL(ctx, r.Poc.IdentityProbeURL); err != nil {
			idSt, idR, idM = metav1.ConditionFalse, agntcy.ReasonIdentityFail, err.Error()
		} else {
			idM = "GET " + r.Poc.IdentityProbeURL + " succeeded (PoC wire check, not VC issuance)"
		}
	}
	meta.SetStatusCondition(&agentCard.Status.Conditions, metav1.Condition{
		Type:               agntcy.CondIdentityPoc,
		Status:             idSt,
		Reason:             idR,
		Message:            idM,
		ObservedGeneration: agentCard.Generation,
		LastTransitionTime: metav1.Now(),
	})

	meta.SetStatusCondition(&agentCard.Status.Conditions, metav1.Condition{
		Type:               agntcy.CondSlimPoc,
		Status:             metav1.ConditionFalse,
		Reason:             agntcy.ReasonSlimPoc,
		Message:            "agntcy/slim is not enabled in the operator PoC; use A2A + Envoy and revisit when workload latency requires SLIM",
		ObservedGeneration: agentCard.Generation,
		LastTransitionTime: metav1.Now(),
	})
	if err := r.updateStatus(ctx, agentCard); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 2 * time.Minute}, nil
}

func (r *AgntcyPocReconciler) lazyInit(ctx context.Context, logger logr.Logger) error {
	r.initOnce.Do(func() {
		if r.Poc.DirAddress != "" {
			dp, derr := agntcy.NewDirPusher(ctx, logger, r.Poc.DirAddress, r.Poc.DirAuthMode)
			if derr != nil {
				r.initErr = fmt.Errorf("agntcy dir client: %w", derr)
				if !r.initLogged {
					logger.Error(derr, "AGNTCY PoC: could not build dir client")
					r.initLogged = true
				}
			} else {
				r.dirPusher = dp
			}
		}
	})
	return r.initErr
}

// patchStatusWithMessage is used when init fails.
func (r *AgntcyPocReconciler) patchStatusWithMessage(
	ctx context.Context, ac *agentv1alpha1.AgentCard, reason, msg string, st metav1.ConditionStatus,
) (ctrl.Result, error) {
	meta.SetStatusCondition(&ac.Status.Conditions, metav1.Condition{
		Type:               agntcy.CondDirPublished,
		Status:             st,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: ac.Generation,
		LastTransitionTime: metav1.Now(),
	})
	meta.SetStatusCondition(&ac.Status.Conditions, metav1.Condition{
		Type:               agntcy.CondIdentityPoc,
		Status:             st,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: ac.Generation,
		LastTransitionTime: metav1.Now(),
	})
	meta.SetStatusCondition(&ac.Status.Conditions, metav1.Condition{
		Type:               agntcy.CondSlimPoc,
		Status:             st,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: ac.Generation,
		LastTransitionTime: metav1.Now(),
	})
	if err := r.updateStatus(ctx, ac); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 2 * time.Minute}, nil
}

func (r *AgntcyPocReconciler) updateStatus(ctx context.Context, ac *agentv1alpha1.AgentCard) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &agentv1alpha1.AgentCard{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(ac), latest); err != nil {
			return err
		}
		mergePocConds := func(dst, src []metav1.Condition) []metav1.Condition {
			var keep []metav1.Condition
			for _, c := range dst {
				if c.Type == agntcy.CondDirPublished ||
					c.Type == agntcy.CondIdentityPoc || c.Type == agntcy.CondSlimPoc {
					continue
				}
				keep = append(keep, c)
			}
			for _, c := range src {
				if c.Type == agntcy.CondDirPublished ||
					c.Type == agntcy.CondIdentityPoc || c.Type == agntcy.CondSlimPoc {
					keep = append(keep, c)
				}
			}
			return keep
		}
		latest.Status.Conditions = mergePocConds(latest.Status.Conditions, ac.Status.Conditions)
		return r.Status().Update(ctx, latest)
	})
}

func (r *AgntcyPocReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return builder.ControllerManagedBy(mgr).
		For(&agentv1alpha1.AgentCard{}).
		WithEventFilter(predicate.NewPredicateFuncs(func(o client.Object) bool {
			return agntcy.PocResourceOptIn(o.GetLabels())
		})).
		Complete(r)
}
