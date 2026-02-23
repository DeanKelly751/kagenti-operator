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
	"encoding/json"
	"fmt"
	"time"

	agentv1alpha1 "github.com/kagenti/operator/api/v1alpha1"
	"github.com/kagenti/operator/internal/distribution"
	"github.com/kagenti/operator/internal/rbac"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// AgentReconciler reconciles Agent CRs into Deployments and Services.
type AgentReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	Distribution distribution.Type
}

var logger = ctrl.Log.WithName("controller").WithName("Agent")

const AgentFinalizer = "agent.kagenti.dev/finalizer"

// +kubebuilder:rbac:groups=agent.kagenti.dev,resources=agents,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=agent.kagenti.dev,resources=agents/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=agent.kagenti.dev,resources=agents/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=pods/log,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete

func (r *AgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger.V(1).Info("Reconciling Agent", "namespacedName", req.NamespacedName)

	agent := &agentv1alpha1.Agent{}
	err := r.Get(ctx, req.NamespacedName, agent)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !agent.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, agent)
	}

	if !controllerutil.ContainsFinalizer(agent, AgentFinalizer) {
		controllerutil.AddFinalizer(agent, AgentFinalizer)
		if err := r.Update(ctx, agent); err != nil {
			logger.Error(err, "Failed to add finalizer to Agent")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	deploymentResult, err := r.reconcileAgentDeployment(ctx, agent)
	if err != nil {
		return deploymentResult, err
	}

	serviceResult, err := r.reconcileAgentService(ctx, agent)
	if err != nil {
		return serviceResult, err
	}
	return ctrl.Result{}, nil
}

func (r *AgentReconciler) reconcileAgentDeployment(ctx context.Context, agent *agentv1alpha1.Agent) (ctrl.Result, error) {
	deploymentName := agent.Name
	deployment := &appsv1.Deployment{}

	rbacConfig, err := r.ensureRBAC(ctx, agent)
	if err != nil {
		logger.Error(err, "Failed to ensure RBAC objects",
			"agent", agent.Name,
			"namespace", agent.Namespace)
		return ctrl.Result{}, err
	}

	err = r.Get(ctx, types.NamespacedName{Name: deploymentName, Namespace: agent.Namespace}, deployment)
	if err != nil && errors.IsNotFound(err) {
		deployment, err = r.buildDeploymentSpec(agent, rbacConfig)
		if err != nil {
			logger.Error(err, "Failed to build deployment spec for Agent",
				"agent", agent.Name,
				"namespace", agent.Namespace)
			return ctrl.Result{}, err
		}
		logger.Info("Creating Agent Deployment", "deploymentName", deploymentName)
		if agent.Annotations != nil {
			deployment.ObjectMeta.Annotations = agent.Annotations
		}

		if logger.V(1).Enabled() {
			data, err := json.MarshalIndent(deployment, "", "  ")
			if err != nil {
				logger.V(1).Error(err, "Failed to marshal deployment spec to JSON")
			} else {
				logger.V(1).Info("Deployment spec", "spec", string(data))
			}
		}

		if err := controllerutil.SetControllerReference(agent, deployment, r.Scheme); err != nil {
			logger.Error(err, "Failed to set controller reference for Agent Deployment",
				"agent", agent.Name,
				"namespace", agent.Namespace)
			return ctrl.Result{}, err
		}

		if err := r.Create(ctx, deployment); err != nil {
			logger.Error(err, "Failed to create Agent Deployment",
				"agent", agent.Name,
				"namespace", agent.Namespace)
			return ctrl.Result{RequeueAfter: 5 * time.Second}, err
		}
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	} else if err != nil {
		logger.Error(err, "Failed to get Agent Deployment",
			"agent", agent.Name,
			"namespace", agent.Namespace)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, err
	}

	desiredDeployment, err := r.buildDeploymentSpec(agent, rbacConfig)
	if err != nil {
		logger.Error(err, "Failed to build desired deployment spec for Agent",
			"agent", agent.Name,
			"namespace", agent.Namespace)
		return ctrl.Result{}, err
	}

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := r.Get(ctx, client.ObjectKey{Name: deploymentName, Namespace: agent.Namespace}, deployment); err != nil {
			return err
		}

		logger.V(1).Info("Updating Agent Deployment", "deploymentName", deploymentName)

		desiredReplicas := desiredDeployment.Spec.Replicas
		currentReplicas := deployment.Spec.Replicas
		if !ptr.Equal(currentReplicas, desiredReplicas) {
			logger.Info("Replicas changed",
				"old", ptrValueOrDefault(currentReplicas, 1),
				"new", ptrValueOrDefault(desiredReplicas, 1))
			deployment.Spec.Replicas = desiredReplicas
		}

		existingByName := map[string]int{}
		var unnamedExisting []int
		for i := range deployment.Spec.Template.Spec.Containers {
			c := deployment.Spec.Template.Spec.Containers[i]
			if c.Name == "" {
				unnamedExisting = append(unnamedExisting, i)
				logger.Info("Warning: found unnamed container at index, matching by position is fragile",
					"index", i,
					"deployment", deploymentName)
			} else {
				existingByName[c.Name] = i
			}
		}

		unnamedIdx := 0
		for i := range desiredDeployment.Spec.Template.Spec.Containers {
			desired := desiredDeployment.Spec.Template.Spec.Containers[i]

			if desired.Name != "" {
				if idx, found := existingByName[desired.Name]; found {
					updated := updateContainerEnv(&deployment.Spec.Template.Spec.Containers[idx], &desired)
					if updated {
						logger.Info("Container updated", "containerName", desired.Name)
					}
					continue
				}
				deployment.Spec.Template.Spec.Containers = append(deployment.Spec.Template.Spec.Containers, desired)
				logger.Info("Container added", "containerName", desired.Name)
				continue
			}

			if unnamedIdx < len(unnamedExisting) {
				idx := unnamedExisting[unnamedIdx]
				updateContainerEnv(&deployment.Spec.Template.Spec.Containers[idx], &desired)
				unnamedIdx++
			} else {
				deployment.Spec.Template.Spec.Containers = append(deployment.Spec.Template.Spec.Containers, desired)
			}
		}
		deployment.ObjectMeta.Annotations = mergeStringMaps(deployment.ObjectMeta.Annotations, agent.Annotations)
		deployment.ObjectMeta.Labels = mergeStringMaps(deployment.ObjectMeta.Labels, agent.Labels)
		return r.Update(ctx, deployment)
	}); err != nil {
		logger.Error(err, "Failed to update Agent Deployment after retries",
			"agent", agent.Name,
			"namespace", agent.Namespace)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, err
	}

	if err := r.Get(ctx, types.NamespacedName{Name: deploymentName, Namespace: agent.Namespace}, deployment); err != nil {
		logger.Error(err, "Failed to get updated deployment status",
			"deployment", deploymentName,
			"namespace", agent.Namespace)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, err
	}

	logger.V(1).Info("Deployment status",
		"name", deploymentName,
		"namespace", agent.Namespace,
		"desiredReplicas", ptrValueOrDefault(deployment.Spec.Replicas, 1),
		"readyReplicas", deployment.Status.ReadyReplicas,
		"availableReplicas", deployment.Status.AvailableReplicas,
		"unavailableReplicas", deployment.Status.UnavailableReplicas)

	desiredReplicas := ptrValueOrDefault(deployment.Spec.Replicas, 1)

	deploymentMessage := fmt.Sprintf(
		"Replicas: %d/%d ready, %d updated, %d available",
		deployment.Status.ReadyReplicas,
		deployment.Status.Replicas,
		deployment.Status.UpdatedReplicas,
		deployment.Status.AvailableReplicas,
	)

	var phase agentv1alpha1.LifecyclePhase
	var conditions []metav1.Condition

	conditions = append(conditions, metav1.Condition{
		Type:               "DeploymentAvailable",
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             "DeploymentExists",
		Message:            fmt.Sprintf("Deployment %s exists with %d desired replicas", deployment.Name, desiredReplicas),
	})

	if deployment.Status.UnavailableReplicas > 0 {
		conditions = append(conditions, metav1.Condition{
			Type:               "PodsScheduled",
			Status:             metav1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             "PodsUnscheduled",
			Message:            fmt.Sprintf("%d of %d pods are unavailable", deployment.Status.UnavailableReplicas, deployment.Status.Replicas),
		})
	} else if deployment.Status.Replicas > 0 {
		conditions = append(conditions, metav1.Condition{
			Type:               "PodsScheduled",
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             "AllPodsScheduled",
			Message:            fmt.Sprintf("All %d pods are scheduled and available", deployment.Status.AvailableReplicas),
		})
	}

	if deployment.Status.ReadyReplicas > 0 && deployment.Status.ReadyReplicas == int32(desiredReplicas) {
		phase = agentv1alpha1.PhaseReady

		conditions = append(conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             "DeploymentReady",
			Message:            fmt.Sprintf("All %d/%d replicas are ready", deployment.Status.ReadyReplicas, desiredReplicas),
		})
	} else {
		phase = agentv1alpha1.PhaseDeploying

		conditions = append(conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             "DeploymentNotReady",
			Message:            fmt.Sprintf("Waiting for replicas: %d/%d ready, %d available", deployment.Status.ReadyReplicas, desiredReplicas, deployment.Status.AvailableReplicas),
		})
	}

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latestAgent := &agentv1alpha1.Agent{}
		if err := r.Get(ctx, types.NamespacedName{Name: agent.Name, Namespace: agent.Namespace}, latestAgent); err != nil {
			return err
		}

		if latestAgent.Status.DeploymentStatus == nil {
			latestAgent.Status.DeploymentStatus = &agentv1alpha1.DeploymentStatus{}
		}

		latestAgent.Status.DeploymentStatus.DeploymentMessage = deploymentMessage
		latestAgent.Status.DeploymentStatus.Phase = phase

		for _, condition := range conditions {
			meta.SetStatusCondition(&latestAgent.Status.Conditions, condition)
		}

		return r.Status().Update(ctx, latestAgent)
	}); err != nil {
		logger.Error(err, "Failed to update Agent status after retries",
			"agent", agent.Name,
			"namespace", agent.Namespace)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, err
	}

	if deployment.Status.ReadyReplicas < int32(desiredReplicas) {
		logger.Info("Requeuing: not all replicas ready",
			"ready", deployment.Status.ReadyReplicas,
			"desired", desiredReplicas)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	logger.Info("Deployment is ready", "replicas", deployment.Status.ReadyReplicas)
	return ctrl.Result{}, nil
}

func ptrValueOrDefault[T any](ptr *T, defaultVal T) T {
	if ptr == nil {
		return defaultVal
	}
	return *ptr
}

func updateContainerEnv(existing, desired *corev1.Container) bool {
	updated := false
	if !equality.Semantic.DeepEqual(existing.Env, desired.Env) {
		existing.Env = desired.Env
		updated = true
	}
	return updated
}

func mergeStringMaps(dst, src map[string]string) map[string]string {
	if dst == nil && src == nil {
		return nil
	}
	if dst == nil {
		dst = map[string]string{}
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// ensureRBAC creates the ServiceAccount, Role, and RoleBinding for the agent if they don't exist.
func (r *AgentReconciler) ensureRBAC(ctx context.Context, agent *agentv1alpha1.Agent) (*rbac.RBACConfig, error) {
	rbacConfig := rbac.GetComponentRBACConfig(agent.Namespace, agent.Name, agent.Labels)
	rbacManager := rbac.NewRBACManager(r.Client, r.Scheme)
	if err := rbacManager.CreateRBACObjects(ctx, rbacConfig, agent); err != nil {
		return nil, fmt.Errorf("failed to create RBAC objects: %w", err)
	}
	return rbacConfig, nil
}

func (r *AgentReconciler) buildDeploymentSpec(agent *agentv1alpha1.Agent, rbacConfig *rbac.RBACConfig) (*appsv1.Deployment, error) {
	if len(agent.Spec.PodTemplateSpec.Spec.Containers) == 0 {
		return nil, fmt.Errorf("no containers defined in PodTemplateSpec")
	}
	replicas := int32(1)
	if agent.Spec.Replicas != nil {
		replicas = int32(*agent.Spec.Replicas)
	}
	podTemplateSpec := agent.Spec.PodTemplateSpec.DeepCopy()

	podTemplateSpec.ObjectMeta.ResourceVersion = ""
	podTemplateSpec.ObjectMeta.UID = ""

	labels := map[string]string{
		"app.kubernetes.io/name": agent.Name,
	}
	for k, v := range agent.Labels {
		if _, exists := labels[k]; !exists {
			labels[k] = v
		}
	}

	for i := range podTemplateSpec.Spec.Containers {
		container := &podTemplateSpec.Spec.Containers[i]

		if i == 0 {
			container.Image = agent.Spec.Image
			logger.Info("Using image for Agent", "image", agent.Spec.Image)
		}

		if len(container.Ports) == 0 {
			container.Ports = []corev1.ContainerPort{
				{
					Name:          "http",
					ContainerPort: 8000,
					Protocol:      corev1.ProtocolTCP,
				},
			}
		}
	}

	r.addVolumesAndMounts(podTemplateSpec)
	if podTemplateSpec.Spec.ServiceAccountName == "" {
		podTemplateSpec.Spec.ServiceAccountName = rbacConfig.ServiceAccountName
	}

	if podTemplateSpec.Spec.SecurityContext == nil {
		podSecCtx := &corev1.PodSecurityContext{
			RunAsNonRoot: ptr.To(true),
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
		}

		// OpenShift SCC injects RunAsUser/FSGroup; only set them on vanilla Kubernetes.
		if r.Distribution != distribution.OpenShift {
			podSecCtx.RunAsUser = ptr.To(int64(1000))
			podSecCtx.FSGroup = ptr.To(int64(1000))
		}

		podTemplateSpec.Spec.SecurityContext = podSecCtx
	}

	for i := range podTemplateSpec.Spec.Containers {
		if podTemplateSpec.Spec.Containers[i].SecurityContext == nil {
			podTemplateSpec.Spec.Containers[i].SecurityContext = &corev1.SecurityContext{
				AllowPrivilegeEscalation: ptr.To(false),
				Privileged:               ptr.To(false),
				ReadOnlyRootFilesystem:   ptr.To(true),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			}
		}
	}

	if podTemplateSpec.ObjectMeta.Labels == nil {
		podTemplateSpec.ObjectMeta.Labels = make(map[string]string)
	}
	for k, v := range labels {
		podTemplateSpec.ObjectMeta.Labels[k] = v
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:        agent.Name,
			Namespace:   agent.Namespace,
			Labels:      labels,
			Annotations: agent.Annotations,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: *podTemplateSpec,
		},
	}, nil
}

func (r *AgentReconciler) volumeExists(podTemplateSpec *corev1.PodTemplateSpec, volumeName string) bool {
	for _, vol := range podTemplateSpec.Spec.Volumes {
		if vol.Name == volumeName {
			return true
		}
	}
	return false
}

func (r *AgentReconciler) addVolumesAndMounts(podTemplateSpec *corev1.PodTemplateSpec) {
	if !hasVolumeMounts(&podTemplateSpec.Spec, "cache") {
		if len(podTemplateSpec.Spec.Containers) > 0 {
			podTemplateSpec.Spec.Containers[0].VolumeMounts =
				append(podTemplateSpec.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
					Name:      "cache",
					MountPath: "/app/.cache",
				})
		}
	}

	if exists := r.volumeExists(podTemplateSpec, "cache"); !exists {
		podTemplateSpec.Spec.Volumes = append(podTemplateSpec.Spec.Volumes, corev1.Volume{
			Name: "cache",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		})
	}
}

func hasVolumeMounts(podSpec *corev1.PodSpec, volumeMountName string) bool {
	for _, container := range podSpec.Containers {
		for _, vm := range container.VolumeMounts {
			if vm.Name == volumeMountName {
				return true
			}
		}
	}
	return false
}

func (r *AgentReconciler) reconcileAgentService(ctx context.Context, agent *agentv1alpha1.Agent) (ctrl.Result, error) {
	serviceName := agent.Name
	service := &corev1.Service{}

	err := r.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: agent.Namespace}, service)

	if err != nil && errors.IsNotFound(err) {
		service = r.createServiceForAgent(agent)
		logger.Info("Creating Service", "serviceName", serviceName)

		if err := controllerutil.SetControllerReference(agent, service, r.Scheme); err != nil {
			logger.Error(err, "Failed to set controller reference for Service")
			return ctrl.Result{}, err
		}

		if err := r.Create(ctx, service); err != nil {
			logger.Error(err, "Failed to create Service")
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	} else if err != nil {
		logger.Error(err, "Failed to get Service")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *AgentReconciler) createServiceForAgent(agent *agentv1alpha1.Agent) *corev1.Service {
	labels := map[string]string{
		"app.kubernetes.io/name": agent.Name,
	}
	servicePorts := agent.Spec.ServicePorts
	if len(servicePorts) == 0 {
		servicePorts = []corev1.ServicePort{{
			Name:       "http",
			Protocol:   corev1.ProtocolTCP,
			Port:       8000,
			TargetPort: intstr.FromInt(8000),
		}}
	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        agent.Name,
			Namespace:   agent.Namespace,
			Labels:      labels,
			Annotations: agent.Annotations,
		},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports:    servicePorts,
		},
	}
}

func (r *AgentReconciler) handleDeletion(ctx context.Context, agent *agentv1alpha1.Agent) (ctrl.Result, error) {
	if controllerutil.ContainsFinalizer(agent, AgentFinalizer) {
		deployment := &appsv1.Deployment{}
		deploymentName := agent.Name
		err := r.Get(ctx, types.NamespacedName{Name: deploymentName, Namespace: agent.Namespace}, deployment)
		if err == nil {
			logger.Info("Deleting deployment for Agent", "deploymentName", deploymentName)
			if err := r.Delete(ctx, deployment); err != nil && !errors.IsNotFound(err) {
				logger.Error(err, "Failed to delete deployment for Agent", "deploymentName", deploymentName)
				return ctrl.Result{}, err
			}
		} else if !errors.IsNotFound(err) {
			logger.Error(err, "Failed to get deployment for deletion", "deploymentName", deploymentName)
			return ctrl.Result{}, err
		}

		service := &corev1.Service{}
		serviceName := agent.Name
		err = r.Get(ctx, types.NamespacedName{Name: serviceName, Namespace: agent.Namespace}, service)
		if err == nil {
			logger.Info("Deleting service for Agent", "serviceName", serviceName)
			if err := r.Delete(ctx, service); err != nil && !errors.IsNotFound(err) {
				logger.Error(err, "Failed to delete service for Agent", "serviceName", serviceName)
				return ctrl.Result{}, err
			}
		} else if !errors.IsNotFound(err) {
			logger.Error(err, "Failed to get service for deletion", "serviceName", serviceName)
			return ctrl.Result{}, err
		}
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			latestAgent := &agentv1alpha1.Agent{}
			if err := r.Get(ctx, types.NamespacedName{Name: agent.Name, Namespace: agent.Namespace}, latestAgent); err != nil {
				return err
			}

			controllerutil.RemoveFinalizer(latestAgent, AgentFinalizer)
			return r.Update(ctx, latestAgent)
		}); err != nil {
			logger.Error(err, "Failed to remove finalizer from Agent after retries")
			return ctrl.Result{}, err
		}
		logger.Info("Removed finalizer from Agent")
	}

	return ctrl.Result{}, nil
}

func (r *AgentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&agentv1alpha1.Agent{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Named("Agent").
		Complete(r)
}
