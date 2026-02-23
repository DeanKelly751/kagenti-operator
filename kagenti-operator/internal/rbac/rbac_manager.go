package rbac

import (
	"context"
	"fmt"

	agentv1alpha1 "github.com/kagenti/operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type RBACManager struct {
	client.Client
	Scheme *runtime.Scheme
}

type RBACConfig struct {
	ServiceAccountName string
	RoleName           string
	BindingName        string
	Namespace          string
	Rules              []rbacv1.PolicyRule
	Labels             map[string]string
	Annotations        map[string]string
}

func NewRBACManager(client client.Client, scheme *runtime.Scheme) *RBACManager {
	return &RBACManager{
		Client: client,
		Scheme: scheme,
	}
}

func (r *RBACManager) CreateRBACObjects(ctx context.Context, config *RBACConfig, agent *agentv1alpha1.Agent) error {
	logger := log.FromContext(ctx)
	logger.Info("Creating RBAC objects", "serviceAccount", config.ServiceAccountName, "Role", config.RoleName)
	if err := r.createServiceAccount(ctx, config, agent); err != nil {
		return fmt.Errorf("failed to create ServiceAccount: %w", err)
	}
	if err := r.createRole(ctx, config, agent); err != nil {
		return fmt.Errorf("failed to create Role: %w", err)
	}
	if err := r.createRoleBinding(ctx, config, agent); err != nil {
		return fmt.Errorf("failed to create RoleBinding: %w", err)
	}
	logger.Info("Successfully created all RBAC objects [ServiceAccount, Role, RoleBinding]")
	return nil
}

func (r *RBACManager) createServiceAccount(ctx context.Context, config *RBACConfig, agent *agentv1alpha1.Agent) error {
	logger := log.FromContext(ctx)
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        config.ServiceAccountName,
			Namespace:   config.Namespace,
			Labels:      config.Labels,
			Annotations: config.Annotations,
		},
	}
	if err := controllerutil.SetOwnerReference(agent, serviceAccount, r.Scheme); err != nil {
		return fmt.Errorf("failed to set owner reference for ServiceAccount: %w", err)
	}
	existing := &corev1.ServiceAccount{}
	err := r.Get(ctx, types.NamespacedName{Name: config.ServiceAccountName, Namespace: config.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Creating ServiceAccount", "name", config.ServiceAccountName, "namespace", config.Namespace)
			if err := r.Create(ctx, serviceAccount); err != nil {
				return fmt.Errorf("failed to create ServiceAccount: %w", err)
			}
			logger.Info("ServiceAccount created successfully")
		} else {
			return fmt.Errorf("failed to get ServiceAccount: %w", err)
		}
	}
	return nil
}

func (r *RBACManager) createRole(ctx context.Context, config *RBACConfig, agent *agentv1alpha1.Agent) error {
	logger := log.FromContext(ctx)
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:        config.RoleName,
			Namespace:   config.Namespace,
			Labels:      config.Labels,
			Annotations: config.Annotations,
		},
		Rules: config.Rules,
	}

	if err := controllerutil.SetOwnerReference(agent, role, r.Scheme); err != nil {
		logger.Info("Warning: Could not set owner reference for Role", "error", err)
	}
	existing := &rbacv1.Role{}
	err := r.Get(ctx, types.NamespacedName{Name: config.RoleName, Namespace: config.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Creating Role", "name", config.RoleName)
			if err := r.Create(ctx, role); err != nil {
				return fmt.Errorf("failed to create Role: %w", err)
			}
			logger.Info("Role created successfully")
		} else {
			return fmt.Errorf("failed to get Role: %w", err)
		}
	}
	return nil
}

func (r *RBACManager) createRoleBinding(ctx context.Context, config *RBACConfig, agent *agentv1alpha1.Agent) error {
	logger := log.FromContext(ctx)
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:        config.BindingName,
			Namespace:   config.Namespace,
			Labels:      config.Labels,
			Annotations: config.Annotations,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      config.ServiceAccountName,
				Namespace: config.Namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     config.RoleName,
		},
	}
	if err := controllerutil.SetOwnerReference(agent, roleBinding, r.Scheme); err != nil {
		logger.Info("Warning: Could not set owner reference for RoleBinding (may be due to scope mismatch)", "error", err)
	}

	existing := &rbacv1.RoleBinding{}
	err := r.Get(ctx, types.NamespacedName{Name: config.BindingName, Namespace: config.Namespace}, existing)

	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Creating RoleBinding", "name", config.BindingName)
			if err := r.Create(ctx, roleBinding); err != nil {
				return fmt.Errorf("failed to create RoleBinding: %w", err)
			}
			logger.Info("RoleBinding created successfully")
		} else {
			return fmt.Errorf("failed to get RoleBinding: %w", err)
		}
	}

	return nil
}

func GetComponentRBACConfig(namespace, serviceAccountName string, labels map[string]string) *RBACConfig {
	return &RBACConfig{
		ServiceAccountName: serviceAccountName,
		RoleName:           serviceAccountName,
		BindingName:        serviceAccountName,
		Namespace:          namespace,
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "pods/log", "configmaps", "secrets"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
		Labels: labels,
	}
}
