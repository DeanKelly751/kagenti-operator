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

// Package distribution detects the Kubernetes distribution (vanilla vs. OpenShift).
package distribution

import (
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
)

var logger = ctrl.Log.WithName("distribution")

type Type string

const (
	Kubernetes Type = "kubernetes"
	OpenShift  Type = "openshift"
)

// Detect probes the API server for distribution-specific API groups.
func Detect(config *rest.Config) Type {
	dc, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		logger.Error(err, "Failed to create discovery client, defaulting to kubernetes")
		return Kubernetes
	}

	_, err = dc.ServerResourcesForGroupVersion("config.openshift.io/v1")
	if err == nil {
		logger.Info("Detected OpenShift distribution")
		return OpenShift
	}

	logger.Info("Detected Kubernetes distribution")
	return Kubernetes
}
