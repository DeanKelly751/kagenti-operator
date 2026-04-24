/*
Copyright 2025.

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

package v1alpha1

// OASFConfig requests validation of the agent card payload (after a successful
// HTTP fetch) against the [AGNTCY OASF] schema service used by
// [github.com/agntcy/oasf-sdk/pkg/validator]. Validation runs in the
// AgentCard reconciler after the card is cached in status, which is the
// Kubernetes-idiomatic point when the fetched data exists (it is not present
// at spec-only admission time).
//
// [AGNTCY OASF]: https://github.com/agntcy/oasf
type OASFConfig struct {
	// Enabled must be true for OASF validation to run. You must set either
	// schemaBaseURL here or configure the operator with a default
	// --oasf-schema-base-url.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// SchemaBaseURL is the OASF API base for validation (per card). When empty,
	// the operator's default from --oasf-schema-base-url is used.
	// +optional
	SchemaBaseURL string `json:"schemaBaseURL,omitempty"`

	// Enforce when true (the default) causes an invalid OASF check to also set
	// the Synced condition to False, similar to a failed A2A signature check.
	// When false, only the OASFValid status condition reflects the error.
	// +optional
	// +kubebuilder:default=true
	Enforce *bool `json:"enforce,omitempty"`
}

// OASFEnforceOrDefault returns whether invalid OASF should mark Synced False.
// Default is true when the field is nil (unspecified in YAML).
func (c *OASFConfig) OASFEnforceOrDefault() bool {
	if c == nil || c.Enforce == nil {
		return true
	}
	return *c.Enforce
}
