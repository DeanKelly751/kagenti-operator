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

package agentcard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	agentv1alpha1 "github.com/kagenti/operator/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
)

var fetcherLogger = ctrl.Log.WithName("agentcard").WithName("fetcher")

const (
	A2AProtocol            = "a2a"
	A2AAgentCardPath       = "/.well-known/agent-card.json"
	A2ALegacyAgentCardPath = "/.well-known/agent.json"
	DefaultFetchTimeout    = 10 * time.Second
)

type Fetcher interface {
	Fetch(ctx context.Context, protocol string, serviceURL string) (*agentv1alpha1.AgentCardData, error)
}

type DefaultFetcher struct {
	httpClient *http.Client
}

func NewFetcher() Fetcher {
	return &DefaultFetcher{
		httpClient: &http.Client{
			Timeout: DefaultFetchTimeout,
		},
	}
}

func (f *DefaultFetcher) Fetch(ctx context.Context, protocol string, serviceURL string) (*agentv1alpha1.AgentCardData, error) {
	switch protocol {
	case A2AProtocol:
		return f.fetchA2ACard(ctx, serviceURL)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

func (f *DefaultFetcher) fetchA2ACard(ctx context.Context, serviceURL string) (*agentv1alpha1.AgentCardData, error) {
	card, err := f.fetchAgentCardFromPath(ctx, serviceURL, A2AAgentCardPath)
	if err == nil {
		return card, nil
	}

	if !errors.Is(err, errNotFound) {
		return nil, err
	}

	fetcherLogger.Info("Agent card not found at current endpoint, trying legacy endpoint",
		"currentPath", A2AAgentCardPath,
		"legacyPath", A2ALegacyAgentCardPath)

	card, legacyErr := f.fetchAgentCardFromPath(ctx, serviceURL, A2ALegacyAgentCardPath)
	if legacyErr != nil {
		// Return the original error since the primary path is canonical.
		return nil, err
	}

	fetcherLogger.Info("Agent card served from deprecated endpoint",
		"deprecated", true,
		"migrateTo", A2AAgentCardPath,
		"legacyPath", A2ALegacyAgentCardPath,
		"agentName", card.Name)

	return card, nil
}

// errNotFound is returned when the agent card endpoint returns HTTP 404.
var errNotFound = errors.New("agent card not found")

func (f *DefaultFetcher) fetchAgentCardFromPath(ctx context.Context, serviceURL, path string) (*agentv1alpha1.AgentCardData, error) {
	agentCardURL := serviceURL + path
	fetcherLogger.Info("Fetching A2A agent card", "url", agentCardURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, agentCardURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch agent card: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	const maxCardSize = 1 << 20 // 1 MiB

	if resp.StatusCode == http.StatusNotFound {
		return nil, errNotFound
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxCardSize))
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCardSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var agentCardData agentv1alpha1.AgentCardData
	if err := json.Unmarshal(body, &agentCardData); err != nil {
		return nil, fmt.Errorf("failed to parse agent card JSON: %w", err)
	}

	fetcherLogger.Info("Successfully fetched agent card",
		"name", agentCardData.Name,
		"version", agentCardData.Version,
		"url", agentCardData.URL)

	return &agentCardData, nil
}

func GetServiceURL(agentName, namespace string, port int32) string {
	return fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", agentName, namespace, port)
}
