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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testAgentCardJSON = `{"name":"test-agent","version":"1.0","url":"http://example.com"}`

func TestDefaultFetcher_SuccessfulA2ACardFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != A2AAgentCardPath {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(testAgentCardJSON))
	}))
	defer server.Close()

	result, err := NewFetcher().Fetch(context.Background(), A2AProtocol, server.URL)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if result.Name != "test-agent" {
		t.Errorf("Name: got %q, want %q", result.Name, "test-agent")
	}
	if result.Version != "1.0" {
		t.Errorf("Version: got %q, want %q", result.Version, "1.0")
	}
}

func TestFetchA2ACard_LegacyFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == A2ALegacyAgentCardPath {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(testAgentCardJSON))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	fetcher := NewFetcher()
	card, err := fetcher.Fetch(context.Background(), A2AProtocol, srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if card.Name != "test-agent" {
		t.Errorf("expected name %q, got %q", "test-agent", card.Name)
	}
}

func TestFetchA2ACard_BothNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	fetcher := NewFetcher()
	_, err := fetcher.Fetch(context.Background(), A2AProtocol, srv.URL)
	if err == nil {
		t.Fatal("expected error when both endpoints return 404")
	}
}

func TestDefaultFetcher_UnsupportedProtocol(t *testing.T) {
	_, err := NewFetcher().Fetch(context.Background(), "unsupported", "http://example.com")
	if err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
	if !strings.Contains(err.Error(), "unsupported protocol") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDefaultFetcher_HTTPError500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("error body"))
	}))
	defer server.Close()

	_, err := NewFetcher().Fetch(context.Background(), A2AProtocol, server.URL)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "unexpected status code") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDefaultFetcher_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	_, err := NewFetcher().Fetch(context.Background(), A2AProtocol, server.URL)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "failed to parse agent card JSON") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGetServiceURL(t *testing.T) {
	got := GetServiceURL("my-agent", "default", 8080)
	want := "http://my-agent.default.svc.cluster.local:8080"
	if got != want {
		t.Errorf("GetServiceURL: got %q, want %q", got, want)
	}
}
