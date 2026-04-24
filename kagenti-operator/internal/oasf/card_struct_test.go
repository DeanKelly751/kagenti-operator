package oasf

import (
	"testing"

	agentv1alpha1 "github.com/kagenti/operator/api/v1alpha1"
)

func TestAgentCardDataToStruct(t *testing.T) {
	card := &agentv1alpha1.AgentCardData{Name: "n", Version: "1", URL: "http://x"}
	s, err := AgentCardDataToStruct(card)
	if err != nil {
		t.Fatal(err)
	}
	if s.GetFields()["name"].GetStringValue() != "n" {
		t.Fatalf("name: %v", s.GetFields()["name"])
	}
}
