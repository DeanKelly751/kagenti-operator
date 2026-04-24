package agntcy

import (
	"testing"

	agentv1alpha1 "github.com/kagenti/operator/api/v1alpha1"
)

func TestAgentRecord(t *testing.T) {
	card := &agentv1alpha1.AgentCardData{
		Name:    "poc",
		Version: "1",
		URL:     "http://example/svc",
	}
	rec, err := AgentRecord(card)
	if err != nil {
		t.Fatalf("AgentRecord: %v", err)
	}
	if rec.GetData() == nil {
		t.Fatal("expected data")
	}
	if rec.GetData().GetFields()["name"].GetStringValue() != "poc" {
		t.Fatalf("unexpected name field: %v", rec.GetData().GetFields()["name"])
	}
}

func TestPocResourceOptIn(t *testing.T) {
	if !PocResourceOptIn(map[string]string{LabelPoc: "true"}) {
		t.Fatal("expected opt-in")
	}
	if PocResourceOptIn(map[string]string{"other": "x"}) {
		t.Fatal("expected opt-out")
	}
}
