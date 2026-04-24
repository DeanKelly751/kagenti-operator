package agntcy

import (
	"encoding/json"
	"fmt"

	agentv1alpha1 "github.com/kagenti/operator/api/v1alpha1"
	corev1 "github.com/agntcy/dir/api/core/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

// AgentRecord builds a directory core record whose Data field embeds the
// A2A-shaped AgentCard payload as a generic JSON object. Full OASF agent
// class encoding may require a richer mapping; the PoC uses this transport so
// DIR can store and re-discover the card bytes.
func AgentRecord(card *agentv1alpha1.AgentCardData) (*corev1.Record, error) {
	if card == nil {
		return nil, fmt.Errorf("agent card data is nil")
	}
	b, err := json.Marshal(card)
	if err != nil {
		return nil, fmt.Errorf("marshal agent card: %w", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal to map: %w", err)
	}
	// Mark provenance for discovery / debugging
	raw["kagenti_poc"] = map[string]any{
		"source": "kagenti-operator/AgentCard.status.card",
	}
	s, err := structpb.NewStruct(raw)
	if err != nil {
		return nil, fmt.Errorf("structpb: %w", err)
	}
	return &corev1.Record{Data: s}, nil
}
