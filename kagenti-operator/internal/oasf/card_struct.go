package oasf

import (
	"encoding/json"
	"fmt"

	agentv1alpha1 "github.com/kagenti/operator/api/v1alpha1"
	"google.golang.org/protobuf/types/known/structpb"
)

// AgentCardDataToStruct encodes the A2A-shaped card as a protobuf Struct for
// the oasf-sdk validator. The payload must be representable as structpb (JSON
// types only; no arbitrary binary).
func AgentCardDataToStruct(card *agentv1alpha1.AgentCardData) (*structpb.Struct, error) {
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
	s, err := structpb.NewStruct(raw)
	if err != nil {
		return nil, fmt.Errorf("structpb: %w", err)
	}
	return s, nil
}
