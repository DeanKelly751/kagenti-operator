package oasf

import (
	"context"
	"fmt"
	"sync"

	"github.com/agntcy/oasf-sdk/pkg/validator"
	"google.golang.org/protobuf/types/known/structpb"
)

// Cache holds one github.com/agntcy/oasf-sdk/pkg/validator.Validator per schema base URL.
type Cache struct {
	mu  sync.Mutex
	v   map[string]*validator.Validator
}

// NewCache returns an empty validator cache. Safe for concurrent use.
func NewCache() *Cache {
	return &Cache{v: make(map[string]*validator.Validator)}
}

func (c *Cache) getOrCreate(baseURL string) (*validator.Validator, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("OASF schema base URL is empty")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.v[baseURL]; ok {
		return v, nil
	}
	v, err := validator.New(baseURL)
	if err != nil {
		return nil, err
	}
	c.v[baseURL] = v
	return v, nil
}

// ValidateRecord runs oasf-sdk remote validation. Returns (valid, first message, err).
// Warnings from the service do not mark the record invalid.
func (c *Cache) ValidateRecord(ctx context.Context, baseURL string, s *structpb.Struct) (bool, string, error) {
	v, err := c.getOrCreate(baseURL)
	if err != nil {
		return false, "", err
	}
	return validateWithValidator(ctx, v, s)
}

func validateWithValidator(ctx context.Context, v *validator.Validator, s *structpb.Struct) (bool, string, error) {
	ok, errMsgs, warnMsgs, err := v.ValidateRecord(ctx, s)
	if err != nil {
		return false, "", err
	}
	if !ok {
		if len(errMsgs) > 0 {
			return false, errMsgs[0], nil
		}
		return false, "OASF validation failed", nil
	}
	if len(warnMsgs) > 0 {
		return true, warnMsgs[0], nil
	}
	return true, "", nil
}
