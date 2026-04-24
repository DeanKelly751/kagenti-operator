package agntcy

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// ProbeIdentityURL performs a GET with a short timeout. This is a PoC
// "wire check" for an AGNTCY identity (or any HTTP) service — not
// verifiable-credential issuance.
func ProbeIdentityURL(ctx context.Context, rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("identity probe url is empty")
	}
	c := &http.Client{Timeout: 5 * time.Second} //nolint:exhaustruct
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	res, err := c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("unexpected status: %d", res.StatusCode)
	}
	return nil
}
