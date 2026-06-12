package config

import "testing"

// TransparentPort is the REDIRECT target for the enforce-redirect guard; it must
// be a valid, non-privileged port (the proxy binds it as a non-root user).
func TestValidate_TransparentPort(t *testing.T) {
	tests := []struct {
		name    string
		port    int32
		wantErr bool
	}{
		{"default 8082 ok", 8082, false},
		{"zero rejected", 0, true},
		{"privileged rejected", 80, true},
		{"too large rejected", 70000, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := CompiledDefaults()
			c.Proxy.TransparentPort = tt.port
			err := c.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("expected validation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}
