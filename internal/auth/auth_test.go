package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		wantKey    string
		wantErr    error
		shouldFail bool
	}{
		{
			name:       "valid ApiKey header",
			header:     "ApiKey secret123",
			wantKey:    "secret123",
			wantErr:    nil,
			shouldFail: false,
		},
		{
			name:       "missing Authorization header",
			header:     "",
			wantKey:    "",
			wantErr:    auth.ErrNoAuthHeaderIncluded,
			shouldFail: true,
		},
		{
			name:       "wrong prefix (Bearer)",
			header:     "Bearer token123",
			wantKey:    "",
			wantErr:    errors.New("malformed authorization header"),
			shouldFail: true,
		},
		{
			name:       "missing key after ApiKey",
			header:     "ApiKey",
			wantKey:    "",
			wantErr:    errors.New("malformed authorization header"),
			shouldFail: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.header != "" {
				h.Set("Authorization", tc.header)
			}

			key, err := auth.GetAPIKey(h)

			if tc.shouldFail {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}

				// Check error type or message
				if tc.wantErr != nil && err.Error() != tc.wantErr.Error() {
					t.Fatalf("expected error %v, got %v", tc.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("did not expect error, got %v", err)
			}

			if key != tc.wantKey {
				t.Fatalf("expected key %q, got %q", tc.wantKey, key)
			}
		})
	}
}
