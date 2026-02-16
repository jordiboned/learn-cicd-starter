package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		wantAPIKey     string
		wantErr        error
		wantErrMessage string
	}{
		{
			name:           "no authorization header",
			headers:        http.Header{},
			wantAPIKey:     "",
			wantErr:        ErrNoAuthHeaderIncluded,
			wantErrMessage: "no authorization header included",
		},
		{
			name: "empty authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			wantAPIKey:     "",
			wantErr:        ErrNoAuthHeaderIncluded,
			wantErrMessage: "no authorization header included",
		},
		{
			name: "valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123xyz"},
			},
			wantAPIKey: "abc123xyz",
			wantErr:    nil,
		},
		{
			name: "malformed - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer token123"},
			},
			wantAPIKey:     "",
			wantErr:        errors.New("malformed authorization header"),
			wantErrMessage: "malformed authorization header",
		},
		{
			name: "malformed - only ApiKey without value",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantAPIKey:     "",
			wantErr:        errors.New("malformed authorization header"),
			wantErrMessage: "malformed authorization header",
		},
		{
			name: "case sensitive prefix - ApiKey vs apikey",
			headers: http.Header{
				"Authorization": []string{"apikey valor123"},
			},
			wantAPIKey:     "",
			wantErr:        errors.New("malformed authorization header"),
			wantErrMessage: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			// Verificar el valor retornado
			if got != tt.wantAPIKey {
				t.Errorf("GetAPIKey() got = %q, want %q", got, tt.wantAPIKey)
			}

			// Verificar si hay error o no
			if (err != nil) != (tt.wantErr != nil) {
				t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr != nil)
				return
			}

			// Si esperamos error, comparamos el mensaje
			if err != nil && tt.wantErr != nil {
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("GetAPIKey() error message = %q, want %q", err.Error(), tt.wantErr.Error())
				}
			}
		})
	}
}
