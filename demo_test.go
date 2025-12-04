package hellotest2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/traefik/plugindemo"
)

func TestDemoBlockIP(t *testing.T) {
	cfg := plugindemo.CreateConfig()
	cfg.IPDenyList = []string{"192.168.1.100", "10.0.0.0/8"}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := plugindemo.New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		remoteAddr     string
		xForwardedFor  string
		expectedStatus int
		description    string
	}{
		{
			name:           "AllowValidIP",
			remoteAddr:     "203.0.113.50:8080",
			xForwardedFor:  "",
			expectedStatus: http.StatusOK,
			description:    "should allow request from non-denied IP",
		},
		{
			name:           "BlockSingleIP",
			remoteAddr:     "192.168.1.100:8080",
			xForwardedFor:  "",
			expectedStatus: http.StatusForbidden,
			description:    "should block request from single denied IP",
		},
		{
			name:           "BlockIPInCIDR",
			remoteAddr:     "10.0.0.50:8080",
			xForwardedFor:  "",
			expectedStatus: http.StatusForbidden,
			description:    "should block request from IP in denied CIDR range",
		},
		{
			name:           "BlockIPFromXForwardedFor",
			remoteAddr:     "203.0.113.50:8080",
			xForwardedFor:  "192.168.1.100, 203.0.113.50",
			expectedStatus: http.StatusForbidden,
			description:    "should block request when denied IP in X-Forwarded-For",
		},
		{
			name:           "AllowIPFromXForwardedFor",
			remoteAddr:     "203.0.113.50:8080",
			xForwardedFor:  "203.0.113.60, 203.0.113.50",
			expectedStatus: http.StatusOK,
			description:    "should allow request when no denied IPs in X-Forwarded-For",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.RemoteAddr = tt.remoteAddr
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}

			handler.ServeHTTP(recorder, req)

			if recorder.Code != tt.expectedStatus {
				t.Errorf("%s: got status %d, expected %d", tt.description, recorder.Code, tt.expectedStatus)
			}
		})
	}
}

func TestDemoEmptyDenyList(t *testing.T) {
	cfg := plugindemo.CreateConfig()
	cfg.IPDenyList = []string{}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	_, err := plugindemo.New(ctx, next, cfg, "demo-plugin")
	if err == nil {
		t.Error("expected error when IPDenyList is empty")
	}
}

func TestDemoInvalidIP(t *testing.T) {
	cfg := plugindemo.CreateConfig()
	cfg.IPDenyList = []string{"invalid-ip-format"}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	_, err := plugindemo.New(ctx, next, cfg, "demo-plugin")
	if err == nil {
		t.Error("expected error when IPDenyList contains invalid IP format")
	}
}