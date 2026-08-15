package protectedstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRemoteKeyProviderWrapUnwrapAndHardwarePosture(t *testing.T) {
	dek := bytes.Repeat([]byte{0x42}, 32)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/status":
			if request.Method != http.MethodGet || request.URL.Query().Get("keyId") != "securestore-kek" || request.URL.Query().Get("keyVersion") != "v2" {
				t.Errorf("unexpected status request: %s %s", request.Method, request.URL.String())
			}
			_ = json.NewEncoder(response).Encode(remoteKeyResponse{KeyID: "securestore-kek", KeyVersion: "v2", Status: "enabled", Provider: "test-hsm", HardwareBacked: true})
		case "/v1/wrap", "/v1/unwrap":
			var input remoteKeyRequest
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Error(err)
				return
			}
			if input.KeyID != "securestore-kek" || input.KeyVersion != "v2" || input.Purpose != remoteKeyPurpose {
				t.Errorf("unsafe key request metadata: %#v", input)
			}
			if request.URL.Path == "/v1/wrap" {
				if !bytes.Equal(input.PlaintextDEK, dek) || len(input.WrappedDEK) != 0 {
					t.Error("wrap request did not contain exactly one DEK")
				}
				_ = json.NewEncoder(response).Encode(remoteKeyResponse{KeyID: input.KeyID, KeyVersion: input.KeyVersion, WrappedDEK: append([]byte("broker-wrapper:"), input.PlaintextDEK...)})
				return
			}
			if !bytes.HasPrefix(input.WrappedDEK, []byte("broker-wrapper:")) || len(input.PlaintextDEK) != 0 {
				t.Error("unwrap request did not contain exactly one wrapped DEK")
			}
			_ = json.NewEncoder(response).Encode(remoteKeyResponse{KeyID: input.KeyID, KeyVersion: input.KeyVersion, PlaintextDEK: append([]byte(nil), input.WrappedDEK[len("broker-wrapper:"):]...)})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	provider, err := newRemoteKeyProvider(RemoteKeyConfig{Endpoint: server.URL, KeyID: "securestore-kek", KeyVersion: "v2", Timeout: time.Second}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	posture := provider.Posture()
	if !posture.Connected || !posture.ProductionReady || !posture.HardwareBacked || posture.Provider != "test-hsm" || posture.Adapter != "remote-kms-mtls" {
		t.Fatalf("managed key posture was inaccurate: %#v", posture)
	}
	wrapper, err := provider.Wrap(dek)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := provider.Unwrap(wrapper, "securestore-kek", "v2")
	if err != nil || !bytes.Equal(opened, dek) {
		t.Fatalf("managed key round trip failed: %x err=%v", opened, err)
	}
}

func TestRemoteKeyProviderFailsClosedOnIdentityMismatchAndUnsafeResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "wrong version", body: `{"keyId":"securestore-kek","keyVersion":"v1","wrappedDek":"d3JhcHBlZA=="}`},
		{name: "plaintext returned by wrap", body: `{"keyId":"securestore-kek","keyVersion":"v2","wrappedDek":"d3JhcHBlZA==","plaintextDek":"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="}`},
		{name: "unknown response field", body: `{"keyId":"securestore-kek","keyVersion":"v2","wrappedDek":"d3JhcHBlZA==","debug":"secret"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				_, _ = response.Write([]byte(test.body))
			}))
			defer server.Close()
			provider, err := newRemoteKeyProvider(RemoteKeyConfig{Endpoint: server.URL, KeyID: "securestore-kek", KeyVersion: "v2", Timeout: time.Second}, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.Wrap(bytes.Repeat([]byte{0x31}, 32)); !errors.Is(err, ErrKeyServiceUnavailable) {
				t.Fatalf("unsafe broker response did not fail closed: %v", err)
			}
		})
	}
}

func TestRemoteKeyProviderRejectsInsecureConfigurationAndNonHardwarePosture(t *testing.T) {
	if _, err := newRemoteKeyProvider(RemoteKeyConfig{Endpoint: "http://key-broker.internal", KeyID: "securestore-kek", KeyVersion: "v1", Timeout: time.Second}, http.DefaultClient); err == nil {
		t.Fatal("plaintext managed key endpoint was accepted")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(remoteKeyResponse{KeyID: "securestore-kek", KeyVersion: "v1", Status: "enabled", Provider: "software-vault", HardwareBacked: false})
	}))
	defer server.Close()
	provider, err := newRemoteKeyProvider(RemoteKeyConfig{Endpoint: server.URL, KeyID: "securestore-kek", KeyVersion: "v1", Timeout: time.Second}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	posture := provider.Posture()
	if !posture.Connected || posture.ProductionReady || posture.HardwareBacked {
		t.Fatalf("software custody was represented as production-ready: %#v", posture)
	}
}
