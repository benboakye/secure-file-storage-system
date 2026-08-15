package authn

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResendMailerSendsBoundedVerificationRequest(t *testing.T) {
	var received resendEmailRequest
	var authorization, contentType, idempotency string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authorization = request.Header.Get("Authorization")
		contentType = request.Header.Get("Content-Type")
		idempotency = request.Header.Get("Idempotency-Key")
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Errorf("decode request: %v", err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"id":"email_test"}`))
	}))
	defer server.Close()

	mailer, err := NewResendMailer(ResendMailerConfig{
		APIKey: "re_test_only_key", From: "SecureVault <no-reply@mail.securevault.tech>",
		Endpoint: server.URL, Client: server.Client(), AllowHTTPForTests: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	message := VerificationMessage{
		To: "user@example.test", Name: "Test User",
		VerificationURL: "https://securevault.tech/#verify-email?token=secret-token",
		ExpiresAt:       time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC),
	}
	if err := mailer.SendVerification(message); err != nil {
		t.Fatal(err)
	}
	if authorization != "Bearer re_test_only_key" || contentType != "application/json" {
		t.Fatalf("provider authentication headers were not set correctly")
	}
	if !strings.HasPrefix(idempotency, "verification-") || strings.Contains(idempotency, "secret-token") {
		t.Fatalf("idempotency key did not safely digest the verification token: %q", idempotency)
	}
	if received.From != "SecureVault <no-reply@mail.securevault.tech>" || len(received.To) != 1 || received.To[0] != message.To {
		t.Fatalf("unexpected provider envelope: %#v", received)
	}
	if received.Subject != "Verify your SecureStore email" || !strings.Contains(received.Text, message.VerificationURL) || !strings.Contains(received.Text, message.ExpiresAt.Format(time.RFC3339)) {
		t.Fatalf("verification content is incomplete: %#v", received)
	}
}

func TestResendMailerFailsClosed(t *testing.T) {
	tests := []ResendMailerConfig{
		{APIKey: "", From: "SecureVault <no-reply@mail.securevault.tech>"},
		{APIKey: "re_test_only_key", From: "not-an-address"},
		{APIKey: "re_test_only_key", From: "SecureVault <no-reply@mail.securevault.tech>", Endpoint: "http://api.resend.com/emails"},
		{APIKey: "re_test_only_key", From: "SecureVault <no-reply@mail.securevault.tech>", Endpoint: "https://example.test/emails"},
	}
	for index, config := range tests {
		if _, err := NewResendMailer(config); err == nil {
			t.Fatalf("invalid configuration %d was accepted", index)
		}
	}
}

func TestResendMailerDoesNotReturnProviderBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
		_, _ = writer.Write([]byte("sensitive provider detail"))
	}))
	defer server.Close()
	mailer, err := NewResendMailer(ResendMailerConfig{
		APIKey: "re_test_only_key", From: "SecureVault <no-reply@mail.securevault.tech>",
		Endpoint: server.URL, Client: server.Client(), AllowHTTPForTests: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = mailer.SendVerification(VerificationMessage{To: "user@example.test", VerificationURL: "https://example.test/token", ExpiresAt: time.Now()})
	if err == nil || strings.Contains(err.Error(), "sensitive provider detail") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("provider failure was not safely bounded: %v", err)
	}
}
