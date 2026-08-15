package authn

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type DiscardMailer struct{}

func (DiscardMailer) SendVerification(VerificationMessage) error { return nil }

// FileMailer is a development-only delivery adapter. It writes verification
// messages to a private local mailbox without logging tokens to stdout.
type FileMailer struct{ Directory string }

func (m FileMailer) SendVerification(message VerificationMessage) error {
	if strings.TrimSpace(m.Directory) == "" {
		return fmt.Errorf("mailbox directory is required")
	}
	if err := os.MkdirAll(m.Directory, 0o700); err != nil {
		return err
	}
	identifier, err := opaqueID("verify")
	if err != nil {
		return err
	}
	path := filepath.Join(m.Directory, time.Now().UTC().Format("20060102T150405.000000000Z")+"_"+identifier+".txt")
	body := fmt.Sprintf("To: %s\nSubject: Verify your SecureStore email\n\nHello %s,\n\nVerify your email address by opening this link:\n%s\n\nThis link expires at %s and can be used only once. After verification, return to SecureStore and sign in manually.\n", message.To, message.Name, message.VerificationURL, message.ExpiresAt.UTC().Format(time.RFC3339))
	return os.WriteFile(path, []byte(body), 0o600)
}

// ResendMailerConfig defines the outbound transactional-email boundary. The
// API key must be supplied by a secret source; it is never read from a request
// or included in logs. AllowHTTP exists only for isolated unit-test servers.
type ResendMailerConfig struct {
	APIKey            string
	From              string
	Endpoint          string
	Timeout           time.Duration
	Client            *http.Client
	AllowHTTPForTests bool
}

// ResendMailer sends verification messages directly to Resend's HTTPS API.
// It intentionally uses the standard library so the authentication service
// does not depend on a frontend SDK or expose the provider key to the browser.
type ResendMailer struct {
	apiKey   string
	from     string
	endpoint string
	client   *http.Client
}

type resendEmailRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Text    string   `json:"text"`
}

func NewResendMailer(config ResendMailerConfig) (*ResendMailer, error) {
	apiKey := strings.TrimSpace(config.APIKey)
	if !strings.HasPrefix(apiKey, "re_") || len(apiKey) < 8 {
		return nil, fmt.Errorf("Resend API key is missing or invalid")
	}
	from := strings.TrimSpace(config.From)
	address, err := mail.ParseAddress(from)
	if err != nil || strings.TrimSpace(address.Address) == "" {
		return nil, fmt.Errorf("Resend sender address is invalid")
	}
	endpoint := strings.TrimSpace(config.Endpoint)
	if endpoint == "" {
		endpoint = "https://api.resend.com/emails"
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || (parsed.Scheme != "https" && !(config.AllowHTTPForTests && parsed.Scheme == "http")) {
		return nil, fmt.Errorf("Resend endpoint must be an HTTPS URL")
	}
	if !config.AllowHTTPForTests && (parsed.Hostname() != "api.resend.com" || parsed.Path != "/emails" || parsed.RawQuery != "") {
		return nil, fmt.Errorf("Resend endpoint must use the official email API")
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := config.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	} else {
		clone := *client
		if clone.Timeout <= 0 {
			clone.Timeout = timeout
		}
		client = &clone
	}
	// Refuse redirects so the bearer credential and verification payload remain
	// bound to the configured provider endpoint.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &ResendMailer{apiKey: apiKey, from: from, endpoint: endpoint, client: client}, nil
}

func (m *ResendMailer) SendVerification(message VerificationMessage) error {
	recipient, err := mail.ParseAddress(strings.TrimSpace(message.To))
	if err != nil || recipient.Address != strings.TrimSpace(message.To) {
		return fmt.Errorf("verification recipient is invalid")
	}
	body := fmt.Sprintf("Hello %s,\n\nVerify your email address by opening this link:\n%s\n\nThis link expires at %s and can be used only once. After verification, return to SecureStore and sign in manually.\n", message.Name, message.VerificationURL, message.ExpiresAt.UTC().Format(time.RFC3339))
	payload, err := json.Marshal(resendEmailRequest{
		From: m.from, To: []string{recipient.Address},
		Subject: "Verify your SecureStore email", Text: body,
	})
	if err != nil {
		return fmt.Errorf("encode verification email: %w", err)
	}
	request, err := http.NewRequest(http.MethodPost, m.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create Resend request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+m.apiKey)
	request.Header.Set("Content-Type", "application/json")
	// The raw verification token never becomes an HTTP header. A deterministic
	// digest prevents duplicate delivery during provider/network retries while a
	// newly issued token receives a distinct key.
	digest := sha256.Sum256([]byte(recipient.Address + "\x00" + message.VerificationURL))
	request.Header.Set("Idempotency-Key", "verification-"+hex.EncodeToString(digest[:]))

	response, err := m.client.Do(request)
	if err != nil {
		return fmt.Errorf("send verification email: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		// Provider response bodies can include addresses or operational details;
		// return only the status so secrets and personal data stay out of logs.
		return fmt.Errorf("Resend rejected verification email with HTTP %d", response.StatusCode)
	}
	return nil
}

var _ VerificationMailer = DiscardMailer{}
var _ VerificationMailer = FileMailer{}
var _ VerificationMailer = (*ResendMailer)(nil)
