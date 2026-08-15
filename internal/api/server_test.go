package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"securestore/internal/audit"
	"securestore/internal/authn"
	"securestore/internal/ingest"
	"securestore/internal/protectedstore"
)

func TestSecurityHeadersDistinguishTLSFromDevelopmentHTTP(t *testing.T) {
	server := &Server{}
	handler := server.securityHeaders(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))

	plainRequest := httptest.NewRequest(http.MethodGet, "http://securestore.test/healthz", nil)
	plainResponse := httptest.NewRecorder()
	handler.ServeHTTP(plainResponse, plainRequest)
	if plainResponse.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("development HTTP response advertised HSTS")
	}

	tlsRequest := httptest.NewRequest(http.MethodGet, "https://securestore.test/healthz", nil)
	tlsRequest.TLS = &tls.ConnectionState{}
	tlsResponse := httptest.NewRecorder()
	handler.ServeHTTP(tlsResponse, tlsRequest)
	for header, expected := range map[string]string{
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "no-referrer",
	} {
		if tlsResponse.Header().Get(header) != expected {
			t.Fatalf("%s header mismatch: %q", header, tlsResponse.Header().Get(header))
		}
	}
	if !strings.Contains(tlsResponse.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("TLS response omitted frame-ancestor protection")
	}
}

func TestAuthenticatedUploadLifecycle(t *testing.T) {
	testServer, mailer, _ := newTestServer(t, 1024)
	defer testServer.Close()
	client := clientWithCookies(t)
	session := registerAndLoginUser(t, client, testServer.URL, mailer)

	unauthenticated := clientWithCookies(t)
	request := uploadRequest(t, testServer.URL, "training.pdf", []byte("harmless fixture"), "idem-unauth-1", session.CSRFToken)
	response, err := unauthenticated.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated upload returned %d", response.StatusCode)
	}
	_ = response.Body.Close()

	request = uploadRequest(t, testServer.URL, "training.pdf", []byte("harmless fixture"), "idem-upload-1", "incorrect")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("invalid CSRF token returned %d", response.StatusCode)
	}
	_ = response.Body.Close()

	request = uploadRequest(t, testServer.URL, "training.pdf", []byte("harmless fixture"), "idem-upload-1", session.CSRFToken)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("upload returned %d: %s", response.StatusCode, body)
	}
	var upload ingest.Upload
	decodeJSON(t, response, &upload)
	if upload.Status != ingest.StatusQuarantined || upload.ID == "" {
		t.Fatalf("unexpected initial upload: %#v", upload)
	}

	terminal := pollUpload(t, client, testServer.URL, upload.ID)
	if terminal.Status != ingest.StatusAccepted || terminal.Progress != 100 {
		t.Fatalf("unexpected terminal upload: %#v", terminal)
	}

	request = uploadRequest(t, testServer.URL, "other.pdf", []byte("different"), "idem-upload-1", session.CSRFToken)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var duplicate ingest.Upload
	decodeJSON(t, response, &duplicate)
	if duplicate.ID != upload.ID {
		t.Fatalf("idempotency created another upload: %q != %q", duplicate.ID, upload.ID)
	}
}

func TestStoredFileDownloadRequiresOwnerSessionAndReturnsAuthenticatedPlaintext(t *testing.T) {
	testServer, mailer, _ := newTestServerMode(t, 1024, true)
	defer testServer.Close()
	client := clientWithCookies(t)
	session := registerAndLoginUser(t, client, testServer.URL, mailer)
	plaintext := []byte("downloaded only after complete authentication")
	request := uploadRequest(t, testServer.URL, "protected.txt", plaintext, "idem-download-1", session.CSRFToken)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var upload ingest.Upload
	decodeJSON(t, response, &upload)
	terminal := pollUpload(t, client, testServer.URL, upload.ID)
	if terminal.Status != ingest.StatusStored {
		t.Fatalf("upload did not reach protected storage: %#v", terminal)
	}
	response, err = client.Get(testServer.URL + "/api/v1/files")
	if err != nil {
		t.Fatal(err)
	}
	var files userFilePage
	decodeJSON(t, response, &files)
	if files.Total != 1 || len(files.Files) != 1 || files.Files[0].Name != upload.Name || files.Files[0].CurrentVersionID == "" {
		t.Fatalf("owner file listing was not authoritative: %#v", files)
	}
	response, err = client.Get(testServer.URL + "/api/v1/uploads/" + upload.ID + "/content")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	content, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || !bytes.Equal(content, plaintext) || !strings.Contains(response.Header.Get("Content-Disposition"), "protected.txt") {
		t.Fatalf("unexpected protected download: status=%d headers=%v body=%q", response.StatusCode, response.Header, content)
	}
	unauthenticated := clientWithCookies(t)
	response, err = unauthenticated.Get(testServer.URL + "/api/v1/files")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated file listing returned %d", response.StatusCode)
	}
	_ = response.Body.Close()
	response, err = unauthenticated.Get(testServer.URL + "/api/v1/uploads/" + upload.ID + "/content")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated download returned %d", response.StatusCode)
	}
	_ = response.Body.Close()
}

func TestFileGrantsAndRestoreIdempotencyAreEnforced(t *testing.T) {
	testServer, mailer, repository := newTestServerMode(t, 4096, true)
	defer testServer.Close()
	ownerClient, recipientClient := clientWithCookies(t), clientWithCookies(t)
	owner := registerAndLoginNamedUser(t, ownerClient, testServer.URL, mailer, "Owner User", "owner@example.edu", "Owner-Password-9!")
	recipient := registerAndLoginNamedUser(t, recipientClient, testServer.URL, mailer, "Recipient User", "recipient@example.edu", "Recipient-Password-9!")
	plaintext := []byte("grant and restore integration fixture")
	response, err := ownerClient.Do(uploadRequest(t, testServer.URL, "shared.txt", plaintext, "grant-upload-key", owner.CSRFToken))
	if err != nil {
		t.Fatal(err)
	}
	var upload ingest.Upload
	decodeJSON(t, response, &upload)
	if terminal := pollUpload(t, ownerClient, testServer.URL, upload.ID); terminal.Status != ingest.StatusStored {
		t.Fatalf("upload status: %s", terminal.Status)
	}
	response, err = ownerClient.Get(testServer.URL + "/api/v1/files")
	if err != nil {
		t.Fatal(err)
	}
	var page userFilePage
	decodeJSON(t, response, &page)
	if len(page.Files) != 1 {
		t.Fatalf("expected one logical file: %#v", page)
	}
	fileID := page.Files[0].FileID

	response, _ = recipientClient.Get(testServer.URL + "/api/v1/files/" + fileID)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("recipient had access before grant: %d", response.StatusCode)
	}
	_ = response.Body.Close()

	createGrant := func(permission, email string) protectedstore.Grant {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"recipientEmail": email, "permission": permission})
		request, _ := http.NewRequest(http.MethodPost, testServer.URL+"/api/v1/files/"+fileID+"/grants", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://test")
		request.Header.Set("X-CSRF-Token", owner.CSRFToken)
		result, requestErr := ownerClient.Do(request)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if result.StatusCode != http.StatusCreated {
			payload, _ := io.ReadAll(result.Body)
			t.Fatalf("grant returned %d: %s", result.StatusCode, payload)
		}
		var grant protectedstore.Grant
		decodeJSON(t, result, &grant)
		return grant
	}
	grant := createGrant(protectedstore.PermissionRead, "recipient@example.edu")
	response, _ = recipientClient.Get(testServer.URL + "/api/v1/files/shared")
	var shared struct {
		Files []protectedstore.SharedFile `json:"files"`
		Total int                         `json:"total"`
	}
	decodeJSON(t, response, &shared)
	if shared.Total != 1 || len(shared.Files) != 1 || shared.Files[0].FileID != fileID || shared.Files[0].Permission != protectedstore.PermissionRead {
		t.Fatalf("shared discovery was not authoritative: %#v", shared)
	}
	response, _ = recipientClient.Get(testServer.URL + "/api/v1/files/" + fileID)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("read grant denied metadata: %d", response.StatusCode)
	}
	_ = response.Body.Close()
	response, _ = recipientClient.Get(testServer.URL + "/api/v1/files/" + fileID + "/content")
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("read grant downloaded plaintext: %d", response.StatusCode)
	}
	_ = response.Body.Close()
	updated := createGrant(protectedstore.PermissionDownload, "recipient@example.edu")
	if updated.GrantID != grant.GrantID {
		t.Fatal("updating a grant created a second active grant")
	}
	response, _ = recipientClient.Get(testServer.URL + "/api/v1/files/" + fileID + "/content")
	downloaded, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Equal(downloaded, plaintext) {
		t.Fatalf("download grant failed: %d %q", response.StatusCode, downloaded)
	}

	// The same restore request returns the same new version and does not append
	// another catalog entry, even when the client retries after an uncertain response.
	response, _ = ownerClient.Get(testServer.URL + "/api/v1/files/" + fileID)
	var before protectedstore.Details
	decodeJSON(t, response, &before)
	restore := func() protectedstore.Version {
		request, _ := http.NewRequest(http.MethodPost, testServer.URL+"/api/v1/files/"+fileID+"/versions/"+before.Versions[0].VersionID+"/restore", nil)
		request.Header.Set("Origin", "http://test")
		request.Header.Set("X-CSRF-Token", owner.CSRFToken)
		request.Header.Set("Idempotency-Key", "stable-restore-request")
		result, requestErr := ownerClient.Do(request)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if result.StatusCode != http.StatusCreated {
			payload, _ := io.ReadAll(result.Body)
			t.Fatalf("restore returned %d: %s", result.StatusCode, payload)
		}
		var version protectedstore.Version
		decodeJSON(t, result, &version)
		return version
	}
	first, retry := restore(), restore()
	if first.VersionID != retry.VersionID {
		t.Fatalf("restore retry created another version: %s != %s", first.VersionID, retry.VersionID)
	}
	response, _ = ownerClient.Get(testServer.URL + "/api/v1/files/" + fileID)
	var after protectedstore.Details
	decodeJSON(t, response, &after)
	if len(after.Versions) != 2 {
		t.Fatalf("restore retry produced %d versions", len(after.Versions))
	}

	trashRequest, _ := http.NewRequest(http.MethodPost, testServer.URL+"/api/v1/files/"+fileID+"/trash", nil)
	trashRequest.Header.Set("Origin", "http://test")
	trashRequest.Header.Set("X-CSRF-Token", owner.CSRFToken)
	response, err = ownerClient.Do(trashRequest)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("move to trash returned %v %d", err, response.StatusCode)
	}
	_ = response.Body.Close()
	response, _ = ownerClient.Get(testServer.URL + "/api/v1/files")
	page.Files = nil
	page.Total = 0
	decodeJSON(t, response, &page)
	if page.Total != 0 {
		t.Fatalf("trashed file remained in active catalog: %#v", page)
	}
	response, _ = recipientClient.Get(testServer.URL + "/api/v1/files/shared")
	shared.Files, shared.Total = nil, 0
	decodeJSON(t, response, &shared)
	if shared.Total != 0 {
		t.Fatalf("trashed file remained shared: %#v", shared)
	}
	response, _ = ownerClient.Get(testServer.URL + "/api/v1/files/trash")
	var trashPage struct {
		Files []protectedstore.LifecycleFile `json:"files"`
		Total int                            `json:"total"`
	}
	decodeJSON(t, response, &trashPage)
	if trashPage.Total != 1 || trashPage.Files[0].PurgeAfter == nil {
		t.Fatalf("trash recovery record missing: %#v", trashPage)
	}
	restoreTrashRequest, _ := http.NewRequest(http.MethodPost, testServer.URL+"/api/v1/files/"+fileID+"/restore", nil)
	restoreTrashRequest.Header.Set("Origin", "http://test")
	restoreTrashRequest.Header.Set("X-CSRF-Token", owner.CSRFToken)
	response, err = ownerClient.Do(restoreTrashRequest)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("trash restore returned %v %d", err, response.StatusCode)
	}
	_ = response.Body.Close()
	response, _ = recipientClient.Get(testServer.URL + "/api/v1/files/shared")
	shared.Files, shared.Total = nil, 0
	decodeJSON(t, response, &shared)
	if shared.Total != 0 {
		t.Fatalf("trash restore silently reactivated a revoked grant: %#v", shared)
	}
	// Restored files require a fresh explicit authorization decision.
	grant = createGrant(protectedstore.PermissionDownload, "recipient@example.edu")

	request, _ := http.NewRequest(http.MethodDelete, testServer.URL+"/api/v1/files/"+fileID+"/grants/"+grant.GrantID, nil)
	request.Header.Set("Origin", "http://test")
	request.Header.Set("X-CSRF-Token", owner.CSRFToken)
	response, err = ownerClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("revoke returned %d", response.StatusCode)
	}
	_ = response.Body.Close()
	response, _ = recipientClient.Get(testServer.URL + "/api/v1/files/" + fileID)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("revoked user retained metadata access: %d", response.StatusCode)
	}
	_ = response.Body.Close()
	response, _ = recipientClient.Get(testServer.URL + "/api/v1/files/shared")
	shared.Files, shared.Total = nil, 0
	decodeJSON(t, response, &shared)
	if shared.Total != 0 || len(shared.Files) != 0 {
		t.Fatalf("revoked file remained discoverable: %#v", shared)
	}

	// Privileged accounts are never eligible recipients, even if their address
	// is known to the owner.
	adminClient := clientWithCookies(t)
	_ = registerAndLoginNamedUser(t, adminClient, testServer.URL, mailer, "Admin Target", "admin-target@example.edu", "Admin-Password-9!")
	if err := repository.UpdateUserRole("admin-target@example.edu", "admin"); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"recipientEmail": "admin-target@example.edu", "permission": "read"})
	request, _ = http.NewRequest(http.MethodPost, testServer.URL+"/api/v1/files/"+fileID+"/grants", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	request.Header.Set("X-CSRF-Token", owner.CSRFToken)
	response, _ = ownerClient.Do(request)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("privileged recipient accepted: %d", response.StatusCode)
	}
	_ = response.Body.Close()
	_ = recipient
}

func TestUploadLimitsAndSafeErrors(t *testing.T) {
	testServer, mailer, _ := newTestServer(t, 16)
	defer testServer.Close()
	client := clientWithCookies(t)
	session := registerAndLoginUser(t, client, testServer.URL, mailer)

	request := uploadRequest(t, testServer.URL, "large.txt", []byte(strings.Repeat("x", 17)), "idem-large-1", session.CSRFToken)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload returned %d", response.StatusCode)
	}
	var apiError errorResponse
	decodeJSON(t, response, &apiError)
	if apiError.Code != "UPLOAD_TOO_LARGE" || apiError.CorrelationID == "" {
		t.Fatalf("unexpected error response: %#v", apiError)
	}

	request = uploadRequest(t, testServer.URL, "undeclared.txt", []byte("safe"), "idem-size-required", session.CSRFToken)
	request.Header.Del("X-File-Size")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("upload without size contract returned %d", response.StatusCode)
	}
	decodeJSON(t, response, &apiError)
	if apiError.Code != "INVALID_FILE_SIZE" {
		t.Fatalf("missing size contract returned %#v", apiError)
	}
}

type captureMailer struct{ messages []authn.VerificationMessage }

func (m *captureMailer) SendVerification(message authn.VerificationMessage) error {
	m.messages = append(m.messages, message)
	return nil
}

func (m *captureMailer) lastToken(t *testing.T) string {
	t.Helper()
	if len(m.messages) == 0 {
		t.Fatal("expected verification mail")
	}
	parsed, err := url.Parse(m.messages[len(m.messages)-1].VerificationURL)
	if err != nil {
		t.Fatal(err)
	}
	question := strings.Index(parsed.Fragment, "?")
	if question < 0 {
		t.Fatal("verification URL did not contain a query")
	}
	values, err := url.ParseQuery(parsed.Fragment[question+1:])
	if err != nil {
		t.Fatal(err)
	}
	return values.Get("token")
}

func newTestServer(t *testing.T, maxUploadBytes int64) (*httptest.Server, *captureMailer, *authn.MemoryRepository) {
	return newTestServerMode(t, maxUploadBytes, false)
}

func newTestServerMode(t *testing.T, maxUploadBytes int64, connectProtectedStore bool) (*httptest.Server, *captureMailer, *authn.MemoryRepository) {
	return newTestServerConfigured(t, maxUploadBytes, connectProtectedStore, "")
}

func newTestServerWithMetrics(t *testing.T, maxUploadBytes int64, metricsToken string) (*httptest.Server, *captureMailer, *authn.MemoryRepository) {
	return newTestServerConfigured(t, maxUploadBytes, false, metricsToken)
}

func newTestServerConfigured(t *testing.T, maxUploadBytes int64, connectProtectedStore bool, metricsToken string) (*httptest.Server, *captureMailer, *authn.MemoryRepository) {
	return newTestServerConfiguredAuth(t, maxUploadBytes, connectProtectedStore, metricsToken, authn.Config{})
}

func newTestServerConfiguredAuth(t *testing.T, maxUploadBytes int64, connectProtectedStore bool, metricsToken string, authConfig authn.Config) (*httptest.Server, *captureMailer, *authn.MemoryRepository) {
	return newTestServerConfiguredClock(t, maxUploadBytes, connectProtectedStore, metricsToken, authConfig, nil)
}

func newTestServerConfiguredClock(t *testing.T, maxUploadBytes int64, connectProtectedStore bool, metricsToken string, authConfig authn.Config, clock func() time.Time) (*httptest.Server, *captureMailer, *authn.MemoryRepository) {
	t.Helper()
	mailer := &captureMailer{}
	repository := authn.NewMemoryRepository()
	authConfig.Repository = repository
	authConfig.Mailer = mailer
	authConfig.SessionTTL = time.Hour
	authConfig.VerificationTTL = 30 * time.Minute
	authConfig.VerificationMinResend = time.Minute
	authConfig.PublicAppURL = "http://test"
	authStore, err := authn.NewStoreWithConfig(authConfig)
	if err != nil {
		t.Fatal(err)
	}
	var protectedService *protectedstore.Service
	if connectProtectedStore {
		keyProvider, keyErr := protectedstore.NewLocalKeyProvider(bytes.Repeat([]byte{0x61}, 32), "api-test-kek", "v1")
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		protectedService, err = protectedstore.NewService(protectedstore.Config{RootDir: t.TempDir(), MaxPlaintextBytes: maxUploadBytes, Repository: protectedstore.NewMemoryRepository(), Keys: keyProvider, Clock: clock})
		if err != nil {
			t.Fatal(err)
		}
	}
	ingestManager, err := ingest.NewManager(ingest.Config{
		QuarantineDir: t.TempDir(), MaxUploadBytes: maxUploadBytes,
		InspectionTTL: time.Second, Scanner: ingest.DeterministicScanner{},
		ProtectedStore: protectedService,
	})
	if err != nil {
		t.Fatal(err)
	}
	auditService, err := audit.NewService(audit.NewMemoryRepository(), bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(Config{
		Auth: authStore, Ingest: ingestManager, Audit: auditService, Protected: protectedService,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		AllowedOrigins: []string{"http://test"}, MaxRequestBytes: maxUploadBytes + 1024,
		MetricsToken: metricsToken, MetricsScrapeStaleAfter: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(server), mailer, repository
}

func TestMetricsExporterRequiresBearerAndUsesSafeRouteLabels(t *testing.T) {
	const token = "test-only-metrics-token-with-32-characters"
	testServer, _, _ := newTestServerWithMetrics(t, 1024, token)
	defer testServer.Close()

	// Exercise a templated route with a deliberately sensitive-looking value;
	// telemetry must record only the registered route pattern.
	response, err := http.Get(testServer.URL + "/api/v1/uploads/secret-object-identifier")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	response, err = http.Get(testServer.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated metrics returned %d", response.StatusCode)
	}
	_ = response.Body.Close()
	request, _ := http.NewRequest(http.MethodGet, testServer.URL+"/metrics", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("authenticated metrics returned %d %q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	payload, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, required := range []string{"securestore_http_requests_total", `route="/api/v1/uploads/{uploadId}"`, "securestore_capacity_active_reservations", "securestore_audit_pending_evidence", "securestore_audit_anchor_connected", "securestore_audit_anchor_production_ready", "securestore_audit_anchor_valid", "securestore_audit_anchor_lag_events", "securestore_scanner_signatures_fresh", "securestore_scanner_signature_age_seconds", "securestore_scanner_signature_max_age_seconds", "securestore_key_service_connected", "securestore_key_service_production_ready", "securestore_key_service_hardware_backed", "securestore_telemetry_scrapes_total 1"} {
		if !strings.Contains(text, required) {
			t.Fatalf("metrics omitted %q: %s", required, text)
		}
	}
	if strings.Contains(text, "secret-object-identifier") || strings.Contains(text, token) {
		t.Fatal("metrics exposed a resource identifier or bearer token")
	}
}

func clientWithCookies(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	// The race detector substantially slows bcrypt cost-12 authentication on
	// constrained CI workers. Keep a bounded timeout while allowing instrumented
	// requests to complete; production server timeouts are configured separately.
	return &http.Client{Jar: jar, Timeout: 20 * time.Second}
}

func registerAndLoginUser(t *testing.T, client *http.Client, baseURL string, mailer *captureMailer) sessionResponse {
	return registerAndLoginNamedUser(t, client, baseURL, mailer, "Jane Student", "jane@example.edu", "Correct-Horse-9!")
}

func registerAndLoginNamedUser(t *testing.T, client *http.Client, baseURL string, mailer *captureMailer, name, email, password string) sessionResponse {
	t.Helper()
	bodyBytes, _ := json.Marshal(map[string]string{"name": name, "email": email, "password": password})
	body := string(bodyBytes)
	request, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/auth/register", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusAccepted {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("registration returned %d: %s", response.StatusCode, payload)
	}
	_ = response.Body.Close()
	if len(client.Jar.Cookies(response.Request.URL)) != 0 {
		t.Fatal("registration created an authenticated cookie")
	}

	verificationBody := `{"token":"` + mailer.lastToken(t) + `"}`
	request, err = http.NewRequest(http.MethodPost, baseURL+"/api/v1/auth/verify-email", strings.NewReader(verificationBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("verification returned %d: %s", response.StatusCode, payload)
	}
	_ = response.Body.Close()
	if len(client.Jar.Cookies(response.Request.URL)) != 0 {
		t.Fatal("email verification created an authenticated cookie")
	}

	loginBytes, _ := json.Marshal(map[string]string{"email": email, "password": password})
	loginBody := string(loginBytes)
	request, err = http.NewRequest(http.MethodPost, baseURL+"/api/v1/auth/login", strings.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("login returned %d: %s", response.StatusCode, payload)
	}
	var session sessionResponse
	decodeJSON(t, response, &session)
	return session
}

func TestRegistrationDoesNotAuthenticateAndUnverifiedLoginIsBlocked(t *testing.T) {
	testServer, _, _ := newTestServer(t, 1024)
	defer testServer.Close()
	client := clientWithCookies(t)
	body := `{"name":"Jane Student","email":"jane@example.edu","password":"Correct-Horse-9!"}`
	request, _ := http.NewRequest(http.MethodPost, testServer.URL+"/api/v1/auth/register", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("registration returned %d", response.StatusCode)
	}
	_ = response.Body.Close()
	if len(client.Jar.Cookies(response.Request.URL)) != 0 {
		t.Fatal("registration set a session cookie")
	}

	loginBody := `{"email":"jane@example.edu","password":"Correct-Horse-9!"}`
	request, _ = http.NewRequest(http.MethodPost, testServer.URL+"/api/v1/auth/login", strings.NewReader(loginBody))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unverified login returned %d", response.StatusCode)
	}
	var apiError errorResponse
	decodeJSON(t, response, &apiError)
	if apiError.Code != "EMAIL_NOT_VERIFIED" {
		t.Fatalf("unexpected error: %#v", apiError)
	}
}

func TestAdminUsersRequiresAdministratorRole(t *testing.T) {
	testServer, mailer, repository := newTestServer(t, 1024)
	defer testServer.Close()
	client := clientWithCookies(t)
	registerAndLoginUser(t, client, testServer.URL, mailer)

	response, err := client.Get(testServer.URL + "/api/v1/admin/users")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("standard user received admin response: %d", response.StatusCode)
	}
	var denied errorResponse
	decodeJSON(t, response, &denied)
	if denied.Code != "ADMINISTRATOR_REQUIRED" {
		t.Fatalf("unexpected denial: %#v", denied)
	}

	response, err = client.Get(testServer.URL + "/api/v1/admin/security")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("standard user received security posture: %d", response.StatusCode)
	}
	_ = response.Body.Close()

	response, err = client.Get(testServer.URL + "/api/v1/admin/monitoring")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("standard user received system monitoring: %d", response.StatusCode)
	}
	_ = response.Body.Close()

	response, err = client.Get(testServer.URL + "/api/v1/admin/lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("standard user received lifecycle governance: %d", response.StatusCode)
	}
	_ = response.Body.Close()

	response, err = client.Get(testServer.URL + "/api/v1/admin/audit")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("standard user received organization audit: %d", response.StatusCode)
	}
	_ = response.Body.Close()

	if err := repository.UpdateUserRole("jane@example.edu", "admin"); err != nil {
		t.Fatal(err)
	}
	// Promotion revokes the standard session. The account must authenticate
	// again through the privileged endpoint before any admin API is available.
	response, err = client.Get(testServer.URL + "/api/v1/admin/users")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("promoted standard session remained authenticated: %d", response.StatusCode)
	}
	_ = response.Body.Close()

	loginBody := `{"email":"jane@example.edu","password":"Correct-Horse-9!"}`
	request, err := http.NewRequest(http.MethodPost, testServer.URL+"/api/v1/admin/auth/login", strings.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("privileged login returned %d: %s", response.StatusCode, payload)
	}
	var privilegedSession sessionResponse
	decodeJSON(t, response, &privilegedSession)

	request, err = http.NewRequest(http.MethodPost, testServer.URL+"/api/v1/uploads", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", "http://test")
	request.Header.Set("X-CSRF-Token", privilegedSession.CSRFToken)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("privileged session reached the standard file API: %d", response.StatusCode)
	}
	var fileDenied errorResponse
	decodeJSON(t, response, &fileDenied)
	if fileDenied.Code != "STANDARD_USER_REQUIRED" {
		t.Fatalf("unexpected file-operation denial: %#v", fileDenied)
	}

	response, err = client.Get(testServer.URL + "/api/v1/admin/resources")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("privileged resource metadata returned %d: %s", response.StatusCode, payload)
	}
	var resources ingest.AdminResourcePage
	decodeJSON(t, response, &resources)
	if !resources.Summary.RuntimeOnly || resources.Summary.ProtectedConnected {
		t.Fatalf("resource endpoint obscured its runtime-only boundary: %#v", resources.Summary)
	}
	response, err = client.Get(testServer.URL + "/api/v1/admin/resources/orphans")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("orphan preview returned %d", response.StatusCode)
	}
	var orphanPage orphanPreview
	decodeJSON(t, response, &orphanPage)
	if orphanPage.Candidates == nil || orphanPage.MinimumAgeSeconds != 3600 {
		t.Fatalf("orphan preview omitted its safe empty set or age policy: %#v", orphanPage)
	}
	request, err = http.NewRequest(http.MethodPost, testServer.URL+"/api/v1/admin/resources/orphans/reconcile", strings.NewReader(`{"tokens":["orp_unknown"]}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("orphan deletion without CSRF was accepted: %d", response.StatusCode)
	}
	_ = response.Body.Close()

	response, err = client.Get(testServer.URL + "/api/v1/admin/security")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("privileged security posture returned %d: %s", response.StatusCode, payload)
	}
	var posture adminSecuritySummary
	decodeJSON(t, response, &posture)
	if posture.Accounts.Total != 1 || posture.Accounts.Verified != 1 || posture.Auth.PasswordHashAlgorithm != "bcrypt" || posture.Auth.MFAEnforced {
		t.Fatalf("security posture was not authoritative: %#v", posture)
	}
	if posture.Ingestion.Scanner.ProductionReady || posture.AuditChainConnected || posture.EncryptionServiceConnected {
		t.Fatalf("security posture overstated pending integrations: %#v", posture)
	}

	response, err = client.Get(testServer.URL + "/api/v1/admin/monitoring")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("privileged system monitoring returned %d: %s", response.StatusCode, payload)
	}
	var monitoring adminMonitoringSummary
	decodeJSON(t, response, &monitoring)
	if monitoring.API.Status != "operational" || monitoring.Persistence.Authentication.Durable || monitoring.Persistence.IngestionDurable {
		t.Fatalf("monitoring did not report test repositories accurately: %#v", monitoring)
	}
	if monitoring.Policies.Ingestion.MaxUploadBytes != 1024 || monitoring.Policies.SessionTTLSeconds != 3600 {
		t.Fatalf("monitoring did not expose effective safe policy: %#v", monitoring.Policies)
	}
	if monitoring.ExternalTelemetryConnected || monitoring.BackupMonitoringConnected || monitoring.EncryptionServiceConnected {
		t.Fatalf("monitoring overstated unavailable integrations: %#v", monitoring)
	}

	response, err = client.Get(testServer.URL + "/api/v1/admin/lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("privileged lifecycle governance returned %d: %s", response.StatusCode, payload)
	}
	var lifecycle adminLifecycleSummary
	decodeJSON(t, response, &lifecycle)
	if lifecycle.Lifecycle.TrackedRecords != 0 || lifecycle.Lifecycle.MetadataDurable {
		t.Fatalf("lifecycle endpoint did not report test state accurately: %#v", lifecycle)
	}
	if !lifecycle.Capabilities.QuarantineWorkflow || !lifecycle.Capabilities.InspectionDecisions {
		t.Fatalf("implemented lifecycle controls were not reported: %#v", lifecycle.Capabilities)
	}
	if lifecycle.Capabilities.ProtectedStorage || lifecycle.Capabilities.RetentionPolicy || lifecycle.Capabilities.VerifiedRecovery {
		t.Fatalf("lifecycle endpoint overstated unavailable capabilities: %#v", lifecycle.Capabilities)
	}

	response, err = client.Get(testServer.URL + "/api/v1/admin/audit")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("privileged audit returned %d: %s", response.StatusCode, payload)
	}
	var auditPage audit.Page
	decodeJSON(t, response, &auditPage)
	if auditPage.Total < 2 || !auditPage.Verification.Valid || auditPage.Verification.VerifiedThrough != int64(auditPage.Total) {
		t.Fatalf("audit page was not authoritative: %#v", auditPage)
	}
	if auditPage.Summary.Total != auditPage.Total || auditPage.Summary.Matching != auditPage.Total {
		t.Fatalf("audit summary did not match the unfiltered page: %#v", auditPage.Summary)
	}

	response, err = client.Get(testServer.URL + "/api/v1/admin/audit?action=AUTHENTICATION&outcome=success&limit=10")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("filtered audit returned %d: %s", response.StatusCode, payload)
	}
	var filteredAudit audit.Page
	decodeJSON(t, response, &filteredAudit)
	if filteredAudit.Total == 0 || filteredAudit.Summary.Successful != filteredAudit.Total {
		t.Fatalf("structured audit filters were not applied: %#v", filteredAudit)
	}

	response, err = client.Get(testServer.URL + "/api/v1/admin/audit/export?action=AUTHENTICATION")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Audit-Chain-Valid") != "true" || !strings.Contains(response.Header.Get("Content-Type"), "text/csv") {
		t.Fatalf("audit export was not integrity-labelled CSV: status=%d headers=%v", response.StatusCode, response.Header)
	}
	exported, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if !strings.Contains(string(exported), "sequence,occurred_at") || strings.Contains(string(exported), "previous_mac") {
		t.Fatalf("audit export did not use the safe projection: %s", exported)
	}

	response, err = client.Get(testServer.URL + "/api/v1/admin/users?search=jane&limit=10")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("administrator user list returned %d: %s", response.StatusCode, payload)
	}
	var page authn.AdminUserPage
	decodeJSON(t, response, &page)
	if page.Total != 1 || len(page.Users) != 1 || page.Users[0].Email != "jane@example.edu" || page.Users[0].Role != "admin" {
		t.Fatalf("unexpected administrator page: %#v", page)
	}

	statusURL := testServer.URL + "/api/v1/admin/users/" + url.PathEscape(page.Users[0].ID) + "/status"
	request, err = http.NewRequest(http.MethodPatch, statusURL, strings.NewReader(`{"status":"suspended"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("admin mutation without CSRF returned %d", response.StatusCode)
	}
	_ = response.Body.Close()

	request, err = http.NewRequest(http.MethodPatch, statusURL, strings.NewReader(`{"status":"suspended"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	request.Header.Set("X-CSRF-Token", privilegedSession.CSRFToken)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusConflict {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("administrator self-suspension returned %d: %s", response.StatusCode, payload)
	}
	var selfSuspensionDenied errorResponse
	decodeJSON(t, response, &selfSuspensionDenied)
	if selfSuspensionDenied.Code != "SELF_MANAGEMENT_PROHIBITED" {
		t.Fatalf("unexpected self-suspension denial: %#v", selfSuspensionDenied)
	}

	revokeSelfURL := testServer.URL + "/api/v1/admin/users/" + url.PathEscape(page.Users[0].ID) + "/sessions/revoke"
	request, err = http.NewRequest(http.MethodPost, revokeSelfURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", "http://test")
	request.Header.Set("X-CSRF-Token", privilegedSession.CSRFToken)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusConflict {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("administrator self-revocation returned %d: %s", response.StatusCode, payload)
	}
	var selfRevocationDenied errorResponse
	decodeJSON(t, response, &selfRevocationDenied)
	if selfRevocationDenied.Code != "SELF_MANAGEMENT_PROHIBITED" {
		t.Fatalf("unexpected self-revocation denial: %#v", selfRevocationDenied)
	}

	// Both rejected requests must leave the originating privileged session and
	// directory role usable; otherwise the denial would still create a lockout.
	response, err = client.Get(testServer.URL + "/api/v1/session")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("administrator session was lost after self-management denial: %d %s", response.StatusCode, payload)
	}
	var survivingSession sessionResponse
	decodeJSON(t, response, &survivingSession)
	if survivingSession.User.ID != privilegedSession.User.ID || survivingSession.User.Role != "admin" {
		t.Fatalf("administrator session changed after denial: %#v", survivingSession.User)
	}

	for _, action := range []string{"ACCOUNT_STATUS_UPDATED", "USER_SESSIONS_REVOKED"} {
		response, err = client.Get(testServer.URL + "/api/v1/admin/audit?action=" + action + "&outcome=denied&limit=10")
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			payload, _ := io.ReadAll(response.Body)
			t.Fatalf("self-management audit query returned %d: %s", response.StatusCode, payload)
		}
		var deniedAudit audit.Page
		decodeJSON(t, response, &deniedAudit)
		if deniedAudit.Total != 1 || len(deniedAudit.Events) != 1 || deniedAudit.Events[0].ReasonCode != "self_management_prohibited" || !deniedAudit.Verification.Valid {
			t.Fatalf("self-management denial evidence was incomplete for %s: %#v", action, deniedAudit)
		}
	}

	quotaURL := testServer.URL + "/api/v1/admin/resources/owners/" + url.PathEscape(page.Users[0].ID) + "/quota"
	request, err = http.NewRequest(http.MethodPut, quotaURL, strings.NewReader(`{"quotaBytes":1048576}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	request.Header.Set("X-CSRF-Token", privilegedSession.CSRFToken)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusConflict {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("quota override accepted a privileged identity: %d %s", response.StatusCode, payload)
	}
}

func TestAuditorCanReadGovernanceButCannotUseAdministratorControls(t *testing.T) {
	testServer, mailer, repository := newTestServer(t, 1024)
	defer testServer.Close()
	client := clientWithCookies(t)
	registerAndLoginUser(t, client, testServer.URL, mailer)

	// Promote the disposable identity only inside this isolated API test. Role
	// changes revoke its standard session, so the next request must establish a
	// separate privileged session before governance endpoints are evaluated.
	if err := repository.UpdateUserRole("jane@example.edu", "auditor"); err != nil {
		t.Fatal(err)
	}
	loginBody := `{"email":"jane@example.edu","password":"Correct-Horse-9!"}`
	request, err := http.NewRequest(http.MethodPost, testServer.URL+"/api/v1/admin/auth/login", strings.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("auditor privileged login returned %d: %s", response.StatusCode, payload)
	}
	var auditorSession sessionResponse
	decodeJSON(t, response, &auditorSession)
	if auditorSession.User.Role != "auditor" {
		t.Fatalf("privileged session did not preserve auditor role: %#v", auditorSession.User)
	}

	// Auditors need authoritative evidence from these endpoints to perform
	// oversight, but they must not receive the administrator identity directory.
	for _, path := range []string{
		"/api/v1/admin/resources",
		"/api/v1/admin/security",
		"/api/v1/admin/monitoring",
		"/api/v1/admin/lifecycle",
		"/api/v1/admin/audit",
	} {
		response, err = client.Get(testServer.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			payload, _ := io.ReadAll(response.Body)
			t.Fatalf("auditor read %s returned %d: %s", path, response.StatusCode, payload)
		}
		_ = response.Body.Close()
	}

	response, err = client.Get(testServer.URL + "/api/v1/admin/users")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("auditor received administrator identity directory: %d %s", response.StatusCode, payload)
	}
	var directoryDenied errorResponse
	decodeJSON(t, response, &directoryDenied)
	if directoryDenied.Code != "ADMINISTRATOR_REQUIRED" {
		t.Fatalf("unexpected identity-directory denial: %#v", directoryDenied)
	}

	// A valid auditor session and CSRF token must still fail at the role gate.
	// This proves that hiding the UI control is defense in depth, not the primary
	// authorization mechanism.
	request, err = http.NewRequest(http.MethodPut, testServer.URL+"/api/v1/admin/resources/owners/usr_target/quota", strings.NewReader(`{"quotaBytes":1048576}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	request.Header.Set("X-CSRF-Token", auditorSession.CSRFToken)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("auditor quota mutation returned %d: %s", response.StatusCode, payload)
	}
	var mutationDenied errorResponse
	decodeJSON(t, response, &mutationDenied)
	if mutationDenied.Code != "ADMINISTRATOR_REQUIRED" {
		t.Fatalf("unexpected auditor mutation denial: %#v", mutationDenied)
	}
}

func TestAdministratorMutationRejectsMissingAndInvalidStepUpProof(t *testing.T) {
	testServer, mailer, repository := newTestServerConfiguredAuth(t, 1024, false, "", authn.Config{
		RequireAdminStepUp: true,
		StepUpTTL:          5 * time.Minute,
	})
	defer testServer.Close()
	client := clientWithCookies(t)
	registerAndLoginUser(t, client, testServer.URL, mailer)

	if err := repository.UpdateUserRole("jane@example.edu", "admin"); err != nil {
		t.Fatal(err)
	}
	loginBody := `{"email":"jane@example.edu","password":"Correct-Horse-9!"}`
	request, err := http.NewRequest(http.MethodPost, testServer.URL+"/api/v1/admin/auth/login", strings.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("administrator login returned %d: %s", response.StatusCode, payload)
	}
	var administratorSession sessionResponse
	decodeJSON(t, response, &administratorSession)

	// Use self-suspension as a fail-safe target: even if the role boundary were
	// accidentally bypassed, the identity layer would reject the state change.
	// The assertions below must stop earlier at the step-up gate.
	statusURL := testServer.URL + "/api/v1/admin/users/" + url.PathEscape(administratorSession.User.ID) + "/status"
	for _, proofToken := range []string{"", "invalid-opaque-step-up-proof"} {
		request, err = http.NewRequest(http.MethodPatch, statusURL, strings.NewReader(`{"status":"suspended"}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://test")
		request.Header.Set("X-CSRF-Token", administratorSession.CSRFToken)
		if proofToken != "" {
			request.Header.Set("X-Step-Up-Token", proofToken)
		}
		response, err = client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusPreconditionRequired {
			payload, _ := io.ReadAll(response.Body)
			t.Fatalf("mutation with proof %q returned %d: %s", proofToken, response.StatusCode, payload)
		}
		var denied errorResponse
		decodeJSON(t, response, &denied)
		if denied.Code != "STEP_UP_REQUIRED" {
			t.Fatalf("unexpected step-up denial for proof %q: %#v", proofToken, denied)
		}
	}
}

func TestRetentionAndLegalHoldBlockOwnerTrashAndCreateDeniedAuditEvidence(t *testing.T) {
	testServer, mailer, repository := newTestServerMode(t, 4096, true)
	defer testServer.Close()

	ownerClient := clientWithCookies(t)
	owner := registerAndLoginNamedUser(t, ownerClient, testServer.URL, mailer, "Lifecycle Owner", "lifecycle-owner@example.edu", "Owner-Pass-9!")

	// Every file is generated inside the isolated test server. No fixture from a
	// developer or user workspace enters the lifecycle test.
	uploadFile := func(name, idempotencyKey, body string) string {
		t.Helper()
		request := uploadRequest(t, testServer.URL, name, []byte(body), idempotencyKey, owner.CSRFToken)
		response, err := ownerClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusAccepted {
			payload, _ := io.ReadAll(response.Body)
			t.Fatalf("upload %s returned %d: %s", name, response.StatusCode, payload)
		}
		var upload ingest.Upload
		decodeJSON(t, response, &upload)
		if terminal := pollUpload(t, ownerClient, testServer.URL, upload.ID); terminal.Status != ingest.StatusStored {
			t.Fatalf("upload %s did not reach protected storage: %#v", name, terminal)
		}
		response, err = ownerClient.Get(testServer.URL + "/api/v1/files")
		if err != nil {
			t.Fatal(err)
		}
		var files userFilePage
		decodeJSON(t, response, &files)
		for _, file := range files.Files {
			if file.Name == name {
				return file.FileID
			}
		}
		t.Fatalf("protected file %s was absent from the owner catalog", name)
		return ""
	}

	retainedFileID := uploadFile("retention-block.txt", "lifecycle-retention-1", "disposable retention fixture")
	heldFileID := uploadFile("hold-block.txt", "lifecycle-hold-1", "disposable legal-hold fixture")

	adminClient := clientWithCookies(t)
	registerAndLoginNamedUser(t, adminClient, testServer.URL, mailer, "Lifecycle Admin", "lifecycle-admin@example.edu", "Admin-Pass-9!")
	if err := repository.UpdateUserRole("lifecycle-admin@example.edu", "admin"); err != nil {
		t.Fatal(err)
	}
	loginBody := `{"email":"lifecycle-admin@example.edu","password":"Admin-Pass-9!"}`
	request, err := http.NewRequest(http.MethodPost, testServer.URL+"/api/v1/admin/auth/login", strings.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	response, err := adminClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("administrator login returned %d: %s", response.StatusCode, payload)
	}
	var administrator sessionResponse
	decodeJSON(t, response, &administrator)

	retentionUntil := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	request, err = http.NewRequest(http.MethodPut, testServer.URL+"/api/v1/admin/lifecycle/files/"+url.PathEscape(retainedFileID)+"/retention", strings.NewReader(`{"retentionUntil":"`+retentionUntil+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	request.Header.Set("X-CSRF-Token", administrator.CSRFToken)
	response, err = adminClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("retention policy returned %d: %s", response.StatusCode, payload)
	}
	_ = response.Body.Close()

	request, err = http.NewRequest(http.MethodPut, testServer.URL+"/api/v1/admin/lifecycle/files/"+url.PathEscape(heldFileID)+"/legal-hold", strings.NewReader(`{"enabled":true,"reason":"Disposable lifecycle boundary test"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	request.Header.Set("X-CSRF-Token", administrator.CSRFToken)
	response, err = adminClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("legal hold returned %d: %s", response.StatusCode, payload)
	}
	_ = response.Body.Close()

	assertTrashDenied := func(fileID, expectedCode string) {
		t.Helper()
		request, err := http.NewRequest(http.MethodPost, testServer.URL+"/api/v1/files/"+url.PathEscape(fileID)+"/trash", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", "http://test")
		request.Header.Set("X-CSRF-Token", owner.CSRFToken)
		response, err := ownerClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusConflict {
			payload, _ := io.ReadAll(response.Body)
			t.Fatalf("trash for %s returned %d: %s", fileID, response.StatusCode, payload)
		}
		var denied errorResponse
		decodeJSON(t, response, &denied)
		if denied.Code != expectedCode {
			t.Fatalf("unexpected lifecycle denial for %s: %#v", fileID, denied)
		}
	}
	assertTrashDenied(retainedFileID, "RETENTION_ACTIVE")
	assertTrashDenied(heldFileID, "LEGAL_HOLD_ACTIVE")

	// A blocked trash transition must preserve both catalog state and owner
	// plaintext authorization; only a successful trash transition removes access.
	response, err = ownerClient.Get(testServer.URL + "/api/v1/files")
	if err != nil {
		t.Fatal(err)
	}
	var activeFiles userFilePage
	decodeJSON(t, response, &activeFiles)
	if activeFiles.Total != 2 {
		t.Fatalf("policy-blocked files left the active catalog: %#v", activeFiles)
	}
	for _, fileID := range []string{retainedFileID, heldFileID} {
		response, err = ownerClient.Get(testServer.URL + "/api/v1/files/" + url.PathEscape(fileID) + "/content")
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			payload, _ := io.ReadAll(response.Body)
			t.Fatalf("policy-blocked file %s became unreadable: %d %s", fileID, response.StatusCode, payload)
		}
		_ = response.Body.Close()
	}

	response, err = adminClient.Get(testServer.URL + "/api/v1/admin/audit?action=FILE_MOVED_TO_TRASH&outcome=denied&limit=10")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("denied lifecycle audit query returned %d: %s", response.StatusCode, payload)
	}
	var deniedEvents audit.Page
	decodeJSON(t, response, &deniedEvents)
	if deniedEvents.Total != 2 || !deniedEvents.Verification.Valid {
		t.Fatalf("denied lifecycle evidence was incomplete: %#v", deniedEvents)
	}
	reasons := map[string]bool{}
	for _, event := range deniedEvents.Events {
		reasons[event.ReasonCode] = true
	}
	if !reasons["retention_active"] || !reasons["legal_hold_active"] {
		t.Fatalf("denied lifecycle reasons were not preserved: %#v", deniedEvents.Events)
	}
}

func TestApprovedCryptographicDeletionIsIdempotentAndAuditedOnce(t *testing.T) {
	lifecycleNow := time.Date(2026, time.August, 15, 18, 0, 0, 0, time.UTC)
	testServer, mailer, repository := newTestServerConfiguredClock(t, 4096, true, "", authn.Config{}, func() time.Time { return lifecycleNow })
	defer testServer.Close()

	ownerClient := clientWithCookies(t)
	owner := registerAndLoginNamedUser(t, ownerClient, testServer.URL, mailer, "Deletion Owner", "deletion-owner@example.edu", "Owner-Pass-9!")
	request := uploadRequest(t, testServer.URL, "approved-deletion.txt", []byte("disposable approved deletion fixture"), "approved-deletion-upload-1", owner.CSRFToken)
	response, err := ownerClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusAccepted {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("upload returned %d: %s", response.StatusCode, payload)
	}
	var upload ingest.Upload
	decodeJSON(t, response, &upload)
	if terminal := pollUpload(t, ownerClient, testServer.URL, upload.ID); terminal.Status != ingest.StatusStored {
		t.Fatalf("fixture did not reach protected storage: %#v", terminal)
	}

	response, err = ownerClient.Get(testServer.URL + "/api/v1/files")
	if err != nil {
		t.Fatal(err)
	}
	var files userFilePage
	decodeJSON(t, response, &files)
	if files.Total != 1 || len(files.Files) != 1 {
		t.Fatalf("fixture was absent from the owner catalog: %#v", files)
	}
	fileID := files.Files[0].FileID

	request, err = http.NewRequest(http.MethodPost, testServer.URL+"/api/v1/files/"+url.PathEscape(fileID)+"/trash", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", "http://test")
	request.Header.Set("X-CSRF-Token", owner.CSRFToken)
	response, err = ownerClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("move to Trash returned %d: %s", response.StatusCode, payload)
	}
	var trashed protectedstore.LifecycleFile
	decodeJSON(t, response, &trashed)
	if trashed.PurgeAfter == nil {
		t.Fatal("Trash transition did not establish a deletion grace deadline")
	}

	// Advance only the protected-storage lifecycle clock. Authentication and
	// audit clocks remain real, while the disposable file becomes eligible.
	lifecycleNow = trashed.PurgeAfter.Add(time.Second)
	purge := func() protectedstore.PurgeResult {
		t.Helper()
		request, err := http.NewRequest(http.MethodDelete, testServer.URL+"/api/v1/files/"+url.PathEscape(fileID), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", "http://test")
		request.Header.Set("X-CSRF-Token", owner.CSRFToken)
		request.Header.Set("Idempotency-Key", "approved-deletion-operation-1")
		response, err := ownerClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			payload, _ := io.ReadAll(response.Body)
			t.Fatalf("approved purge returned %d: %s", response.StatusCode, payload)
		}
		var result protectedstore.PurgeResult
		decodeJSON(t, response, &result)
		return result
	}
	first, retry := purge(), purge()
	if first.OperationID == "" || retry.OperationID != first.OperationID || retry.FileID != first.FileID {
		t.Fatalf("purge retry changed operation identity: first=%#v retry=%#v", first, retry)
	}
	if first.DestroyedKeys != 1 || retry.DestroyedKeys != 1 {
		t.Fatalf("purge did not report stable key destruction: first=%#v retry=%#v", first, retry)
	}

	response, err = ownerClient.Get(testServer.URL + "/api/v1/files")
	if err != nil {
		t.Fatal(err)
	}
	files.Files, files.Total = nil, 0
	decodeJSON(t, response, &files)
	if files.Total != 0 {
		t.Fatalf("purged file remained active: %#v", files)
	}
	response, err = ownerClient.Get(testServer.URL + "/api/v1/files/trash")
	if err != nil {
		t.Fatal(err)
	}
	var trash struct {
		Files []protectedstore.LifecycleFile `json:"files"`
		Total int                            `json:"total"`
	}
	decodeJSON(t, response, &trash)
	if trash.Total != 0 {
		t.Fatalf("purged file remained recoverable in Trash: %#v", trash)
	}
	response, err = ownerClient.Get(testServer.URL + "/api/v1/files/" + url.PathEscape(fileID) + "/content")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusNotFound {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("purged plaintext remained accessible: %d %s", response.StatusCode, payload)
	}
	_ = response.Body.Close()

	adminClient := clientWithCookies(t)
	registerAndLoginNamedUser(t, adminClient, testServer.URL, mailer, "Deletion Admin", "deletion-admin@example.edu", "Admin-Pass-9!")
	if err := repository.UpdateUserRole("deletion-admin@example.edu", "admin"); err != nil {
		t.Fatal(err)
	}
	loginBody := `{"email":"deletion-admin@example.edu","password":"Admin-Pass-9!"}`
	request, err = http.NewRequest(http.MethodPost, testServer.URL+"/api/v1/admin/auth/login", strings.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://test")
	response, err = adminClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("administrator login returned %d: %s", response.StatusCode, payload)
	}
	_ = response.Body.Close()

	response, err = adminClient.Get(testServer.URL + "/api/v1/admin/lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("lifecycle evidence returned %d: %s", response.StatusCode, payload)
	}
	var lifecycle adminLifecycleSummary
	decodeJSON(t, response, &lifecycle)
	if lifecycle.Protected.Purged != 1 || len(lifecycle.Protected.DeletionOperations) != 1 {
		t.Fatalf("durable deletion evidence was incomplete: %#v", lifecycle.Protected)
	}
	operation := lifecycle.Protected.DeletionOperations[0]
	if operation.OperationID != first.OperationID || operation.Status != "completed" || operation.DestroyedKeys != 1 || operation.Attempts != 1 || operation.CompletedAt == nil {
		t.Fatalf("unexpected deletion tombstone: %#v", operation)
	}

	response, err = adminClient.Get(testServer.URL + "/api/v1/admin/audit?action=FILE_CRYPTOGRAPHICALLY_DELETED&outcome=success&limit=10")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("deletion audit query returned %d: %s", response.StatusCode, payload)
	}
	var deletionAudit audit.Page
	decodeJSON(t, response, &deletionAudit)
	if deletionAudit.Total != 1 || len(deletionAudit.Events) != 1 || !deletionAudit.Verification.Valid {
		t.Fatalf("purge retry duplicated or corrupted audit evidence: %#v", deletionAudit)
	}
	event := deletionAudit.Events[0]
	if event.ResourceID != fileID || event.ReasonCode != "wrapped_keys_destroyed" || event.ToState != "purged" {
		t.Fatalf("deletion audit event was incomplete: %#v", event)
	}
}

func uploadRequest(t *testing.T, baseURL, name string, content []byte, idempotencyKey, csrfToken string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/uploads", &body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("Origin", "http://test")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	request.Header.Set("X-File-Size", strconv.Itoa(len(content)))
	request.Header.Set("X-CSRF-Token", csrfToken)
	return request
}

func pollUpload(t *testing.T, client *http.Client, baseURL, uploadID string) ingest.Upload {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(baseURL + "/api/v1/uploads/" + uploadID)
		if err != nil {
			t.Fatal(err)
		}
		var upload ingest.Upload
		decodeJSON(t, response, &upload)
		if upload.Status == ingest.StatusAccepted || upload.Status == ingest.StatusStored || upload.Status == ingest.StatusRejected || upload.Status == ingest.StatusFailed {
			return upload
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("upload did not reach terminal status")
	return ingest.Upload{}
}

func decodeJSON(t *testing.T, response *http.Response, destination any) {
	t.Helper()
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		t.Fatal(err)
	}
}
