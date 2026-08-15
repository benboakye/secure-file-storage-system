package protectedstore

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	remoteKeyPurpose          = "securestore-envelope-dek-v1"
	remoteKeyMaxWrappedBytes  = 16 * 1024
	remoteKeyMaxResponseBytes = 64 * 1024
)

var ErrKeyServiceUnavailable = errors.New("managed key service unavailable")

type RemoteKeyConfig struct {
	Endpoint, KeyID, KeyVersion                  string
	CAFile, ClientCertificateFile, ClientKeyFile string
	Timeout                                      time.Duration
}

// RemoteKeyProvider delegates DEK wrapping to a private key broker backed by a
// managed KMS or HSM. Mutual TLS authenticates both workloads; no static API
// secret or KEK material is loaded into the SecureStore process.
type RemoteKeyProvider struct {
	endpoint       string
	keyID, version string
	client         *http.Client
	now            func() time.Time
}

func NewRemoteKeyProvider(config RemoteKeyConfig) (*RemoteKeyProvider, error) {
	if config.CAFile == "" || config.ClientCertificateFile == "" || config.ClientKeyFile == "" {
		return nil, errors.New("managed key service requires CA and client certificate files")
	}
	caPEM, err := os.ReadFile(config.CAFile)
	if err != nil {
		return nil, errors.New("managed key service CA is unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("managed key service CA is invalid")
	}
	certificate, err := tls.LoadX509KeyPair(config.ClientCertificateFile, config.ClientKeyFile)
	if err != nil {
		return nil, errors.New("managed key service client identity is invalid")
	}
	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{certificate},
		},
		DisableCompression: true,
	}
	client := &http.Client{
		Transport: transport, Timeout: config.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrKeyServiceUnavailable },
	}
	return newRemoteKeyProvider(config, client)
}

func newRemoteKeyProvider(config RemoteKeyConfig, client *http.Client) (*RemoteKeyProvider, error) {
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !safeKeyToken(config.KeyID) || !safeKeyToken(config.KeyVersion) || config.Timeout <= 0 || client == nil {
		return nil, errors.New("invalid managed key service configuration")
	}
	return &RemoteKeyProvider{
		endpoint: strings.TrimRight(config.Endpoint, "/"), keyID: config.KeyID,
		version: config.KeyVersion, client: client, now: time.Now,
	}, nil
}

func (provider *RemoteKeyProvider) ID() string      { return provider.keyID }
func (provider *RemoteKeyProvider) Version() string { return provider.version }

type remoteKeyRequest struct {
	KeyID        string `json:"keyId"`
	KeyVersion   string `json:"keyVersion"`
	Purpose      string `json:"purpose"`
	PlaintextDEK []byte `json:"plaintextDek,omitempty"`
	WrappedDEK   []byte `json:"wrappedDek,omitempty"`
}

type remoteKeyResponse struct {
	KeyID          string `json:"keyId"`
	KeyVersion     string `json:"keyVersion"`
	Status         string `json:"status,omitempty"`
	Provider       string `json:"provider,omitempty"`
	HardwareBacked bool   `json:"hardwareBacked,omitempty"`
	PlaintextDEK   []byte `json:"plaintextDek,omitempty"`
	WrappedDEK     []byte `json:"wrappedDek,omitempty"`
}

func (provider *RemoteKeyProvider) Wrap(dek []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, ErrIntegrity
	}
	var response remoteKeyResponse
	request := remoteKeyRequest{KeyID: provider.keyID, KeyVersion: provider.version, Purpose: remoteKeyPurpose, PlaintextDEK: dek}
	if err := provider.post("/v1/wrap", request, &response); err != nil || response.KeyID != provider.keyID || response.KeyVersion != provider.version || len(response.WrappedDEK) == 0 || len(response.WrappedDEK) > remoteKeyMaxWrappedBytes || len(response.PlaintextDEK) != 0 {
		clear(response.PlaintextDEK)
		clear(response.WrappedDEK)
		return nil, ErrKeyServiceUnavailable
	}
	return response.WrappedDEK, nil
}

func (provider *RemoteKeyProvider) Unwrap(wrapped []byte, id, version string) ([]byte, error) {
	if len(wrapped) == 0 || len(wrapped) > remoteKeyMaxWrappedBytes || !safeKeyToken(id) || !safeKeyToken(version) {
		return nil, ErrIntegrity
	}
	var response remoteKeyResponse
	request := remoteKeyRequest{KeyID: id, KeyVersion: version, Purpose: remoteKeyPurpose, WrappedDEK: wrapped}
	if err := provider.post("/v1/unwrap", request, &response); err != nil || response.KeyID != id || response.KeyVersion != version || len(response.PlaintextDEK) != 32 || len(response.WrappedDEK) != 0 {
		clear(response.PlaintextDEK)
		clear(response.WrappedDEK)
		return nil, ErrIntegrity
	}
	return response.PlaintextDEK, nil
}

func (provider *RemoteKeyProvider) Posture() KeyProviderPosture {
	checkedAt := provider.now().UTC()
	result := KeyProviderPosture{
		Adapter: "remote-kms-mtls", KeyID: provider.keyID, KeyVersion: provider.version,
		CheckedAt: &checkedAt, Detail: "Managed key service is unavailable; wrap and unwrap operations fail closed.",
	}
	request, err := http.NewRequest(http.MethodGet, provider.endpoint+"/v1/status?keyId="+url.QueryEscape(provider.keyID)+"&keyVersion="+url.QueryEscape(provider.version), nil)
	if err != nil {
		return result
	}
	request.Header.Set("Accept", "application/json")
	var response remoteKeyResponse
	if err := provider.do(request, &response); err != nil || response.KeyID != provider.keyID || response.KeyVersion != provider.version || !safeProviderToken(response.Provider) || len(response.PlaintextDEK) != 0 || len(response.WrappedDEK) != 0 {
		clear(response.PlaintextDEK)
		clear(response.WrappedDEK)
		return result
	}
	result.Connected = true
	result.Provider = response.Provider
	result.HardwareBacked = response.HardwareBacked
	result.ProductionReady = response.Status == "enabled" && response.HardwareBacked
	if result.ProductionReady {
		result.Detail = "Mutually authenticated hardware-backed key custody is enabled for the current wrapping-key version."
	} else {
		result.Detail = "Managed key service is reachable, but the current key is not enabled with hardware-backed custody."
	}
	return result
}

func (provider *RemoteKeyProvider) post(path string, input remoteKeyRequest, output *remoteKeyResponse) error {
	payload, err := json.Marshal(input)
	if err != nil {
		return ErrKeyServiceUnavailable
	}
	defer clear(payload)
	request, err := http.NewRequest(http.MethodPost, provider.endpoint+path, bytes.NewReader(payload))
	if err != nil {
		return ErrKeyServiceUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	return provider.do(request, output)
}

func (provider *RemoteKeyProvider) do(request *http.Request, output *remoteKeyResponse) error {
	response, err := provider.client.Do(request)
	if err != nil {
		return ErrKeyServiceUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 || !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/json") {
		return ErrKeyServiceUnavailable
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, remoteKeyMaxResponseBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return ErrKeyServiceUnavailable
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrKeyServiceUnavailable
	}
	return nil
}

func safeKeyToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func safeProviderToken(value string) bool {
	return safeKeyToken(value) && len(value) <= 64
}

var _ KeyProvider = (*RemoteKeyProvider)(nil)
var _ keyPostureReporter = (*RemoteKeyProvider)(nil)
