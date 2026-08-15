package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const remoteAnchorMaxResponseBytes = 64 * 1024

type RemoteAnchorConfig struct {
	Endpoint, CAFile, ClientCertificateFile, ClientKeyFile string
	ReceiptPublicKeyFile                                   string
	Timeout                                                time.Duration
}

// RemoteCheckpointAnchor sends checkpoint digests to an independently
// administered append-only ledger over mutual TLS. The ledger returns an
// Ed25519-signed receipt; SecureStore holds only the pinned public key.
type RemoteCheckpointAnchor struct {
	endpoint string
	client   *http.Client
	public   ed25519.PublicKey
}

func NewRemoteCheckpointAnchor(config RemoteAnchorConfig) (*RemoteCheckpointAnchor, error) {
	if config.CAFile == "" || config.ClientCertificateFile == "" || config.ClientKeyFile == "" || config.ReceiptPublicKeyFile == "" {
		return nil, errors.New("remote audit anchor requires CA, client identity, and receipt public-key files")
	}
	caPEM, err := os.ReadFile(config.CAFile)
	if err != nil {
		return nil, errors.New("remote audit anchor CA is unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("remote audit anchor CA is invalid")
	}
	certificate, err := tls.LoadX509KeyPair(config.ClientCertificateFile, config.ClientKeyFile)
	if err != nil {
		return nil, errors.New("remote audit anchor client identity is invalid")
	}
	publicPEM, err := os.ReadFile(config.ReceiptPublicKeyFile)
	if err != nil {
		return nil, errors.New("remote audit anchor receipt public key is unavailable")
	}
	publicKey, err := parseAnchorPublicKey(publicPEM)
	if err != nil {
		return nil, err
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
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrAnchorUnavailable },
	}
	return newRemoteCheckpointAnchor(config.Endpoint, config.Timeout, client, publicKey)
}

func newRemoteCheckpointAnchor(endpoint string, timeout time.Duration, client *http.Client, publicKey ed25519.PublicKey) (*RemoteCheckpointAnchor, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || timeout <= 0 || client == nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid remote audit anchor configuration")
	}
	return &RemoteCheckpointAnchor{endpoint: strings.TrimRight(endpoint, "/"), client: client, public: append(ed25519.PublicKey(nil), publicKey...)}, nil
}

type remoteAnchorStatus struct {
	Status                    string `json:"status"`
	Provider                  string `json:"provider"`
	Immutable                 bool   `json:"immutable"`
	IndependentlyAdministered bool   `json:"independentlyAdministered"`
	ServerAttested            bool   `json:"serverAttested"`
}

func (anchor *RemoteCheckpointAnchor) Append(record AnchorRecord) error {
	if !validUnsignedAnchorRecord(record) || record.Signature != "" {
		return ErrAnchorUnavailable
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return ErrAnchorUnavailable
	}
	defer clear(payload)
	request, err := http.NewRequest(http.MethodPost, anchor.endpoint+"/v1/checkpoints", bytes.NewReader(payload))
	if err != nil {
		return ErrAnchorUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	var receipt AnchorRecord
	if err := anchor.do(request, &receipt); err != nil || !sameAnchorRecord(record, receipt) || !anchor.VerifyReceipt(receipt) {
		return ErrAnchorUnavailable
	}
	return nil
}

func (anchor *RemoteCheckpointAnchor) Latest() (AnchorRecord, error) {
	request, err := http.NewRequest(http.MethodGet, anchor.endpoint+"/v1/checkpoints/latest?chainId="+url.QueryEscape(chainID), nil)
	if err != nil {
		return AnchorRecord{}, ErrAnchorUnavailable
	}
	request.Header.Set("Accept", "application/json")
	var receipt AnchorRecord
	if err := anchor.do(request, &receipt); err != nil || !validUnsignedAnchorRecord(receipt) || !anchor.VerifyReceipt(receipt) {
		return AnchorRecord{}, ErrAnchorUnavailable
	}
	return receipt, nil
}

func (anchor *RemoteCheckpointAnchor) Posture() AnchorPosture {
	result := AnchorPosture{Adapter: "remote-immutable-ledger-mtls", Detail: "Independent audit checkpoint ledger is unavailable; remote anchoring requires attention."}
	request, err := http.NewRequest(http.MethodGet, anchor.endpoint+"/v1/status", nil)
	if err != nil {
		return result
	}
	request.Header.Set("Accept", "application/json")
	var status remoteAnchorStatus
	if err := anchor.do(request, &status); err != nil || !safeAnchorToken(status.Provider) {
		return result
	}
	result.Connected = true
	result.ProductionReady = status.Status == "enabled" && status.Immutable && status.IndependentlyAdministered && status.ServerAttested
	if result.ProductionReady {
		result.Detail = "Mutually authenticated independent immutable checkpoint anchoring is enabled with server-attested receipts."
	} else {
		result.Detail = "The audit anchor is reachable, but immutability, independent administration, or server attestation is not confirmed."
	}
	return result
}

func (anchor *RemoteCheckpointAnchor) VerifyReceipt(record AnchorRecord) bool {
	provided, err := base64.RawURLEncoding.DecodeString(record.Signature)
	if err != nil || len(provided) != ed25519.SignatureSize || !validUnsignedAnchorRecord(record) {
		return false
	}
	return ed25519.Verify(anchor.public, canonicalAnchorReceipt(record), provided)
}

func (anchor *RemoteCheckpointAnchor) do(request *http.Request, output any) error {
	response, err := anchor.client.Do(request)
	if err != nil {
		return ErrAnchorUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 || !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/json") {
		return ErrAnchorUnavailable
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, remoteAnchorMaxResponseBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return ErrAnchorUnavailable
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrAnchorUnavailable
	}
	return nil
}

func parseAnchorPublicKey(value []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(value)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "PUBLIC KEY" {
		return nil, errors.New("remote audit anchor receipt public key is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("remote audit anchor receipt public key is invalid")
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("remote audit anchor receipt public key must be Ed25519")
	}
	return publicKey, nil
}

func canonicalAnchorReceipt(record AnchorRecord) []byte {
	var buffer bytes.Buffer
	for _, value := range []string{"securestore.audit.external-anchor.v1", record.ChainID} {
		writeField(&buffer, []byte(value))
	}
	_ = binary.Write(&buffer, binary.BigEndian, record.Sequence)
	for _, value := range []string{record.Checkpoint, record.PreviousCheckpoint, record.KeyVersion, record.AnchoredAt.UTC().Format(time.RFC3339Nano)} {
		writeField(&buffer, []byte(value))
	}
	return buffer.Bytes()
}

func validUnsignedAnchorRecord(record AnchorRecord) bool {
	if record.ChainID != chainID || record.Sequence < 1 || record.Sequence > 1<<62 || record.AnchoredAt.IsZero() || !safeAnchorToken(record.KeyVersion) || len(record.Checkpoint) < 32 || len(record.Checkpoint) > 128 {
		return false
	}
	checkpoint, err := base64.RawURLEncoding.DecodeString(record.Checkpoint)
	if err != nil || len(checkpoint) != sha256.Size {
		return false
	}
	previous, err := base64.RawURLEncoding.DecodeString(record.PreviousCheckpoint)
	return err == nil && len(previous) == sha256.Size
}

func sameAnchorRecord(expected, actual AnchorRecord) bool {
	return expected.ChainID == actual.ChainID && expected.Sequence == actual.Sequence && expected.Checkpoint == actual.Checkpoint && expected.PreviousCheckpoint == actual.PreviousCheckpoint && expected.KeyVersion == actual.KeyVersion && expected.AnchoredAt.Equal(actual.AnchoredAt)
}

func safeAnchorToken(value string) bool {
	if value == "" || len(value) > 64 {
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

var _ CheckpointAnchor = (*RemoteCheckpointAnchor)(nil)
var _ anchorReceiptVerifier = (*RemoteCheckpointAnchor)(nil)
