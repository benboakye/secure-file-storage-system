package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestRemoteCheckpointAnchorRoundTripAndProductionPosture(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mutex sync.Mutex
	var latest AnchorRecord
	expectedPrevious := base64.RawURLEncoding.EncodeToString(genesisMAC[:])
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v1/status":
			_ = json.NewEncoder(response).Encode(remoteAnchorStatus{Status: "enabled", Provider: "test-ledger", Immutable: true, IndependentlyAdministered: true, ServerAttested: true})
		case request.Method == http.MethodPost && request.URL.Path == "/v1/checkpoints":
			var record AnchorRecord
			if err := json.NewDecoder(request.Body).Decode(&record); err != nil {
				http.Error(response, "invalid", http.StatusBadRequest)
				return
			}
			mutex.Lock()
			if record.PreviousCheckpoint != expectedPrevious {
				mutex.Unlock()
				http.Error(response, "checkpoint fork", http.StatusConflict)
				return
			}
			record.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, canonicalAnchorReceipt(record)))
			latest = record
			expectedPrevious = record.Checkpoint
			mutex.Unlock()
			_ = json.NewEncoder(response).Encode(record)
		case request.Method == http.MethodGet && request.URL.Path == "/v1/checkpoints/latest":
			mutex.Lock()
			record := latest
			mutex.Unlock()
			_ = json.NewEncoder(response).Encode(record)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	anchor, err := newRemoteCheckpointAnchor(server.URL, 2*time.Second, server.Client(), publicKey)
	if err != nil {
		t.Fatal(err)
	}
	posture := anchor.Posture()
	if !posture.Connected || !posture.ProductionReady || posture.Adapter != "remote-immutable-ledger-mtls" {
		t.Fatalf("unexpected remote posture: %#v", posture)
	}
	if _, ok := any(anchor).(anchorReceiptVerifier); !ok {
		t.Fatal("remote anchor does not advertise external receipt verification")
	}
	service, err := NewService(NewMemoryRepository(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureCheckpointAnchor(anchor, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Append(Input{ActorType: "system", Action: "REMOTE_ANCHOR_TEST", ResourceType: "audit_chain", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	mutex.Lock()
	stored := latest
	mutex.Unlock()
	if stored.Sequence != 1 || !anchor.VerifyReceipt(stored) {
		t.Fatalf("remote append did not retain a trusted receipt: %#v", stored)
	}
	if _, err := anchor.Latest(); err != nil {
		t.Fatalf("remote latest receipt failed: %v", err)
	}
	verification, err := service.Verify()
	if err != nil || !verification.Valid || !verification.Anchor.Valid || !verification.Anchor.ProductionReady || verification.Anchor.AnchoredThrough != 1 {
		t.Fatalf("remote anchor was not verified: %#v err=%v", verification, err)
	}
}

func TestRemoteCheckpointAnchorRejectsUntrustedReceiptAndUnknownFields(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/v1/status" {
			_, _ = response.Write([]byte(`{"status":"enabled","provider":"test-ledger","immutable":true,"independentlyAdministered":true,"serverAttested":true,"unexpected":true}`))
			return
		}
		var record AnchorRecord
		_ = json.NewDecoder(request.Body).Decode(&record)
		record.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		_ = json.NewEncoder(response).Encode(record)
	}))
	defer server.Close()
	anchor, err := newRemoteCheckpointAnchor(server.URL, time.Second, server.Client(), publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if posture := anchor.Posture(); posture.Connected || posture.ProductionReady {
		t.Fatalf("unknown status evidence must fail closed: %#v", posture)
	}
	record := AnchorRecord{ChainID: chainID, Sequence: 1, Checkpoint: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), PreviousCheckpoint: base64.RawURLEncoding.EncodeToString(genesisMAC[:]), KeyVersion: "v1", AnchoredAt: time.Now().UTC()}
	if err := anchor.Append(record); err == nil {
		t.Fatal("untrusted receipt was accepted")
	}
}

func TestRemoteCheckpointAnchorRequiresHTTPSAndEd25519(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newRemoteCheckpointAnchor("http://anchor.example", time.Second, http.DefaultClient, publicKey); err == nil {
		t.Fatal("plaintext remote anchor endpoint was accepted")
	}
	if _, err := newRemoteCheckpointAnchor("https://anchor.example", time.Second, http.DefaultClient, make([]byte, 31)); err == nil {
		t.Fatal("invalid receipt key was accepted")
	}
}
