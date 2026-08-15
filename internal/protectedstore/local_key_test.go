package protectedstore

import (
	"bytes"
	"testing"
)

func TestLocalKeyringWrapsCurrentAndUnwrapsHistoricalVersions(t *testing.T) {
	keys := map[string][]byte{"v1": bytes.Repeat([]byte{0x41}, 32), "v2": bytes.Repeat([]byte{0x42}, 32)}
	v1, err := NewLocalKeyringProvider(keys, "test-kek", "v1")
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{0x51}, 32)
	wrappedV1, err := v1.Wrap(dek)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := NewLocalKeyringProvider(keys, "test-kek", "v2")
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := v2.Unwrap(wrappedV1, "test-kek", "v1"); err != nil || !bytes.Equal(opened, dek) {
		t.Fatalf("historical DEK did not unwrap after rotation: %x err=%v", opened, err)
	}
	wrappedV2, err := v2.Wrap(dek)
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := v2.Unwrap(wrappedV2, "test-kek", "v2"); err != nil || !bytes.Equal(opened, dek) {
		t.Fatalf("current DEK did not unwrap: %x err=%v", opened, err)
	}
	withoutV1, err := NewLocalKeyringProvider(map[string][]byte{"v2": keys["v2"]}, "test-kek", "v2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutV1.Unwrap(wrappedV1, "test-kek", "v1"); err == nil {
		t.Fatal("missing historical KEK unexpectedly decrypted an old DEK")
	}
}
