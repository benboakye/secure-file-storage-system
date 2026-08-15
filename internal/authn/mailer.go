package authn

import (
	"fmt"
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

var _ VerificationMailer = DiscardMailer{}
var _ VerificationMailer = FileMailer{}
