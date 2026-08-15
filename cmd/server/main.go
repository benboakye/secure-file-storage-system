package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"securestore/internal/api"
	"securestore/internal/audit"
	"securestore/internal/auditoutbox"
	"securestore/internal/authn"
	"securestore/internal/ingest"
	"securestore/internal/orphan"
	"securestore/internal/protectedstore"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	deploymentMode := strings.ToLower(envString("SECURESTORE_DEPLOYMENT_MODE", "development"))
	listenAddress := envString("SECURESTORE_LISTEN_ADDR", "127.0.0.1:8080")
	tlsCertificateFile := envString("SECURESTORE_TLS_CERT_FILE", "")
	tlsKeyFile := envString("SECURESTORE_TLS_KEY_FILE", "")
	quarantineDir := envString("SECURESTORE_QUARANTINE_DIR", ".data/quarantine")
	maxUploadBytes := envInt64("SECURESTORE_MAX_UPLOAD_BYTES", 25*1024*1024)
	defaultOwnerQuotaBytes := envInt64("SECURESTORE_DEFAULT_USER_QUOTA_BYTES", 1024*1024*1024)
	storageCapacityBytes := envInt64("SECURESTORE_STORAGE_CAPACITY_BYTES", 50*1024*1024*1024)
	storageReserveBytes := envInt64("SECURESTORE_STORAGE_RESERVE_BYTES", 5*1024*1024*1024)
	reservationTTL := time.Duration(envInt64("SECURESTORE_CAPACITY_RESERVATION_TTL_SECONDS", 3600)) * time.Second
	secureCookies := envBool("SECURESTORE_SECURE_COOKIES", false)
	allowedOrigins := configuredOrigins(envString("SECURESTORE_ALLOWED_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173"))
	databaseURL := envString("SECURESTORE_DATABASE_URL", "")
	mailboxDir := envString("SECURESTORE_MAILBOX_DIR", ".data/mailbox")
	publicAppURL := envString("SECURESTORE_PUBLIC_APP_URL", "http://127.0.0.1:5173")
	auditKeyFile := envString("SECURESTORE_AUDIT_HMAC_KEY_FILE", ".data/audit-hmac.key")
	auditKeyVersion := envString("SECURESTORE_AUDIT_KEY_VERSION", "v1")
	auditAnchorMode := strings.ToLower(envString("SECURESTORE_AUDIT_ANCHOR_PROVIDER", "local"))
	auditAnchorFile := envString("SECURESTORE_AUDIT_ANCHOR_FILE", ".data/audit-checkpoints.jsonl")
	auditAnchorKeyFile := envString("SECURESTORE_AUDIT_ANCHOR_KEY_FILE", ".data/audit-anchor.key")
	protectedDir := envString("SECURESTORE_PROTECTED_DIR", ".data/protected")
	keyProviderMode := strings.ToLower(envString("SECURESTORE_KEY_PROVIDER", "local"))
	protectedKeyFile := envString("SECURESTORE_LOCAL_KEK_FILE", ".data/local-kek.key")
	protectedKeyVersion := envString("SECURESTORE_LOCAL_KEK_VERSION", "v1")
	mfaKeyFile := envString("SECURESTORE_MFA_ENCRYPTION_KEY_FILE", ".data/mfa-encryption.key")
	metricsTokenFile := envString("SECURESTORE_METRICS_TOKEN_FILE", ".data/metrics-token.key")
	metricsStaleAfter := time.Duration(envInt64("SECURESTORE_METRICS_STALE_AFTER_SECONDS", 300)) * time.Second
	requirePrivilegedMFA := envBool("SECURESTORE_REQUIRE_PRIVILEGED_MFA", true)
	loginFailureThreshold := int(envInt64("SECURESTORE_LOGIN_FAILURE_THRESHOLD", 5))
	loginFailureWindow := time.Duration(envInt64("SECURESTORE_LOGIN_FAILURE_WINDOW_SECONDS", 900)) * time.Second
	accountLockDuration := time.Duration(envInt64("SECURESTORE_ACCOUNT_LOCK_SECONDS", 900)) * time.Second
	authRateLimit := int(envInt64("SECURESTORE_AUTH_RATE_LIMIT", 10))
	authRateWindow := time.Duration(envInt64("SECURESTORE_AUTH_RATE_WINDOW_SECONDS", 300)) * time.Second
	requireAdminStepUp := envBool("SECURESTORE_REQUIRE_ADMIN_STEP_UP", true)
	adminStepUpTTL := time.Duration(envInt64("SECURESTORE_ADMIN_STEP_UP_TTL_SECONDS", 300)) * time.Second
	inspectionTTL := time.Duration(envInt64("SECURESTORE_INSPECTION_TIMEOUT_SECONDS", 15)) * time.Second
	scannerMode := strings.ToLower(envString("SECURESTORE_SCANNER_MODE", "deterministic"))
	if err := validateDeployment(deploymentConfig{
		Mode: deploymentMode, PublicAppURL: publicAppURL, DatabaseURL: databaseURL,
		TLSCertificateFile: tlsCertificateFile, TLSKeyFile: tlsKeyFile,
		ScannerMode: scannerMode, KeyProviderMode: keyProviderMode, AuditAnchorMode: auditAnchorMode,
		AuditKeyFile: auditKeyFile, MFAKeyFile: mfaKeyFile, MetricsTokenFile: metricsTokenFile,
		AuditKeyInjected:     strings.TrimSpace(os.Getenv("SECURESTORE_AUDIT_HMAC_KEY")) != "",
		MFAKeyInjected:       strings.TrimSpace(os.Getenv("SECURESTORE_MFA_ENCRYPTION_KEY")) != "",
		MetricsTokenInjected: strings.TrimSpace(os.Getenv("SECURESTORE_METRICS_BEARER_TOKEN")) != "",
		AllowedOrigins:       allowedOrigins, SecureCookies: secureCookies,
		RequirePrivilegedMFA: requirePrivilegedMFA, RequireAdminStepUp: requireAdminStepUp,
	}); err != nil {
		return err
	}
	var scanner ingest.Scanner
	switch scannerMode {
	case "deterministic":
		scanner = ingest.DeterministicScanner{Delay: 700 * time.Millisecond}
		logger.Warn("development malware scanner configured; uploads are not production-scanned")
	case "clamd":
		clamdScanner, scannerErr := ingest.NewClamdScanner(
			envString("SECURESTORE_CLAMD_NETWORK", "tcp"),
			envString("SECURESTORE_CLAMD_ADDRESS", "127.0.0.1:3310"),
			maxUploadBytes,
			time.Duration(envInt64("SECURESTORE_CLAMD_DIAL_TIMEOUT_MS", 1000))*time.Millisecond,
			time.Duration(envInt64("SECURESTORE_CLAMD_IO_TIMEOUT_MS", 10000))*time.Millisecond,
			time.Duration(envInt64("SECURESTORE_CLAMD_MAX_SIGNATURE_AGE_HOURS", 24))*time.Hour,
		)
		if scannerErr != nil {
			return scannerErr
		}
		scanner = clamdScanner
	default:
		return errors.New("SECURESTORE_SCANNER_MODE must be deterministic or clamd")
	}

	var authRepository authn.Repository = authn.NewMemoryRepository()
	var closeAuthRepository func()
	if databaseURL != "" {
		postgresRepository, err := authn.NewPostgresRepository(context.Background(), databaseURL)
		if err != nil {
			return err
		}
		authRepository = postgresRepository
		closeAuthRepository = postgresRepository.Close
		logger.Info("authentication repository ready", "driver", "postgresql")
	} else {
		logger.Warn("authentication state is in memory; set SECURESTORE_DATABASE_URL for durable PostgreSQL storage")
	}
	if closeAuthRepository != nil {
		defer closeAuthRepository()
	}
	mfaKey, err := loadSecretKey(mfaKeyFile, "SECURESTORE_MFA_ENCRYPTION_KEY", "SECURESTORE_MFA_ENCRYPTION_KEY must be base64 for exactly 32 random bytes")
	if err != nil {
		return err
	}
	metricsTokenBytes, err := loadSecretKey(metricsTokenFile, "SECURESTORE_METRICS_BEARER_TOKEN", "SECURESTORE_METRICS_BEARER_TOKEN must be base64 for exactly 32 random bytes")
	if err != nil {
		return err
	}
	metricsToken := base64.StdEncoding.EncodeToString(metricsTokenBytes)
	authStore, err := authn.NewStoreWithConfig(authn.Config{
		Repository: authRepository, Mailer: authn.FileMailer{Directory: mailboxDir},
		SessionTTL: 8 * time.Hour, VerificationTTL: 30 * time.Minute,
		VerificationMinResend: time.Minute, PublicAppURL: publicAppURL,
		RequirePrivilegedMFA: requirePrivilegedMFA, MFAEncryptionKey: mfaKey, MFAIssuer: "SecureStore",
		LoginFailureThreshold: loginFailureThreshold, LoginFailureWindow: loginFailureWindow, AccountLockDuration: accountLockDuration,
		RequireAdminStepUp: requireAdminStepUp, StepUpTTL: adminStepUpTTL,
	})
	if err != nil {
		return err
	}
	var ingestRepository ingest.Repository = ingest.NewMemoryRepository()
	var closeIngestRepository func()
	if databaseURL != "" {
		postgresRepository, err := ingest.NewPostgresRepository(context.Background(), databaseURL)
		if err != nil {
			return err
		}
		ingestRepository = postgresRepository
		closeIngestRepository = postgresRepository.Close
		logger.Info("ingestion metadata repository ready", "driver", "postgresql")
	} else {
		logger.Warn("ingestion metadata is in memory; set SECURESTORE_DATABASE_URL for durable lifecycle records")
	}
	if closeIngestRepository != nil {
		defer closeIngestRepository()
	}
	var protectedRepository protectedstore.Repository = protectedstore.NewMemoryRepository()
	var closeProtectedRepository func()
	if databaseURL != "" {
		postgresRepository, err := protectedstore.NewPostgresRepository(context.Background(), databaseURL)
		if err != nil {
			return err
		}
		protectedRepository = postgresRepository
		closeProtectedRepository = postgresRepository.Close
		logger.Info("protected-file metadata repository ready", "driver", "postgresql")
	}
	if closeProtectedRepository != nil {
		defer closeProtectedRepository()
	}
	var keyProvider protectedstore.KeyProvider
	switch keyProviderMode {
	case "local":
		localKEK, err := loadSecretKey(protectedKeyFile, "SECURESTORE_LOCAL_KEK", "SECURESTORE_LOCAL_KEK must be base64 for exactly 32 random bytes")
		if err != nil {
			return err
		}
		protectedKeys, err := decodeHistoricalKeys("SECURESTORE_LOCAL_KEK_HISTORICAL_KEYS", protectedKeyVersion, localKEK)
		if err != nil {
			clear(localKEK)
			return err
		}
		localProvider, providerErr := protectedstore.NewLocalKeyringProvider(protectedKeys, "securestore-local-development-kek", protectedKeyVersion)
		for _, key := range protectedKeys {
			clear(key)
		}
		keyProvider, err = localProvider, providerErr
		if err != nil {
			return err
		}
		logger.Warn("development file-backed envelope key provider configured; managed custody is not connected")
	case "remote":
		keyProvider, err = protectedstore.NewRemoteKeyProvider(protectedstore.RemoteKeyConfig{
			Endpoint: envString("SECURESTORE_KMS_ENDPOINT", ""),
			KeyID:    envString("SECURESTORE_KMS_KEY_ID", ""), KeyVersion: envString("SECURESTORE_KMS_KEY_VERSION", ""),
			CAFile:                envString("SECURESTORE_KMS_CA_FILE", ""),
			ClientCertificateFile: envString("SECURESTORE_KMS_CLIENT_CERT_FILE", ""),
			ClientKeyFile:         envString("SECURESTORE_KMS_CLIENT_KEY_FILE", ""),
			Timeout:               time.Duration(envInt64("SECURESTORE_KMS_TIMEOUT_MS", 3000)) * time.Millisecond,
		})
		if err != nil {
			return err
		}
	default:
		return errors.New("SECURESTORE_KEY_PROVIDER must be local or remote")
	}
	protectedService, err := protectedstore.NewService(protectedstore.Config{RootDir: protectedDir, MaxPlaintextBytes: maxUploadBytes, Repository: protectedRepository, Keys: keyProvider})
	if err != nil {
		return err
	}
	var auditRepository audit.Repository = audit.NewMemoryRepository()
	var closeAuditRepository func()
	if databaseURL != "" {
		postgresRepository, err := audit.NewPostgresRepository(context.Background(), databaseURL)
		if err != nil {
			return err
		}
		auditRepository = postgresRepository
		closeAuditRepository = postgresRepository.Close
		logger.Info("audit repository ready", "driver", "postgresql")
	}
	if closeAuditRepository != nil {
		defer closeAuditRepository()
	}
	auditKeys, err := loadAuditKeyring(auditKeyFile, auditKeyVersion)
	if err != nil {
		return err
	}
	auditService, err := audit.NewServiceWithKeyring(auditRepository, auditKeyVersion, auditKeys)
	if err != nil {
		return err
	}
	var auditAnchor audit.CheckpointAnchor
	var auditAnchorKey []byte
	switch auditAnchorMode {
	case "local":
		auditAnchorKey, err = loadSecretKey(auditAnchorKeyFile, "SECURESTORE_AUDIT_ANCHOR_KEY", "SECURESTORE_AUDIT_ANCHOR_KEY must be base64 for exactly 32 random bytes")
		if err != nil {
			return err
		}
		auditAnchor, err = audit.NewFileCheckpointAnchor(auditAnchorFile)
		if err != nil {
			return err
		}
		logger.Warn("development on-host audit checkpoint anchor configured; independent anchoring is not connected")
	case "remote":
		auditAnchor, err = audit.NewRemoteCheckpointAnchor(audit.RemoteAnchorConfig{
			Endpoint:              envString("SECURESTORE_AUDIT_ANCHOR_ENDPOINT", ""),
			CAFile:                envString("SECURESTORE_AUDIT_ANCHOR_CA_FILE", ""),
			ClientCertificateFile: envString("SECURESTORE_AUDIT_ANCHOR_CLIENT_CERT_FILE", ""),
			ClientKeyFile:         envString("SECURESTORE_AUDIT_ANCHOR_CLIENT_KEY_FILE", ""),
			ReceiptPublicKeyFile:  envString("SECURESTORE_AUDIT_ANCHOR_RECEIPT_PUBLIC_KEY_FILE", ""),
			Timeout:               time.Duration(envInt64("SECURESTORE_AUDIT_ANCHOR_TIMEOUT_MS", 3000)) * time.Millisecond,
		})
		if err != nil {
			return err
		}
	default:
		return errors.New("SECURESTORE_AUDIT_ANCHOR_PROVIDER must be local or remote")
	}
	if err := auditService.ConfigureCheckpointAnchor(auditAnchor, auditAnchorKey); err != nil {
		return err
	}
	clear(auditAnchorKey)
	if _, err := auditService.RotateTo(auditKeyVersion); err != nil {
		return err
	}
	ingestManager, err := ingest.NewManager(ingest.Config{
		QuarantineDir: quarantineDir, MaxUploadBytes: maxUploadBytes, DefaultOwnerQuotaBytes: defaultOwnerQuotaBytes,
		StorageCapacityBytes: storageCapacityBytes, StorageReserveBytes: storageReserveBytes, ReservationTTL: reservationTTL,
		InspectionTTL: inspectionTTL, TransitionDelay: 350 * time.Millisecond,
		Scanner: scanner, Repository: ingestRepository,
		ProtectedStore: protectedService,
		PrepareLifecycleAudit: func(event ingest.LifecycleEvent) (auditoutbox.Intent, error) {
			return auditService.NewMutationIntent(audit.Input{ActorType: "system", ActorID: event.OwnerID, Action: event.Action, ResourceType: "upload", ResourceID: event.UploadID, Outcome: event.Outcome, ReasonCode: event.ReasonCode, CorrelationID: event.CorrelationID, FromState: string(event.FromState), ToState: string(event.ToState)})
		},
		DeliverLifecycleAudit: func(intent auditoutbox.Intent, durable bool) {
			if deliverErr := auditService.DeliverMutationIntent(intent, durable); deliverErr != nil {
				logger.Error("lifecycle audit delivery failed", "error", deliverErr)
			}
		},
	})
	if err != nil {
		return err
	}
	apiServer, err := api.NewServer(api.Config{
		Auth: authStore, Ingest: ingestManager, Audit: auditService, Protected: protectedService, Logger: logger,
		AllowedOrigins: allowedOrigins, SecureCookies: secureCookies,
		MaxRequestBytes:         maxUploadBytes + 1024*1024,
		AuthenticationRateLimit: authRateLimit, AuthenticationRateWindow: authRateWindow,
		MetricsToken: metricsToken, MetricsScrapeStaleAfter: metricsStaleAfter,
		DeploymentMode: deploymentMode,
	})
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr: listenAddress, Handler: apiServer,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20,
	}

	shutdownSignal, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Durable mutation intents are retried independently of request handling.
	// A crash after the business commit delays delivery but cannot erase the
	// evidence or create a duplicate signed-chain event.
	go func() {
		run := func() {
			if delivered, flushErr := auditService.FlushOutbox(100); flushErr != nil {
				logger.Error("audit outbox delivery failed", "error", flushErr)
			} else if delivered > 0 {
				logger.Info("audit outbox evidence delivered", "events", delivered)
			}
		}
		run()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				run()
			case <-shutdownSignal.Done():
				return
			}
		}
	}()
	// Reconciliation operations are authorized and journaled before the
	// filesystem is touched. This worker repairs either crash window: it can
	// perform a deletion that never started, or recognize an already absent
	// object and atomically commit the missing completion evidence.
	go func() {
		run := func() {
			operations, pendingErr := protectedService.PendingOrphanReconciliations(25)
			if pendingErr != nil {
				logger.Error("orphan reconciliation recovery query failed", "error", pendingErr)
				return
			}
			for _, operation := range operations {
				var outcome orphan.ResumeOutcome
				var resumeErr error
				switch operation.Zone {
				case "quarantine":
					outcome, resumeErr = ingestManager.ResumeOrphanReconciliation(operation)
				case "protected":
					outcome, resumeErr = protectedService.ResumeProtectedOrphan(operation)
				default:
					outcome = orphan.ResumeOutcome{Status: protectedstore.ReconciliationFailed, ReasonCode: "invalid_storage_zone"}
				}
				if resumeErr != nil {
					logger.Error("orphan reconciliation recovery deferred", "operation_id", operation.OperationID, "error", resumeErr)
					continue
				}
				auditOutcome, toState := "success", "deleted"
				if outcome.Status == protectedstore.ReconciliationFailed {
					auditOutcome, toState = "failed", "retained"
				}
				intent, intentErr := auditService.NewMutationIntent(audit.Input{ActorType: "system", ActorID: "reconciliation-worker", Action: "ORPHAN_DELETION_COMPLETED", ResourceType: "storage_orphan", ResourceID: operation.Token, Outcome: auditOutcome, ReasonCode: outcome.ReasonCode, CorrelationID: operation.CorrelationID, FromState: operation.Zone, ToState: toState})
				if intentErr != nil {
					logger.Error("orphan reconciliation audit intent failed", "operation_id", operation.OperationID, "error", intentErr)
					continue
				}
				updated, completeErr := protectedService.CompleteOrphanReconciliation(operation.OperationID, outcome.Status, outcome.ReasonCode, intent)
				if completeErr != nil {
					logger.Error("orphan reconciliation completion failed", "operation_id", operation.OperationID, "error", completeErr)
					continue
				}
				if updated {
					_ = auditService.DeliverMutationIntent(intent, protectedService.Durable())
					logger.Info("orphan reconciliation recovered", "operation_id", operation.OperationID, "status", outcome.Status, "reason", outcome.ReasonCode)
				}
			}
		}
		run()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				run()
			case <-shutdownSignal.Done():
				return
			}
		}
	}()
	// The lifecycle worker is policy-driven and idempotent. It only selects files
	// whose recovery window has elapsed and whose retention/hold gates permit
	// deletion; each attempt is persisted for operational review and safe retry.
	go func() {
		run := func() {
			result := protectedService.ProcessDuePurgesAudited(25, "system", "lifecycle-worker", "")
			if result.Examined == 0 && result.Failed == 0 {
				return
			}
			outcome := "success"
			if result.Failed > 0 {
				outcome = "failure"
			}
			if _, appendErr := auditService.Append(audit.Input{ActorType: "system", ActorID: "lifecycle-worker", Action: "SCHEDULED_LIFECYCLE_PROCESSING", ResourceType: "lifecycle", ResourceID: "due-deletions", Outcome: outcome, ReasonCode: "scheduled_policy_evaluation", ToState: strconv.Itoa(result.Completed)}); appendErr != nil {
				logger.Error("scheduled lifecycle audit append failed", "error", appendErr)
			}
		}
		run()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				run()
			case <-shutdownSignal.Done():
				return
			}
		}
	}()
	serverErrors := make(chan error, 1)
	go func() {
		if deploymentMode == "production" {
			logger.Info("server listening with TLS", "address", listenAddress)
			serverErrors <- server.ListenAndServeTLS(tlsCertificateFile, tlsKeyFile)
			return
		}
		logger.Info("development server listening without TLS", "address", listenAddress)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-shutdownSignal.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	}
}

func loadAuditKey(path string) ([]byte, error) {
	if encoded := strings.TrimSpace(os.Getenv("SECURESTORE_AUDIT_HMAC_KEY")); encoded != "" {
		return audit.DecodeKey(encoded)
	}
	if content, err := os.ReadFile(path); err == nil {
		return audit.DecodeKey(string(content))
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	// Local development receives a persistent, access-restricted key file.
	// Production deployments should inject SECURESTORE_AUDIT_HMAC_KEY from a
	// secret manager and avoid relying on a host-local key file.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	if _, err := file.WriteString(encoded); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return raw, nil
}

func loadAuditKeyring(path, currentVersion string) (map[string][]byte, error) {
	current, err := loadAuditKey(path)
	if err != nil {
		return nil, err
	}
	return decodeHistoricalKeys("SECURESTORE_AUDIT_HISTORICAL_KEYS", currentVersion, current)
}

func decodeHistoricalKeys(environmentName, currentVersion string, current []byte) (map[string][]byte, error) {
	keys := map[string][]byte{currentVersion: current}
	encoded := strings.TrimSpace(os.Getenv(environmentName))
	if encoded == "" {
		return keys, nil
	}
	var historical map[string]string
	if err := json.Unmarshal([]byte(encoded), &historical); err != nil {
		return nil, errors.New(environmentName + " must be a JSON object of version to base64 key")
	}
	for version, value := range historical {
		key, err := audit.DecodeKey(value)
		if err != nil {
			return nil, err
		}
		if existing, ok := keys[version]; ok && !strings.EqualFold(base64.StdEncoding.EncodeToString(existing), base64.StdEncoding.EncodeToString(key)) {
			return nil, errors.New("current key conflicts with historical keyring")
		}
		keys[version] = key
	}
	return keys, nil
}

func loadSecretKey(path, environmentName, invalidMessage string) ([]byte, error) {
	decode := func(encoded string) ([]byte, error) {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		if err != nil || len(key) != 32 {
			return nil, errors.New(invalidMessage)
		}
		return key, nil
	}
	if encoded := strings.TrimSpace(os.Getenv(environmentName)); encoded != "" {
		return decode(encoded)
	}
	if content, err := os.ReadFile(path); err == nil {
		return decode(string(content))
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := file.WriteString(base64.StdEncoding.EncodeToString(raw)); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return raw, nil
}

func envString(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envInt64(name string, fallback int64) int64 {
	value, err := strconv.ParseInt(os.Getenv(name), 10, 64)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func envBool(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}
