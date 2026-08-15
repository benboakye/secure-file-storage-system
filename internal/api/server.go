package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"securestore/internal/audit"
	"securestore/internal/auditoutbox"
	"securestore/internal/authn"
	"securestore/internal/ingest"
	"securestore/internal/orphan"
	"securestore/internal/protectedstore"
)

const sessionCookieName = "securestore_session"
const orphanReconciliationMinimumAge = time.Hour

type Config struct {
	Auth                     *authn.Store
	Ingest                   *ingest.Manager
	Audit                    *audit.Service
	Protected                *protectedstore.Service
	Logger                   *slog.Logger
	AllowedOrigins           []string
	SecureCookies            bool
	MaxRequestBytes          int64
	AuthenticationRateLimit  int
	AuthenticationRateWindow time.Duration
	MetricsToken             string
	MetricsScrapeStaleAfter  time.Duration
	DeploymentMode           string
}

type Server struct {
	auth                  *authn.Store
	ingest                *ingest.Manager
	audit                 *audit.Service
	protected             *protectedstore.Service
	logger                *slog.Logger
	allowedOrigins        map[string]struct{}
	secureCookies         bool
	deploymentMode        string
	maxRequestBytes       int64
	startedAt             time.Time
	handler               http.Handler
	authenticationLimiter *authenticationRateLimiter
	telemetry             *telemetryRegistry
}

type contextKey string

const correlationKey contextKey = "correlation-id"

type errorResponse struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	CorrelationID string `json:"correlationId"`
}

type sessionResponse struct {
	User      authn.User `json:"user"`
	CSRFToken string     `json:"csrfToken"`
}

type messageResponse struct {
	Message string `json:"message"`
}

type createGrantRequest struct {
	RecipientEmail string     `json:"recipientEmail"`
	Permission     string     `json:"permission"`
	ExpiresAt      *time.Time `json:"expiresAt"`
}

type userFilePage struct {
	Files []protectedstore.LogicalFile `json:"files"`
	Total int                          `json:"total"`
}

type adminSecuritySummary struct {
	GeneratedAt time.Time             `json:"generatedAt"`
	Auth        authn.SecurityPosture `json:"authentication"`
	Accounts    adminSecurityAccounts `json:"accounts"`
	Ingestion   struct {
		StatusCounts map[ingest.Status]int `json:"statusCounts"`
		Scanner      ingest.ScannerPosture `json:"scanner"`
	} `json:"ingestion"`
	AuditChainConnected        bool                              `json:"auditChainConnected"`
	AuditAnchor                audit.AnchorVerification          `json:"auditAnchor"`
	EncryptionServiceConnected bool                              `json:"encryptionServiceConnected"`
	KeyService                 protectedstore.KeyProviderPosture `json:"keyService"`
	KeyRotation                protectedstore.KeyRotationPosture `json:"keyRotation"`
}

type dekRewrapRequest struct {
	Limit int `json:"limit"`
}

type orphanPreview struct {
	GeneratedAt       time.Time          `json:"generatedAt"`
	MinimumAgeSeconds int64              `json:"minimumAgeSeconds"`
	Candidates        []orphan.Candidate `json:"candidates"`
}

type reconcileOrphansRequest struct {
	Tokens []string `json:"tokens"`
}
type reconcileOrphansResult struct {
	Requested int `json:"requested"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

type adminSecurityAccounts struct {
	Total          int `json:"total"`
	Verified       int `json:"verified"`
	Unverified     int `json:"unverified"`
	Active         int `json:"active"`
	Suspended      int `json:"suspended"`
	Locked         int `json:"locked"`
	Administrators int `json:"administrators"`
	Auditors       int `json:"auditors"`
}

type adminMonitoringSummary struct {
	GeneratedAt   time.Time `json:"generatedAt"`
	StartedAt     time.Time `json:"startedAt"`
	UptimeSeconds int64     `json:"uptimeSeconds"`
	API           struct {
		Status string `json:"status"`
	} `json:"api"`
	Persistence struct {
		Authentication   authn.PersistencePosture `json:"authentication"`
		IngestionDurable bool                     `json:"ingestionDurable"`
	} `json:"persistence"`
	Worker struct {
		Mode              string `json:"mode"`
		PendingProcessing int    `json:"pendingProcessing"`
		FailedRecords     int    `json:"failedRecords"`
	} `json:"worker"`
	Quarantine struct {
		Bytes           int64 `json:"bytes"`
		OrphanedObjects int   `json:"orphanedObjects"`
		OrphanedBytes   int64 `json:"orphanedBytes"`
	} `json:"quarantine"`
	Scanner  ingest.ScannerPosture `json:"scanner"`
	Policies struct {
		Ingestion         ingest.PolicyPosture `json:"ingestion"`
		SessionTTLSeconds int64                `json:"sessionTtlSeconds"`
		SecureCookies     bool                 `json:"secureCookies"`
		AllowedOrigins    int                  `json:"allowedOrigins"`
		DeploymentMode    string               `json:"deploymentMode"`
		HTTPSRequired     bool                 `json:"httpsRequired"`
	} `json:"policies"`
	ExternalTelemetryConnected bool                              `json:"externalTelemetryConnected"`
	Telemetry                  telemetryPosture                  `json:"telemetry"`
	BackupMonitoringConnected  bool                              `json:"backupMonitoringConnected"`
	EncryptionServiceConnected bool                              `json:"encryptionServiceConnected"`
	KeyService                 protectedstore.KeyProviderPosture `json:"keyService"`
	Audit                      struct {
		Durable         bool                     `json:"durable"`
		IntegrityValid  bool                     `json:"integrityValid"`
		EventCount      int                      `json:"eventCount"`
		EventsLast24H   int                      `json:"eventsLast24Hours"`
		DeniedLast24H   int                      `json:"deniedLast24Hours"`
		HighRiskLast24H int                      `json:"highRiskLast24Hours"`
		PendingEvidence int                      `json:"pendingEvidence"`
		Anchor          audit.AnchorVerification `json:"anchor"`
		Alerts          []audit.Alert            `json:"alerts"`
	} `json:"audit"`
}

type adminLifecycleSummary struct {
	GeneratedAt  time.Time                       `json:"generatedAt"`
	Lifecycle    ingest.LifecyclePosture         `json:"lifecycle"`
	Protected    protectedstore.LifecycleSummary `json:"protectedFiles"`
	Capabilities struct {
		QuarantineWorkflow    bool `json:"quarantineWorkflow"`
		InspectionDecisions   bool `json:"inspectionDecisions"`
		ProtectedStorage      bool `json:"protectedStorage"`
		VersionHistory        bool `json:"versionHistory"`
		RetentionPolicy       bool `json:"retentionPolicy"`
		LegalHolds            bool `json:"legalHolds"`
		DeletionGracePeriod   bool `json:"deletionGracePeriod"`
		CryptographicDeletion bool `json:"cryptographicDeletion"`
		BackupMonitoring      bool `json:"backupMonitoring"`
		VerifiedRecovery      bool `json:"verifiedRecovery"`
	} `json:"capabilities"`
}

type privilegedMFACompletionResponse struct {
	User          authn.User `json:"user"`
	CSRFToken     string     `json:"csrfToken"`
	RecoveryCodes []string   `json:"recoveryCodes,omitempty"`
}

func NewServer(config Config) (*Server, error) {
	if config.Auth == nil || config.Ingest == nil || config.Audit == nil {
		return nil, errors.New("auth, ingest, and audit services are required")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.MaxRequestBytes <= 0 {
		config.MaxRequestBytes = 26 * 1024 * 1024
	}
	if config.AuthenticationRateLimit <= 0 {
		config.AuthenticationRateLimit = 10
	}
	if config.AuthenticationRateWindow <= 0 {
		config.AuthenticationRateWindow = 5 * time.Minute
	}
	telemetry, err := newTelemetryRegistry(config.MetricsToken, config.MetricsScrapeStaleAfter)
	if err != nil {
		return nil, err
	}
	deploymentMode := strings.ToLower(strings.TrimSpace(config.DeploymentMode))
	if deploymentMode == "" {
		deploymentMode = "development"
	}
	if deploymentMode != "development" && deploymentMode != "production" {
		return nil, errors.New("deployment mode must be development or production")
	}
	server := &Server{
		auth:                  config.Auth,
		ingest:                config.Ingest,
		audit:                 config.Audit,
		protected:             config.Protected,
		logger:                config.Logger,
		allowedOrigins:        make(map[string]struct{}),
		secureCookies:         config.SecureCookies,
		deploymentMode:        deploymentMode,
		maxRequestBytes:       config.MaxRequestBytes,
		startedAt:             time.Now().UTC(),
		authenticationLimiter: newAuthenticationRateLimiter(config.AuthenticationRateLimit, config.AuthenticationRateWindow),
		telemetry:             telemetry,
	}
	for _, origin := range config.AllowedOrigins {
		server.allowedOrigins[origin] = struct{}{}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", server.health)
	mux.HandleFunc("GET /metrics", server.metrics)
	mux.HandleFunc("POST /api/v1/auth/register", server.register)
	mux.HandleFunc("POST /api/v1/auth/verify-email", server.verifyEmail)
	mux.HandleFunc("POST /api/v1/auth/resend-verification", server.resendVerification)
	mux.HandleFunc("POST /api/v1/auth/login", server.login)
	mux.HandleFunc("POST /api/v1/admin/auth/login", server.privilegedLogin)
	mux.HandleFunc("POST /api/v1/admin/auth/mfa/complete", server.completePrivilegedMFA)
	mux.HandleFunc("POST /api/v1/admin/auth/step-up", server.createStepUpProof)
	mux.HandleFunc("POST /api/v1/admin/auth/activate", server.activatePrivilegedAccount)
	mux.HandleFunc("POST /api/v1/auth/logout", server.logout)
	mux.HandleFunc("GET /api/v1/session", server.getSession)
	mux.HandleFunc("GET /api/v1/admin/users", server.listUsers)
	mux.HandleFunc("POST /api/v1/admin/users/invitations", server.invitePrivilegedAccount)
	mux.HandleFunc("PATCH /api/v1/admin/users/{userId}/status", server.updateUserStatus)
	mux.HandleFunc("POST /api/v1/admin/users/{userId}/sessions/revoke", server.revokeUserSessions)
	mux.HandleFunc("GET /api/v1/admin/resources", server.listAdminResources)
	mux.HandleFunc("GET /api/v1/admin/resources/orphans", server.listOrphans)
	mux.HandleFunc("POST /api/v1/admin/resources/orphans/reconcile", server.reconcileOrphans)
	mux.HandleFunc("GET /api/v1/admin/security", server.adminSecurity)
	mux.HandleFunc("POST /api/v1/admin/security/keys/rewrap", server.rewrapDEKs)
	mux.HandleFunc("GET /api/v1/admin/monitoring", server.adminMonitoring)
	mux.HandleFunc("GET /api/v1/admin/lifecycle", server.adminLifecycle)
	mux.HandleFunc("POST /api/v1/admin/lifecycle/process", server.processLifecycleDeletions)
	mux.HandleFunc("POST /api/v1/admin/lifecycle/files/{fileId}/recovery-drill", server.runRecoveryDrill)
	mux.HandleFunc("GET /api/v1/admin/audit", server.listAuditEvents)
	mux.HandleFunc("GET /api/v1/admin/audit/export", server.exportAuditEvents)
	mux.HandleFunc("PUT /api/v1/admin/resources/owners/{ownerId}/quota", server.updateOwnerQuota)
	mux.HandleFunc("DELETE /api/v1/admin/resources/owners/{ownerId}/quota", server.resetOwnerQuota)
	mux.HandleFunc("POST /api/v1/uploads", server.createUpload)
	mux.HandleFunc("GET /api/v1/files", server.listUserFiles)
	mux.HandleFunc("GET /api/v1/files/trash", server.listTrash)
	mux.HandleFunc("POST /api/v1/files/{fileId}/trash", server.moveFileToTrash)
	mux.HandleFunc("POST /api/v1/files/{fileId}/restore", server.restoreFileFromTrash)
	mux.HandleFunc("DELETE /api/v1/files/{fileId}", server.purgeFile)
	mux.HandleFunc("GET /api/v1/files/shared", server.listSharedFiles)
	mux.HandleFunc("GET /api/v1/files/{fileId}", server.getUserFile)
	mux.HandleFunc("GET /api/v1/files/{fileId}/content", server.downloadUserFile)
	mux.HandleFunc("POST /api/v1/files/{fileId}/versions/{versionId}/restore", server.restoreUserFileVersion)
	mux.HandleFunc("GET /api/v1/files/{fileId}/grants", server.listFileGrants)
	mux.HandleFunc("POST /api/v1/files/{fileId}/grants", server.createFileGrant)
	mux.HandleFunc("DELETE /api/v1/files/{fileId}/grants/{grantId}", server.revokeFileGrant)
	mux.HandleFunc("PUT /api/v1/admin/lifecycle/files/{fileId}/retention", server.setFileRetention)
	mux.HandleFunc("PUT /api/v1/admin/lifecycle/files/{fileId}/legal-hold", server.setFileLegalHold)
	mux.HandleFunc("GET /api/v1/uploads/{uploadId}", server.getUpload)
	mux.HandleFunc("GET /api/v1/uploads/{uploadId}/content", server.downloadUpload)
	server.handler = server.telemetry.observe(mux, server.securityHeaders(server.correlation(server.originCheck(mux))))
	return server, nil
}

func (s *Server) listAuditEvents(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requirePrivileged(response, request)
	if !ok {
		return
	}
	// Audit reads are themselves security-relevant. Appending before loading the
	// page avoids recursive "verify the verification event" ambiguity while the
	// returned verification still covers the newly appended read event.
	if _, err := s.audit.Append(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "AUDIT_READ", ResourceType: "audit_chain", ResourceID: "main", Outcome: "success", ReasonCode: "privileged_review", CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request)}); err != nil {
		s.internalError(response, request, err)
		return
	}
	query, err := parseAuditQuery(request)
	if err != nil {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_AUDIT_FILTER", "Choose a valid audit date range and supported filters.")
		return
	}
	page, err := s.audit.List(query)
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, page)
}

func (s *Server) exportAuditEvents(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requirePrivileged(response, request)
	if !ok {
		return
	}
	query, err := parseAuditQuery(request)
	if err != nil {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_AUDIT_FILTER", "Choose a valid audit date range and supported filters.")
		return
	}
	if _, err := s.audit.Append(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "AUDIT_EXPORT", ResourceType: "audit_chain", ResourceID: "main", Outcome: "success", ReasonCode: "privileged_export", CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request)}); err != nil {
		s.internalError(response, request, err)
		return
	}
	events, verification, err := s.audit.Export(query, 5000)
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	response.Header().Set("Content-Type", "text/csv; charset=utf-8")
	response.Header().Set("Content-Disposition", `attachment; filename="securestore-audit-events.csv"`)
	response.Header().Set("X-Audit-Chain-Valid", strconv.FormatBool(verification.Valid))
	response.WriteHeader(http.StatusOK)
	writer := csv.NewWriter(response)
	_ = writer.Write([]string{"sequence", "occurred_at", "actor_type", "actor_id", "action", "resource_type", "resource_id", "outcome", "reason_code", "correlation_id", "network_source", "from_state", "to_state"})
	for _, event := range events {
		_ = writer.Write([]string{strconv.FormatInt(event.Sequence, 10), event.OccurredAt.Format(time.RFC3339Nano), event.ActorType, event.ActorID, event.Action, event.ResourceType, event.ResourceID, event.Outcome, event.ReasonCode, event.CorrelationID, event.NetworkSource, event.FromState, event.ToState})
	}
	writer.Flush()
}

func (s *Server) adminLifecycle(response http.ResponseWriter, request *http.Request) {
	if _, _, ok := s.requirePrivileged(response, request); !ok {
		return
	}
	posture, err := s.ingest.LifecyclePosture()
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	result := adminLifecycleSummary{GeneratedAt: time.Now().UTC(), Lifecycle: posture}
	result.Capabilities.QuarantineWorkflow = true
	result.Capabilities.InspectionDecisions = true
	result.Capabilities.ProtectedStorage = s.protected != nil && s.protected.Durable()
	result.Capabilities.VersionHistory = result.Capabilities.ProtectedStorage
	result.Capabilities.VerifiedRecovery = result.Capabilities.ProtectedStorage
	if s.protected != nil {
		result.Protected, err = s.protected.LifecycleSummary(50)
		if err != nil {
			s.internalError(response, request, err)
			return
		}
		result.Capabilities.RetentionPolicy = s.protected.Durable()
		result.Capabilities.LegalHolds = s.protected.Durable()
		result.Capabilities.DeletionGracePeriod = s.protected.Durable()
		result.Capabilities.CryptographicDeletion = s.protected.Durable()
	}
	writeJSON(response, http.StatusOK, result)
}

func (s *Server) setFileRetention(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireAdminMutation(response, request)
	if !ok {
		return
	}
	var input struct {
		RetentionUntil *time.Time `json:"retentionUntil"`
	}
	if err := readJSON(response, request, &input); err != nil || input.RetentionUntil == nil || input.RetentionUntil.Before(time.Now().UTC()) {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_RETENTION", "Choose a future retention date.")
		return
	}
	fileID := request.PathValue("fileId")
	intent, err := s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_RETENTION_UPDATED", ResourceType: "file", ResourceID: fileID, Outcome: "success", ReasonCode: "administrator_policy", CorrelationID: correlationID(request.Context()), ToState: input.RetentionUntil.UTC().Format(time.RFC3339)})
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	file, durable, err := s.protected.SetRetentionAudited(fileID, input.RetentionUntil, intent)
	if err != nil {
		s.writeLifecycleError(response, request, err)
		return
	}
	if err := s.audit.DeliverMutationIntent(intent, durable); err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, file)
}

func (s *Server) processLifecycleDeletions(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireAdminMutation(response, request)
	if !ok {
		return
	}
	if s.protected == nil {
		s.writeError(response, request, http.StatusServiceUnavailable, "LIFECYCLE_UNAVAILABLE", "Protected-storage lifecycle processing is unavailable.")
		return
	}
	if _, err := s.audit.Append(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "LIFECYCLE_PROCESSING_REQUESTED", ResourceType: "lifecycle", ResourceID: "due-deletions", Outcome: "success", ReasonCode: "administrator_action", CorrelationID: correlationID(request.Context())}); err != nil {
		s.internalError(response, request, err)
		return
	}
	result := s.protected.ProcessDuePurgesAudited(25, "user", session.User.ID, correlationID(request.Context()))
	outcome := "success"
	if result.Failed > 0 {
		outcome = "failure"
	}
	s.bestEffortAudit(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "LIFECYCLE_PROCESSING_COMPLETED", ResourceType: "lifecycle", ResourceID: "due-deletions", Outcome: outcome, ReasonCode: "scheduled_policy_evaluation", CorrelationID: correlationID(request.Context()), ToState: fmt.Sprintf("examined=%d;completed=%d;failed=%d", result.Examined, result.Completed, result.Failed)})
	writeJSON(response, http.StatusOK, result)
}

func (s *Server) runRecoveryDrill(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireAdminMutation(response, request)
	if !ok {
		return
	}
	if s.protected == nil {
		s.writeError(response, request, http.StatusServiceUnavailable, "RECOVERY_DRILL_UNAVAILABLE", "Protected-storage recovery verification is unavailable.")
		return
	}
	fileID := request.PathValue("fileId")
	if _, err := s.audit.Append(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "RECOVERY_DRILL_REQUESTED", ResourceType: "file", ResourceID: fileID, Outcome: "success", ReasonCode: "administrator_assurance", CorrelationID: correlationID(request.Context())}); err != nil {
		s.internalError(response, request, err)
		return
	}
	intent, err := s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "RECOVERY_DRILL_COMPLETED", ResourceType: "file", ResourceID: fileID, Outcome: "success", ReasonCode: "verification_pending", CorrelationID: correlationID(request.Context())})
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	drill, durable, err := s.protected.RunRecoveryDrillAudited(fileID, session.User.ID, intent)
	if !durable && drill.DrillID != "" {
		intent.Outcome, intent.ReasonCode, intent.ToState = drill.Outcome, drill.ReasonCode, drill.Outcome
	}
	if err != nil {
		_ = s.audit.DeliverMutationIntent(intent, durable)
		if errors.Is(err, protectedstore.ErrNotFound) {
			s.writeLifecycleError(response, request, err)
		} else {
			s.writeError(response, request, http.StatusUnprocessableEntity, "RECOVERY_VERIFICATION_FAILED", "The encrypted version did not pass recovery verification.")
		}
		return
	}
	if err := s.audit.DeliverMutationIntent(intent, durable); err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, drill)
}

func (s *Server) setFileLegalHold(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireAdminMutation(response, request)
	if !ok {
		return
	}
	var input struct {
		Enabled bool   `json:"enabled"`
		Reason  string `json:"reason"`
	}
	if err := readJSON(response, request, &input); err != nil {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_LEGAL_HOLD", "Provide a valid legal-hold instruction.")
		return
	}
	fileID := request.PathValue("fileId")
	state := "released"
	if input.Enabled {
		state = "active"
	}
	intent, err := s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "LEGAL_HOLD_UPDATED", ResourceType: "file", ResourceID: fileID, Outcome: "success", ReasonCode: "administrator_action", CorrelationID: correlationID(request.Context()), ToState: state})
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	file, durable, err := s.protected.SetLegalHoldAudited(fileID, input.Enabled, input.Reason, intent)
	if err != nil {
		s.writeLifecycleError(response, request, err)
		return
	}
	if err := s.audit.DeliverMutationIntent(intent, durable); err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, file)
}

func (s *Server) adminMonitoring(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requirePrivileged(response, request)
	if !ok {
		return
	}
	if _, err := s.audit.Append(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "MONITORING_READ", ResourceType: "system", ResourceID: "runtime", Outcome: "success", ReasonCode: "privileged_review", CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request)}); err != nil {
		s.internalError(response, request, err)
		return
	}
	resources, err := s.ingest.ListAdminResources("", 1, 0)
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	now := time.Now().UTC()
	result := adminMonitoringSummary{GeneratedAt: now, StartedAt: s.startedAt, UptimeSeconds: int64(now.Sub(s.startedAt).Seconds())}
	result.API.Status = "operational"
	result.Persistence.Authentication = s.auth.PersistencePosture()
	result.Persistence.IngestionDurable = resources.Summary.MetadataDurable
	result.Worker.Mode = "in-process"
	result.Worker.PendingProcessing = resources.Summary.PendingProcessing
	result.Worker.FailedRecords = resources.Summary.StatusCounts[ingest.StatusFailed]
	result.Quarantine.Bytes = resources.Summary.QuarantineBytes
	result.Quarantine.OrphanedObjects = resources.Summary.OrphanedObjects
	result.Quarantine.OrphanedBytes = resources.Summary.OrphanedBytes
	result.Scanner = s.ingest.ScannerPosture()
	result.Policies.Ingestion = s.ingest.PolicyPosture()
	result.Policies.SessionTTLSeconds = s.auth.SecurityPosture().SessionTTLSeconds
	result.Policies.SecureCookies = s.secureCookies
	result.Policies.AllowedOrigins = len(s.allowedOrigins)
	result.Policies.DeploymentMode = s.deploymentMode
	result.Policies.HTTPSRequired = s.deploymentMode == "production"
	result.Telemetry = s.telemetry.posture(now)
	result.ExternalTelemetryConnected = result.Telemetry.Connected
	if s.protected != nil {
		result.KeyService = s.protected.KeyPosture()
		result.EncryptionServiceConnected = s.protected.Durable() && result.KeyService.ProductionReady
	}
	auditPage, err := s.audit.List(audit.Query{From: now.Add(-24 * time.Hour), Limit: 1})
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	result.Audit.Durable = s.audit.Durable()
	result.Audit.IntegrityValid = auditPage.Verification.Valid && (!auditPage.Verification.Anchor.Connected || auditPage.Verification.Anchor.Valid)
	result.Audit.EventCount = auditPage.Verification.EventCount
	result.Audit.EventsLast24H = auditPage.Summary.Matching
	result.Audit.DeniedLast24H = auditPage.Summary.Denied
	result.Audit.HighRiskLast24H = auditPage.Summary.HighRisk
	result.Audit.PendingEvidence, err = s.audit.PendingOutboxCount()
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	result.Audit.Alerts = auditPage.Alerts
	result.Audit.Anchor = auditPage.Verification.Anchor
	writeJSON(response, http.StatusOK, result)
}

func (s *Server) adminSecurity(response http.ResponseWriter, request *http.Request) {
	if _, _, ok := s.requirePrivileged(response, request); !ok {
		return
	}

	result := adminSecuritySummary{GeneratedAt: time.Now().UTC(), Auth: s.auth.SecurityPosture()}
	// Iterate the safe directory in bounded pages so organization totals are
	// authoritative even after the directory grows beyond one UI page.
	for offset := 0; ; offset += 100 {
		page, err := s.auth.ListUsers("", 100, offset)
		if err != nil {
			s.internalError(response, request, err)
			return
		}
		result.Accounts.Total = page.Total
		for _, user := range page.Users {
			if user.VerificationStatus == "verified" {
				result.Accounts.Verified++
			} else {
				result.Accounts.Unverified++
			}
			switch user.AccountStatus {
			case "active":
				result.Accounts.Active++
			case "suspended":
				result.Accounts.Suspended++
			case "locked":
				result.Accounts.Locked++
			}
			if user.Role == "admin" {
				result.Accounts.Administrators++
			}
			if user.Role == "auditor" {
				result.Accounts.Auditors++
			}
		}
		if offset+len(page.Users) >= page.Total || len(page.Users) == 0 {
			break
		}
	}
	resources, err := s.ingest.ListAdminResources("", 1, 0)
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	result.Ingestion.StatusCounts = resources.Summary.StatusCounts
	result.Ingestion.Scanner = s.ingest.ScannerPosture()
	auditVerification, err := s.audit.Verify()
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	result.AuditAnchor = auditVerification.Anchor
	result.AuditChainConnected = s.audit.Durable() && auditVerification.Valid
	if s.protected != nil {
		result.KeyService = s.protected.KeyPosture()
		result.EncryptionServiceConnected = s.protected.Durable() && result.KeyService.ProductionReady
		result.KeyRotation, err = s.protected.KeyRotationPosture()
		if err != nil {
			s.internalError(response, request, err)
			return
		}
	}
	writeJSON(response, http.StatusOK, result)
}

func (s *Server) rewrapDEKs(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireAdminMutation(response, request)
	if !ok {
		return
	}
	if s.protected == nil {
		s.writeError(response, request, http.StatusServiceUnavailable, "PROTECTED_STORAGE_UNAVAILABLE", "Protected storage is not connected.")
		return
	}
	input := dekRewrapRequest{Limit: 25}
	if request.Body != nil && request.ContentLength != 0 {
		if err := readJSON(response, request, &input); err != nil {
			return
		}
	}
	if input.Limit < 1 || input.Limit > 100 {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_REWRAP_REQUEST", "Choose a batch size from 1 to 100.")
		return
	}
	result, err := s.protected.RewrapDEKs(input.Limit, func(metadata protectedstore.Metadata, fromID, fromVersion, toID, toVersion string) (auditoutbox.Intent, error) {
		return s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_DEK_REWRAPPED", ResourceType: "file_version", ResourceID: metadata.VersionID, Outcome: "success", ReasonCode: "administrator_key_rotation", CorrelationID: correlationID(request.Context()), FromState: fromID + ":" + fromVersion, ToState: toID + ":" + toVersion})
	})
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	for _, intent := range result.Intents {
		if err := s.audit.DeliverMutationIntent(intent, result.Durable); err != nil {
			s.internalError(response, request, err)
			return
		}
	}
	writeJSON(response, http.StatusOK, result)
}

func (s *Server) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	s.handler.ServeHTTP(response, request)
}

func (s *Server) health(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) metrics(response http.ResponseWriter, request *http.Request) {
	if !s.telemetry.enabled {
		http.NotFound(response, request)
		return
	}
	if !s.telemetry.authorized(request.Header.Get("Authorization")) {
		response.Header().Set("WWW-Authenticate", `Bearer realm="securestore-metrics"`)
		http.Error(response, "metrics authentication required", http.StatusUnauthorized)
		return
	}
	resources, err := s.ingest.ListAdminResources("", 1, 0)
	if err != nil {
		http.Error(response, "metrics collection unavailable", http.StatusServiceUnavailable)
		return
	}
	now := time.Now().UTC()
	metrics := metricsFromResources(resources)
	metrics.UptimeSeconds = int64(now.Sub(s.startedAt).Seconds())
	scannerPosture := s.ingest.ScannerPosture()
	metrics.ScannerConnected = scannerPosture.Connected
	metrics.ScannerProductionReady = scannerPosture.ProductionReady
	metrics.ScannerSignaturesFresh = scannerPosture.SignaturesFresh
	metrics.ScannerSignatureAgeSeconds = scannerPosture.SignatureAgeSeconds
	metrics.ScannerSignatureMaxAgeSeconds = scannerPosture.SignatureMaxAgeSeconds
	if s.protected != nil {
		keyPosture := s.protected.KeyPosture()
		metrics.KeyServiceConnected = keyPosture.Connected
		metrics.KeyServiceProductionReady = keyPosture.ProductionReady
		metrics.KeyServiceHardwareBacked = keyPosture.HardwareBacked
		capacity, capacityErr := s.protected.CapacitySummary()
		if capacityErr != nil {
			http.Error(response, "metrics collection unavailable", http.StatusServiceUnavailable)
			return
		}
		metrics.ProtectedDurable = s.protected.Durable()
		metrics.ProtectedObjects = capacity.TrackedObjects
		metrics.ProtectedCiphertextBytes = capacity.TrackedCiphertextBytes
		metrics.ProtectedOrphans = capacity.OrphanedObjects
		metrics.ProtectedMissing = capacity.MissingObjects
	}
	pending, err := s.audit.PendingOutboxCount()
	if err != nil {
		http.Error(response, "metrics collection unavailable", http.StatusServiceUnavailable)
		return
	}
	metrics.AuditPendingEvidence = int64(pending)
	verification, err := s.audit.Verify()
	if err != nil {
		http.Error(response, "metrics collection unavailable", http.StatusServiceUnavailable)
		return
	}
	metrics.AuditAnchorConnected = verification.Anchor.Connected
	metrics.AuditAnchorProductionReady = verification.Anchor.ProductionReady
	metrics.AuditAnchorValid = verification.Anchor.Valid
	if verification.VerifiedThrough > verification.Anchor.AnchoredThrough {
		metrics.AuditAnchorLagEvents = verification.VerifiedThrough - verification.Anchor.AnchoredThrough
	}
	var builder strings.Builder
	s.telemetry.recordScrape(now)
	s.telemetry.renderHTTP(&builder)
	renderOperationalMetrics(&builder, metrics)
	response.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(response, builder.String())
}

func (s *Server) register(response http.ResponseWriter, request *http.Request) {
	var input struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := readJSON(response, request, &input); err != nil {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_REQUEST", "Account details do not meet requirements.")
		return
	}
	err := s.auth.Register(input.Name, input.Email, input.Password)
	if err != nil {
		if errors.Is(err, authn.ErrInvalidInput) {
			s.writeError(response, request, http.StatusBadRequest, "INVALID_ACCOUNT_DETAILS", "Account details do not meet requirements.")
			return
		}
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusAccepted, messageResponse{Message: "If the address can be registered, verification instructions will be sent."})
}

func (s *Server) verifyEmail(response http.ResponseWriter, request *http.Request) {
	var input struct {
		Token string `json:"token"`
	}
	if err := readJSON(response, request, &input); err != nil {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_VERIFICATION_TOKEN", "This verification link is invalid or has expired.")
		return
	}
	if err := s.auth.VerifyEmail(input.Token); err != nil {
		if errors.Is(err, authn.ErrVerificationToken) {
			s.writeError(response, request, http.StatusBadRequest, "INVALID_VERIFICATION_TOKEN", "This verification link is invalid or has expired.")
			return
		}
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, messageResponse{Message: "Email verified. Sign in to continue."})
}

func (s *Server) resendVerification(response http.ResponseWriter, request *http.Request) {
	var input struct {
		Email string `json:"email"`
	}
	if err := readJSON(response, request, &input); err != nil {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_REQUEST", "Enter a valid email address.")
		return
	}
	if err := s.auth.ResendVerification(input.Email); err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusAccepted, messageResponse{Message: "If an unverified account exists, new verification instructions will be sent."})
}

func (s *Server) login(response http.ResponseWriter, request *http.Request) {
	s.loginForAudience(response, request, false)
}

func (s *Server) privilegedLogin(response http.ResponseWriter, request *http.Request) {
	s.loginForAudience(response, request, true)
}

func (s *Server) loginForAudience(response http.ResponseWriter, request *http.Request, privileged bool) {
	scope := "standard-password"
	if privileged {
		scope = "privileged-password"
	}
	if !s.authenticationLimiter.Allow(scope, clientAddress(request)) {
		s.bestEffortAudit(audit.Input{ActorType: "anonymous", Action: "AUTHENTICATION_RATE_LIMIT", ResourceType: "session", Outcome: "denied", ReasonCode: "network_rate_limited", CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request)})
		response.Header().Set("Retry-After", "300")
		s.writeError(response, request, http.StatusTooManyRequests, "AUTHENTICATION_THROTTLED", "Too many authentication attempts. Try again later.")
		return
	}
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := readJSON(response, request, &input); err != nil {
		s.writeError(response, request, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Email or password is incorrect.")
		return
	}
	if privileged && s.auth.PrivilegedMFARequired() {
		challenge, err := s.auth.BeginPrivilegedLogin(input.Email, input.Password)
		if err != nil {
			s.bestEffortAudit(audit.Input{ActorType: "anonymous", Action: "PRIVILEGED_MFA_BEGIN", ResourceType: "session", Outcome: "denied", ReasonCode: auditReason(err), CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request)})
			if errors.Is(err, authn.ErrEmailNotVerified) {
				s.writeError(response, request, http.StatusForbidden, "EMAIL_NOT_VERIFIED", "Verify your email address before signing in.")
				return
			}
			if errors.Is(err, authn.ErrInvalidCredentials) {
				s.writeError(response, request, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Email or password is incorrect.")
				return
			}
			s.internalError(response, request, err)
			return
		}
		s.bestEffortAudit(audit.Input{ActorType: "anonymous", Action: "PRIVILEGED_MFA_BEGIN", ResourceType: "session", Outcome: "success", ReasonCode: "password_verified_mfa_pending", CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request), ToState: challenge.Mode})
		writeJSON(response, http.StatusAccepted, challenge)
		return
	}
	var user authn.User
	var token string
	var session authn.Session
	var err error
	if privileged {
		user, token, session, err = s.auth.LoginPrivileged(input.Email, input.Password)
	} else {
		user, token, session, err = s.auth.Login(input.Email, input.Password)
	}
	if err != nil {
		s.bestEffortAudit(audit.Input{ActorType: "anonymous", ActorID: "", Action: "AUTHENTICATION", ResourceType: "session", ResourceID: "", Outcome: "denied", ReasonCode: auditReason(err), CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request)})
		if errors.Is(err, authn.ErrInvalidCredentials) {
			s.writeError(response, request, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Email or password is incorrect.")
			return
		}
		if errors.Is(err, authn.ErrEmailNotVerified) {
			s.writeError(response, request, http.StatusForbidden, "EMAIL_NOT_VERIFIED", "Verify your email address before signing in.")
			return
		}
		s.internalError(response, request, err)
		return
	}
	if _, auditErr := s.audit.Append(audit.Input{ActorType: "user", ActorID: user.ID, Action: "AUTHENTICATION", ResourceType: "session", ResourceID: session.Audience, Outcome: "success", ReasonCode: "credentials_verified", CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request)}); auditErr != nil {
		s.auth.Logout(token)
		s.internalError(response, request, auditErr)
		return
	}
	s.setSessionCookie(response, token, session.ExpiresAt)
	writeJSON(response, http.StatusOK, sessionResponse{User: user, CSRFToken: session.CSRFToken})
}

func (s *Server) completePrivilegedMFA(response http.ResponseWriter, request *http.Request) {
	if !s.authenticationLimiter.Allow("privileged-mfa", clientAddress(request)) {
		s.bestEffortAudit(audit.Input{ActorType: "anonymous", Action: "AUTHENTICATION_RATE_LIMIT", ResourceType: "session", Outcome: "denied", ReasonCode: "network_rate_limited", CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request)})
		response.Header().Set("Retry-After", "300")
		s.writeError(response, request, http.StatusTooManyRequests, "AUTHENTICATION_THROTTLED", "Too many authentication attempts. Try again later.")
		return
	}
	var input struct {
		ChallengeToken string `json:"challengeToken"`
		Code           string `json:"code"`
	}
	if err := readJSON(response, request, &input); err != nil {
		s.writeError(response, request, http.StatusUnauthorized, "MFA_INVALID", "The verification code is invalid or expired.")
		return
	}
	completion, err := s.auth.CompletePrivilegedLogin(input.ChallengeToken, input.Code)
	if err != nil {
		s.bestEffortAudit(audit.Input{ActorType: "anonymous", Action: "PRIVILEGED_MFA_COMPLETE", ResourceType: "session", Outcome: "denied", ReasonCode: auditReason(err), CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request)})
		if errors.Is(err, authn.ErrMFAInvalid) || errors.Is(err, authn.ErrMFAChallenge) {
			s.writeError(response, request, http.StatusUnauthorized, "MFA_INVALID", "The verification code is invalid or expired.")
			return
		}
		s.internalError(response, request, err)
		return
	}
	if _, auditErr := s.audit.Append(audit.Input{ActorType: "user", ActorID: completion.User.ID, Action: "AUTHENTICATION", ResourceType: "session", ResourceID: completion.Session.Audience, Outcome: "success", ReasonCode: "password_and_mfa_verified", CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request)}); auditErr != nil {
		s.auth.Logout(completion.Token)
		s.internalError(response, request, auditErr)
		return
	}
	s.setSessionCookie(response, completion.Token, completion.Session.ExpiresAt)
	writeJSON(response, http.StatusOK, privilegedMFACompletionResponse{User: completion.User, CSRFToken: completion.Session.CSRFToken, RecoveryCodes: completion.RecoveryCodes})
}

func (s *Server) createStepUpProof(response http.ResponseWriter, request *http.Request) {
	token, session, ok := s.requireAdminCSRF(response, request)
	if !ok {
		return
	}
	if !s.authenticationLimiter.Allow("privileged-step-up", clientAddress(request)) {
		response.Header().Set("Retry-After", "300")
		s.writeError(response, request, http.StatusTooManyRequests, "AUTHENTICATION_THROTTLED", "Too many authentication attempts. Try again later.")
		return
	}
	var input struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := readJSON(response, request, &input); err != nil {
		s.writeError(response, request, http.StatusUnauthorized, "STEP_UP_FAILED", "Password or verification code is incorrect.")
		return
	}
	proof, err := s.auth.CreateStepUpProof(token, session, input.Password, input.Code)
	if err != nil {
		s.bestEffortAudit(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "ADMIN_STEP_UP", ResourceType: "session", ResourceID: "privileged", Outcome: "denied", ReasonCode: auditReason(err), CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request)})
		if errors.Is(err, authn.ErrStepUpRequired) || errors.Is(err, authn.ErrInvalidCredentials) {
			s.writeError(response, request, http.StatusUnauthorized, "STEP_UP_FAILED", "Password or verification code is incorrect.")
			return
		}
		s.internalError(response, request, err)
		return
	}
	if _, err := s.audit.Append(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "ADMIN_STEP_UP", ResourceType: "session", ResourceID: "privileged", Outcome: "success", ReasonCode: "password_and_fresh_totp_verified", CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request), ToState: proof.ExpiresAt.Format(time.RFC3339)}); err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, proof)
}

func (s *Server) logout(response http.ResponseWriter, request *http.Request) {
	token, session, ok := s.requireSession(response, request)
	if !ok {
		return
	}
	if !validCSRF(request.Header.Get("X-CSRF-Token"), session.CSRFToken) {
		s.writeError(response, request, http.StatusForbidden, "CSRF_REJECTED", "The request could not be authorized.")
		return
	}
	if _, err := s.audit.Append(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "SESSION_LOGOUT", ResourceType: "session", ResourceID: session.Audience, Outcome: "success", ReasonCode: "user_requested", CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request)}); err != nil {
		s.internalError(response, request, err)
		return
	}
	s.auth.Logout(token)
	http.SetCookie(response, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	response.WriteHeader(http.StatusNoContent)
}

func (s *Server) getSession(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireSession(response, request)
	if !ok {
		return
	}
	writeJSON(response, http.StatusOK, sessionResponse{User: session.User, CSRFToken: session.CSRFToken})
}

func (s *Server) listUsers(response http.ResponseWriter, request *http.Request) {
	_, _, ok := s.requireAdmin(response, request)
	if !ok {
		return
	}
	limit := parsePositiveInt(request.URL.Query().Get("limit"), 50)
	offset := parsePositiveInt(request.URL.Query().Get("offset"), 0)
	page, err := s.auth.ListUsers(request.URL.Query().Get("search"), limit, offset)
	if err != nil {
		if errors.Is(err, authn.ErrInvalidInput) {
			s.writeError(response, request, http.StatusBadRequest, "INVALID_QUERY", "The user search could not be completed.")
			return
		}
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, page)
}

func (s *Server) invitePrivilegedAccount(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireAdminMutation(response, request)
	if !ok {
		return
	}
	var input struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := readJSON(response, request, &input); err != nil {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_INVITATION", "Provide a valid name, email address, and privileged role.")
		return
	}
	intent, err := s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "PRIVILEGED_ACCOUNT_INVITED", ResourceType: "identity", ResourceID: strings.ToLower(strings.TrimSpace(input.Email)), Outcome: "success", ReasonCode: "controlled_provisioning", CorrelationID: correlationID(request.Context()), ToState: input.Role})
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	durable, err := s.auth.InvitePrivilegedAccountAudited(session.User.ID, input.Name, input.Email, input.Role, intent)
	if err != nil {
		if errors.Is(err, authn.ErrInvalidInput) {
			s.writeError(response, request, http.StatusBadRequest, "INVALID_INVITATION", "Provide a valid name, email address, and privileged role.")
			return
		}
		if errors.Is(err, authn.ErrDuplicateUser) {
			s.writeError(response, request, http.StatusConflict, "IDENTITY_ALREADY_EXISTS", "An account or pending invitation already uses this email address.")
			return
		}
		s.internalError(response, request, err)
		return
	}
	if err := s.audit.DeliverMutationIntent(intent, durable); err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusAccepted, messageResponse{Message: "The privileged invitation was created and delivered without exposing recipient credentials."})
}

func (s *Server) activatePrivilegedAccount(response http.ResponseWriter, request *http.Request) {
	if !s.authenticationLimiter.Allow("privileged-activation", clientAddress(request)) {
		response.Header().Set("Retry-After", "300")
		s.writeError(response, request, http.StatusTooManyRequests, "AUTHENTICATION_THROTTLED", "Too many activation attempts. Try again later.")
		return
	}
	var input struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := readJSON(response, request, &input); err != nil {
		s.writeError(response, request, http.StatusBadRequest, "INVITATION_INVALID", "The invitation is invalid or expired.")
		return
	}
	intent, err := s.audit.NewMutationIntent(audit.Input{ActorType: "user", Action: "PRIVILEGED_ACCOUNT_ACTIVATED", ResourceType: "identity", Outcome: "success", ReasonCode: "invitation_accepted", CorrelationID: correlationID(request.Context())})
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	user, durable, err := s.auth.ActivatePrivilegedAccountAudited(input.Token, input.Password, intent)
	if err != nil {
		if errors.Is(err, authn.ErrInvitationToken) {
			s.writeError(response, request, http.StatusBadRequest, "INVITATION_INVALID", "The invitation is invalid or expired.")
			return
		}
		s.internalError(response, request, err)
		return
	}
	intent.ActorID, intent.ResourceID, intent.ToState = user.ID, user.ID, user.Role
	if !durable {
		// The memory repository cannot amend a previously committed outbox row;
		// use the fully resolved safe identity projection for development audit.
		resolved, intentErr := s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: user.ID, Action: "PRIVILEGED_ACCOUNT_ACTIVATED", ResourceType: "identity", ResourceID: user.ID, Outcome: "success", ReasonCode: "invitation_accepted", CorrelationID: correlationID(request.Context()), ToState: user.Role})
		if intentErr != nil {
			s.internalError(response, request, intentErr)
			return
		}
		intent = resolved
	}
	if err := s.audit.DeliverMutationIntent(intent, durable); err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, messageResponse{Message: "Privileged account activated. Sign in separately and enroll multi-factor authentication."})
}

func (s *Server) listAdminResources(response http.ResponseWriter, request *http.Request) {
	_, _, ok := s.requirePrivileged(response, request)
	if !ok {
		return
	}
	page, err := s.ingest.ListAdminResources(
		request.URL.Query().Get("search"),
		parsePositiveInt(request.URL.Query().Get("limit"), 50),
		parsePositiveInt(request.URL.Query().Get("offset"), 0),
	)
	if err != nil {
		if errors.Is(err, ingest.ErrInvalidQuery) {
			s.writeError(response, request, http.StatusBadRequest, "INVALID_QUERY", "The resource search could not be completed.")
			return
		}
		s.internalError(response, request, err)
		return
	}
	if s.protected != nil {
		capacity, capacityErr := s.protected.CapacitySummary()
		if capacityErr != nil {
			s.internalError(response, request, capacityErr)
			return
		}
		page.Summary.ProtectedCapacity = ingest.ProtectedCapacitySummary{
			TrackedObjects: capacity.TrackedObjects, TrackedCiphertextBytes: capacity.TrackedCiphertextBytes,
			OrphanedObjects: capacity.OrphanedObjects, OrphanedBytes: capacity.OrphanedBytes,
			MissingObjects: capacity.MissingObjects, VolumeTotalBytes: capacity.VolumeTotalBytes,
			VolumeAvailableBytes: capacity.VolumeAvailableBytes, VolumeUsedPercent: capacity.VolumeUsedPercent,
			Alerts: make([]ingest.ProtectedCapacityAlert, 0, len(capacity.Alerts)),
		}
		for _, alert := range capacity.Alerts {
			page.Summary.ProtectedCapacity.Alerts = append(page.Summary.ProtectedCapacity.Alerts, ingest.ProtectedCapacityAlert{ID: alert.ID, Severity: alert.Severity, Title: alert.Title, Detail: alert.Detail, Count: alert.Count})
		}
	}
	writeJSON(response, http.StatusOK, page)
}

func (s *Server) listOrphans(response http.ResponseWriter, request *http.Request) {
	if _, _, ok := s.requirePrivileged(response, request); !ok {
		return
	}
	candidates, err := s.orphanCandidates()
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, orphanPreview{GeneratedAt: time.Now().UTC(), MinimumAgeSeconds: int64(orphanReconciliationMinimumAge.Seconds()), Candidates: candidates})
}

func (s *Server) reconcileOrphans(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireAdminMutation(response, request)
	if !ok {
		return
	}
	var input reconcileOrphansRequest
	if err := readJSON(response, request, &input); err != nil {
		return
	}
	if len(input.Tokens) < 1 || len(input.Tokens) > 25 {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_RECONCILIATION_SELECTION", "Select between 1 and 25 eligible orphan objects.")
		return
	}
	if s.protected == nil {
		s.writeError(response, request, http.StatusServiceUnavailable, "RECONCILIATION_UNAVAILABLE", "Durable orphan reconciliation is unavailable.")
		return
	}
	candidates, err := s.orphanCandidates()
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	available := make(map[string]orphan.Candidate, len(candidates))
	for _, candidate := range candidates {
		available[candidate.Token] = candidate
	}
	seen := make(map[string]struct{}, len(input.Tokens))
	result := reconcileOrphansResult{Requested: len(input.Tokens)}
	for _, token := range input.Tokens {
		candidate, exists := available[token]
		if _, duplicate := seen[token]; duplicate || !exists || !candidate.Eligible {
			result.Failed++
			continue
		}
		seen[token] = struct{}{}
		requestCorrelationID := correlationID(request.Context())
		authorizationIntent, intentErr := s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "ORPHAN_DELETION_AUTHORIZED", ResourceType: "storage_orphan", ResourceID: token, Outcome: "success", ReasonCode: "administrator_reconciliation", CorrelationID: requestCorrelationID, ToState: candidate.Zone})
		if intentErr != nil {
			s.internalError(response, request, intentErr)
			return
		}
		operation, created, authorizeErr := s.protected.AuthorizeOrphanReconciliation(candidate, session.User.ID, requestCorrelationID, authorizationIntent)
		if authorizeErr != nil {
			s.internalError(response, request, authorizeErr)
			return
		}
		if created {
			if err := s.audit.DeliverMutationIntent(authorizationIntent, s.protected.Durable()); err != nil {
				s.internalError(response, request, err)
				return
			}
		} else if operation.Status == protectedstore.ReconciliationCompleted {
			result.Completed++
			continue
		} else if operation.Status == protectedstore.ReconciliationFailed {
			result.Failed++
			continue
		}

		var outcome orphan.ResumeOutcome
		if operation.Zone == "quarantine" {
			outcome, err = s.ingest.ResumeOrphanReconciliation(operation)
		} else {
			outcome, err = s.protected.ResumeProtectedOrphan(operation)
		}
		// Transient I/O or repository errors leave the operation authorized so
		// the recovery worker can retry it without another admin approval.
		if err != nil {
			result.Failed++
			continue
		}
		auditOutcome, toState := "success", "deleted"
		if outcome.Status == protectedstore.ReconciliationFailed {
			auditOutcome, toState = "failed", "retained"
		}
		completionIntent, intentErr := s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "ORPHAN_DELETION_COMPLETED", ResourceType: "storage_orphan", ResourceID: token, Outcome: auditOutcome, ReasonCode: outcome.ReasonCode, CorrelationID: operation.CorrelationID, FromState: operation.Zone, ToState: toState})
		if intentErr != nil {
			s.internalError(response, request, intentErr)
			return
		}
		updated, completeErr := s.protected.CompleteOrphanReconciliation(operation.OperationID, outcome.Status, outcome.ReasonCode, completionIntent)
		if completeErr != nil {
			s.internalError(response, request, completeErr)
			return
		}
		if updated {
			if err := s.audit.DeliverMutationIntent(completionIntent, s.protected.Durable()); err != nil {
				s.internalError(response, request, err)
				return
			}
		}
		if outcome.Status == protectedstore.ReconciliationFailed {
			result.Failed++
		} else {
			result.Completed++
		}
	}
	writeJSON(response, http.StatusOK, result)
}

func (s *Server) orphanCandidates() ([]orphan.Candidate, error) {
	candidates, err := s.ingest.OrphanCandidates(orphanReconciliationMinimumAge)
	if err != nil {
		return nil, err
	}
	if s.protected != nil {
		protectedCandidates, protectedErr := s.protected.OrphanCandidates(orphanReconciliationMinimumAge)
		if protectedErr != nil {
			return nil, protectedErr
		}
		candidates = append(candidates, protectedCandidates...)
	}
	if candidates == nil {
		candidates = []orphan.Candidate{}
	}
	return candidates, nil
}

func (s *Server) updateOwnerQuota(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireAdminMutation(response, request)
	if !ok {
		return
	}
	ownerID := request.PathValue("ownerId")
	role, err := s.auth.UserRole(ownerID)
	if err != nil {
		if errors.Is(err, authn.ErrUserNotFound) {
			s.writeError(response, request, http.StatusNotFound, "USER_NOT_FOUND", "The standard-user account could not be found.")
			return
		}
		s.internalError(response, request, err)
		return
	}
	if role != "user" {
		s.writeError(response, request, http.StatusConflict, "STANDARD_USER_REQUIRED", "Quota overrides apply only to standard-user accounts.")
		return
	}
	var input struct {
		QuotaBytes int64 `json:"quotaBytes"`
	}
	if err := readJSON(response, request, &input); err != nil {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_QUOTA", "Choose a quota between 1 MB and 10 TB.")
		return
	}
	intent, err := s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "OWNER_QUOTA_UPDATED", ResourceType: "user", ResourceID: ownerID, Outcome: "success", ReasonCode: "administrator_policy", CorrelationID: correlationID(request.Context()), ToState: fmt.Sprintf("%d", input.QuotaBytes)})
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	durable, err := s.ingest.SetOwnerQuotaAudited(ownerID, input.QuotaBytes, intent)
	if err != nil {
		if errors.Is(err, ingest.ErrInvalidQuery) {
			s.writeError(response, request, http.StatusBadRequest, "INVALID_QUOTA", "Choose a quota between 1 MB and 10 TB.")
			return
		}
		s.internalError(response, request, err)
		return
	}
	if err := s.audit.DeliverMutationIntent(intent, durable); err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, messageResponse{Message: "The account quota was updated."})
}

func (s *Server) resetOwnerQuota(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireAdminMutation(response, request)
	if !ok {
		return
	}
	ownerID := request.PathValue("ownerId")
	role, err := s.auth.UserRole(ownerID)
	if err != nil {
		if errors.Is(err, authn.ErrUserNotFound) {
			s.writeError(response, request, http.StatusNotFound, "USER_NOT_FOUND", "The standard-user account could not be found.")
			return
		}
		s.internalError(response, request, err)
		return
	}
	if role != "user" {
		s.writeError(response, request, http.StatusConflict, "STANDARD_USER_REQUIRED", "Quota overrides apply only to standard-user accounts.")
		return
	}
	intent, err := s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "OWNER_QUOTA_UPDATED", ResourceType: "user", ResourceID: ownerID, Outcome: "success", ReasonCode: "organization_default_restored", CorrelationID: correlationID(request.Context()), ToState: "default"})
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	durable, err := s.ingest.ResetOwnerQuotaAudited(ownerID, intent)
	if err != nil {
		if errors.Is(err, ingest.ErrInvalidQuery) {
			s.writeError(response, request, http.StatusBadRequest, "INVALID_OWNER", "Choose a valid standard-user account.")
			return
		}
		s.internalError(response, request, err)
		return
	}
	if err := s.audit.DeliverMutationIntent(intent, durable); err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, messageResponse{Message: "The organization default quota was restored."})
}

func (s *Server) updateUserStatus(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireAdminMutation(response, request)
	if !ok {
		return
	}
	var input struct {
		Status string `json:"status"`
	}
	if err := readJSON(response, request, &input); err != nil {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_REQUEST", "Choose a supported account status.")
		return
	}
	userID := request.PathValue("userId")
	intent, err := s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "ACCOUNT_STATUS_UPDATED", ResourceType: "user", ResourceID: userID, Outcome: "success", ReasonCode: "administrator_action", CorrelationID: correlationID(request.Context()), ToState: input.Status})
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	durable, err := s.auth.UpdateUserStatusAudited(session.User.ID, userID, input.Status, intent)
	if err != nil {
		if errors.Is(err, authn.ErrSelfManagement) {
			s.bestEffortAudit(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "ACCOUNT_STATUS_UPDATED", ResourceType: "user", ResourceID: userID, Outcome: "denied", ReasonCode: "self_management_prohibited", CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request), ToState: input.Status})
		}
		s.writeAdminIdentityError(response, request, err)
		return
	}
	if err := s.audit.DeliverMutationIntent(intent, durable); err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, messageResponse{Message: "Account status updated and existing sessions revoked."})
}

func (s *Server) revokeUserSessions(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireAdminMutation(response, request)
	if !ok {
		return
	}
	userID := request.PathValue("userId")
	intent, err := s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "USER_SESSIONS_REVOKED", ResourceType: "user", ResourceID: userID, Outcome: "success", ReasonCode: "administrator_action", CorrelationID: correlationID(request.Context())})
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	durable, err := s.auth.RevokeUserSessionsAudited(session.User.ID, userID, intent)
	if err != nil {
		if errors.Is(err, authn.ErrSelfManagement) {
			s.bestEffortAudit(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "USER_SESSIONS_REVOKED", ResourceType: "user", ResourceID: userID, Outcome: "denied", ReasonCode: "self_management_prohibited", CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request), ToState: "unchanged"})
		}
		s.writeAdminIdentityError(response, request, err)
		return
	}
	if err := s.audit.DeliverMutationIntent(intent, durable); err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, messageResponse{Message: "All sessions for this account were revoked."})
}

func (s *Server) requireAdminMutation(response http.ResponseWriter, request *http.Request) (string, authn.Session, bool) {
	token, session, ok := s.requireAdminCSRF(response, request)
	if !ok {
		return "", authn.Session{}, false
	}
	if s.auth.AdminStepUpRequired() && !s.auth.ValidateStepUpProof(token, session, request.Header.Get("X-Step-Up-Token")) {
		s.writeError(response, request, http.StatusPreconditionRequired, "STEP_UP_REQUIRED", "Confirm your password and a fresh authenticator code to continue.")
		return "", authn.Session{}, false
	}
	return token, session, true
}

func (s *Server) requireAdminCSRF(response http.ResponseWriter, request *http.Request) (string, authn.Session, bool) {
	token, session, ok := s.requireAdmin(response, request)
	if !ok {
		return "", authn.Session{}, false
	}
	if !validCSRF(request.Header.Get("X-CSRF-Token"), session.CSRFToken) {
		s.writeError(response, request, http.StatusForbidden, "CSRF_REJECTED", "The request could not be authorized.")
		return "", authn.Session{}, false
	}
	return token, session, true
}

func (s *Server) writeAdminIdentityError(response http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, authn.ErrInvalidInput):
		s.writeError(response, request, http.StatusBadRequest, "INVALID_ACCOUNT_STATUS", "Choose a supported account status.")
	case errors.Is(err, authn.ErrSelfManagement):
		s.writeError(response, request, http.StatusConflict, "SELF_MANAGEMENT_PROHIBITED", "Use another administrator for changes to your own privileged account.")
	case errors.Is(err, authn.ErrUserNotFound):
		s.writeError(response, request, http.StatusNotFound, "USER_NOT_FOUND", "The account could not be found.")
	default:
		s.internalError(response, request, err)
	}
}

func (s *Server) createUpload(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireStandardUser(response, request)
	if !ok {
		return
	}
	if !validCSRF(request.Header.Get("X-CSRF-Token"), session.CSRFToken) {
		s.writeError(response, request, http.StatusForbidden, "CSRF_REJECTED", "The request could not be authorized.")
		return
	}
	idempotencyKey := request.Header.Get("Idempotency-Key")
	expectedSize, sizeErr := strconv.ParseInt(strings.TrimSpace(request.Header.Get("X-File-Size")), 10, 64)
	if sizeErr != nil || expectedSize <= 0 {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_FILE_SIZE", "A valid X-File-Size header is required for capacity reservation.")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, s.maxRequestBytes)
	multipartReader, err := request.MultipartReader()
	if err != nil {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_MULTIPART", "Choose one file and try again.")
		return
	}

	part, err := nextFilePart(multipartReader)
	if err != nil {
		s.writeError(response, request, http.StatusBadRequest, "FILE_REQUIRED", "Choose one file and try again.")
		return
	}
	defer part.Close()
	upload, _, err := s.ingest.CreateSized(request.Context(), session.User.ID, idempotencyKey, part.FileName(), part.Header.Get("Content-Type"), part, expectedSize)
	if err != nil {
		switch {
		case errors.Is(err, ingest.ErrTooLarge):
			s.writeError(response, request, http.StatusRequestEntityTooLarge, "UPLOAD_TOO_LARGE", "This file exceeds the configured upload limit.")
		case errors.Is(err, ingest.ErrQuotaExceeded):
			s.writeError(response, request, http.StatusConflict, "STORAGE_QUOTA_EXCEEDED", "This upload would exceed the account storage quota.")
		case errors.Is(err, ingest.ErrCapacityExceeded):
			s.writeError(response, request, http.StatusInsufficientStorage, "STORAGE_CAPACITY_RESERVED", "Protected storage cannot safely reserve capacity for this upload.")
		case errors.Is(err, ingest.ErrInvalidKey):
			s.writeError(response, request, http.StatusBadRequest, "INVALID_IDEMPOTENCY_KEY", "The upload request could not be finalized.")
		case errors.Is(err, ingest.ErrInvalidFile):
			s.writeError(response, request, http.StatusBadRequest, "INVALID_FILE", "Choose a non-empty file and try again.")
		default:
			s.internalError(response, request, err)
		}
		return
	}
	writeJSON(response, http.StatusAccepted, upload)
}

func (s *Server) bestEffortAudit(input audit.Input) {
	if _, err := s.audit.Append(input); err != nil {
		s.logger.Error("audit append failed", "error", err)
	}
}

func auditReason(err error) string {
	switch {
	case errors.Is(err, authn.ErrEmailNotVerified):
		return "email_not_verified"
	case errors.Is(err, authn.ErrInvalidCredentials):
		return "invalid_credentials"
	case errors.Is(err, authn.ErrMFAInvalid):
		return "mfa_code_invalid"
	case errors.Is(err, authn.ErrMFAChallenge):
		return "mfa_challenge_invalid_or_expired"
	default:
		return "authentication_error"
	}
}

func (s *Server) getUpload(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireStandardUser(response, request)
	if !ok {
		return
	}
	upload, err := s.ingest.Get(session.User.ID, request.PathValue("uploadId"))
	if err != nil {
		s.writeError(response, request, http.StatusNotFound, "UPLOAD_NOT_FOUND", "The upload could not be found.")
		return
	}
	writeJSON(response, http.StatusOK, upload)
}

func (s *Server) listUserFiles(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireStandardUser(response, request)
	if !ok {
		return
	}
	if s.protected == nil {
		s.writeError(response, request, http.StatusServiceUnavailable, "FILE_CATALOG_UNAVAILABLE", "The protected file catalog is unavailable.")
		return
	}
	files, err := s.protected.ListFiles(session.User.ID)
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, userFilePage{Files: files, Total: len(files)})
}

func (s *Server) listTrash(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireStandardUser(response, request)
	if !ok {
		return
	}
	files, err := s.protected.ListTrash(session.User.ID)
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"files": files, "total": len(files)})
}

func (s *Server) moveFileToTrash(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireStandardUserMutation(response, request)
	if !ok {
		return
	}
	fileID := request.PathValue("fileId")
	intent, err := s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_MOVED_TO_TRASH", ResourceType: "file", ResourceID: fileID, Outcome: "success", ReasonCode: "grace_period_started", CorrelationID: correlationID(request.Context()), ToState: "trashed"})
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	file, durable, err := s.protected.MoveToTrashAudited(session.User.ID, fileID, intent)
	if err != nil {
		// A policy-blocked deletion attempt is security-relevant evidence even
		// though the protected repository correctly leaves the file unchanged.
		// Record only the opaque file identifier and normalized reason code.
		s.bestEffortAudit(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_MOVED_TO_TRASH", ResourceType: "file", ResourceID: fileID, Outcome: "denied", ReasonCode: lifecycleDenialReason(err), CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request), ToState: "active"})
		s.writeLifecycleError(response, request, err)
		return
	}
	if err := s.audit.DeliverMutationIntent(intent, durable); err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, file)
}

func (s *Server) restoreFileFromTrash(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireStandardUserMutation(response, request)
	if !ok {
		return
	}
	fileID := request.PathValue("fileId")
	intent, err := s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_RESTORED_FROM_TRASH", ResourceType: "file", ResourceID: fileID, Outcome: "success", ReasonCode: "owner_requested", CorrelationID: correlationID(request.Context()), ToState: "active"})
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	file, durable, err := s.protected.RestoreFromTrashAudited(session.User.ID, fileID, intent)
	if err != nil {
		s.writeLifecycleError(response, request, err)
		return
	}
	if err := s.audit.DeliverMutationIntent(intent, durable); err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, file)
}

func (s *Server) purgeFile(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireStandardUserMutation(response, request)
	if !ok {
		return
	}
	fileID := request.PathValue("fileId")
	key := request.Header.Get("Idempotency-Key")
	if len(strings.TrimSpace(key)) < 8 || len(key) > 128 {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_IDEMPOTENCY_KEY", "A valid Idempotency-Key header is required.")
		return
	}
	intent, err := s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_CRYPTOGRAPHICALLY_DELETED", ResourceType: "file", ResourceID: fileID, Outcome: "success", ReasonCode: "wrapped_keys_destroyed", CorrelationID: correlationID(request.Context()), ToState: "purged"})
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	_, auditEventID, err := protectedstore.PurgeOperationIDs(session.User.ID, fileID, key)
	if err != nil {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_IDEMPOTENCY_KEY", "A valid Idempotency-Key header is required.")
		return
	}
	intent.EventID = auditEventID
	result, durable, err := s.protected.PurgeAudited(session.User.ID, fileID, key, intent)
	if err != nil {
		// Permanent-deletion denials remain visible in the tamper-evident audit
		// chain without exposing file content, names, or storage locations.
		s.bestEffortAudit(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_CRYPTOGRAPHICALLY_DELETED", ResourceType: "file", ResourceID: fileID, Outcome: "denied", ReasonCode: lifecycleDenialReason(err), CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request), ToState: "retained"})
		s.writeLifecycleError(response, request, err)
		return
	}
	if err := s.audit.DeliverMutationIntent(intent, durable); err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (s *Server) requireStandardUserMutation(response http.ResponseWriter, request *http.Request) (string, authn.Session, bool) {
	token, session, ok := s.requireStandardUser(response, request)
	if !ok {
		return "", authn.Session{}, false
	}
	if !validCSRF(request.Header.Get("X-CSRF-Token"), session.CSRFToken) {
		s.writeError(response, request, http.StatusForbidden, "CSRF_REJECTED", "The request could not be authorized.")
		return "", authn.Session{}, false
	}
	return token, session, true
}

func (s *Server) writeLifecycleError(response http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, protectedstore.ErrRetentionActive):
		s.writeError(response, request, http.StatusConflict, "RETENTION_ACTIVE", "The file is protected by an active retention period.")
	case errors.Is(err, protectedstore.ErrLegalHold):
		s.writeError(response, request, http.StatusConflict, "LEGAL_HOLD_ACTIVE", "The file is protected by a legal hold.")
	case errors.Is(err, protectedstore.ErrPurgeTooEarly):
		s.writeError(response, request, http.StatusConflict, "DELETION_GRACE_ACTIVE", "Permanent deletion is unavailable until the recovery period ends.")
	case errors.Is(err, protectedstore.ErrNotInTrash):
		s.writeError(response, request, http.StatusConflict, "FILE_NOT_IN_TRASH", "The file is not available in Trash.")
	case errors.Is(err, protectedstore.ErrNotFound):
		s.writeError(response, request, http.StatusNotFound, "FILE_NOT_FOUND", "The file could not be found.")
	default:
		s.internalError(response, request, err)
	}
}

func lifecycleDenialReason(err error) string {
	switch {
	case errors.Is(err, protectedstore.ErrRetentionActive):
		return "retention_active"
	case errors.Is(err, protectedstore.ErrLegalHold):
		return "legal_hold_active"
	case errors.Is(err, protectedstore.ErrPurgeTooEarly):
		return "deletion_grace_active"
	case errors.Is(err, protectedstore.ErrNotInTrash):
		return "file_not_in_trash"
	case errors.Is(err, protectedstore.ErrNotFound):
		return "file_not_found"
	default:
		return "lifecycle_policy_denied"
	}
}

func (s *Server) listSharedFiles(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireStandardUser(response, request)
	if !ok {
		return
	}
	if s.protected == nil {
		s.writeError(response, request, http.StatusServiceUnavailable, "ACCESS_GRANTS_UNAVAILABLE", "Shared files are unavailable.")
		return
	}
	files, err := s.protected.ListSharedFiles(session.User.ID)
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"files": files, "total": len(files)})
}

func (s *Server) getUserFile(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireStandardUser(response, request)
	if !ok {
		return
	}
	if s.protected == nil {
		s.writeError(response, request, http.StatusServiceUnavailable, "FILE_CATALOG_UNAVAILABLE", "The protected file catalog is unavailable.")
		return
	}
	details, err := s.protected.AuthorizedDetails(session.User.ID, request.PathValue("fileId"))
	if err != nil {
		s.bestEffortAudit(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_METADATA_READ", ResourceType: "file", ResourceID: request.PathValue("fileId"), Outcome: "denied", ReasonCode: "not_authorized_or_missing", CorrelationID: correlationID(request.Context())})
		s.writeError(response, request, http.StatusNotFound, "FILE_NOT_FOUND", "The file could not be found.")
		return
	}
	reason := "grant_authorized"
	if details.File.OwnerID == session.User.ID {
		reason = "owner_authorized"
	}
	s.bestEffortAudit(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_METADATA_READ", ResourceType: "file", ResourceID: details.File.FileID, Outcome: "success", ReasonCode: reason, CorrelationID: correlationID(request.Context())})
	writeJSON(response, http.StatusOK, details)
}

func (s *Server) listFileGrants(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireStandardUser(response, request)
	if !ok {
		return
	}
	if s.protected == nil {
		s.writeError(response, request, http.StatusServiceUnavailable, "ACCESS_GRANTS_UNAVAILABLE", "File access grants are unavailable.")
		return
	}
	grants, err := s.protected.ListGrants(session.User.ID, request.PathValue("fileId"))
	if err != nil {
		s.writeError(response, request, http.StatusNotFound, "FILE_NOT_FOUND", "The file could not be found.")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"grants": grants, "total": len(grants)})
}

func (s *Server) createFileGrant(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireStandardUser(response, request)
	if !ok {
		return
	}
	if !validCSRF(request.Header.Get("X-CSRF-Token"), session.CSRFToken) {
		s.writeError(response, request, http.StatusForbidden, "CSRF_REJECTED", "The request could not be authorized.")
		return
	}
	var input createGrantRequest
	if err := readJSON(response, request, &input); err != nil || (input.Permission != protectedstore.PermissionRead && input.Permission != protectedstore.PermissionDownload) {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_ACCESS_GRANT", "Choose a verified user and supported permission.")
		return
	}
	recipient, err := s.auth.GrantRecipient(input.RecipientEmail)
	if err != nil || recipient.ID == session.User.ID {
		s.writeError(response, request, http.StatusNotFound, "RECIPIENT_NOT_AVAILABLE", "A verified standard-user account could not be found for that address.")
		return
	}
	fileID := request.PathValue("fileId")
	intent, err := s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_GRANT_CREATED", ResourceType: "file", ResourceID: fileID, Outcome: "success", ReasonCode: input.Permission, CorrelationID: correlationID(request.Context()), ToState: recipient.ID})
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	grant, durable, err := s.protected.CreateGrantAudited(session.User.ID, fileID, protectedstore.Recipient{ID: recipient.ID, Name: recipient.Name, Email: recipient.Email}, input.Permission, input.ExpiresAt, intent)
	if err != nil {
		if errors.Is(err, protectedstore.ErrNotFound) {
			s.writeError(response, request, http.StatusNotFound, "FILE_NOT_FOUND", "The file could not be found.")
			return
		}
		s.writeError(response, request, http.StatusBadRequest, "INVALID_ACCESS_GRANT", "Choose a future expiry and supported permission.")
		return
	}
	if err := s.audit.DeliverMutationIntent(intent, durable); err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusCreated, grant)
}

func (s *Server) revokeFileGrant(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireStandardUser(response, request)
	if !ok {
		return
	}
	if !validCSRF(request.Header.Get("X-CSRF-Token"), session.CSRFToken) {
		s.writeError(response, request, http.StatusForbidden, "CSRF_REJECTED", "The request could not be authorized.")
		return
	}
	if s.protected == nil {
		s.writeError(response, request, http.StatusServiceUnavailable, "ACCESS_GRANTS_UNAVAILABLE", "File access grants are unavailable.")
		return
	}
	fileID, grantID := request.PathValue("fileId"), request.PathValue("grantId")
	intent, err := s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_GRANT_REVOKED", ResourceType: "file", ResourceID: fileID, Outcome: "success", ReasonCode: "owner_revoked", CorrelationID: correlationID(request.Context()), ToState: grantID})
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	durable, err := s.protected.RevokeGrantAudited(session.User.ID, fileID, grantID, intent)
	if err != nil {
		s.writeError(response, request, http.StatusNotFound, "ACCESS_GRANT_NOT_FOUND", "The active access grant could not be found.")
		return
	}
	if err := s.audit.DeliverMutationIntent(intent, durable); err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, messageResponse{Message: "File access was revoked."})
}

func (s *Server) restoreUserFileVersion(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireStandardUser(response, request)
	if !ok {
		return
	}
	if !validCSRF(request.Header.Get("X-CSRF-Token"), session.CSRFToken) {
		s.writeError(response, request, http.StatusForbidden, "CSRF_REJECTED", "The request could not be authorized.")
		return
	}
	fileID, versionID := request.PathValue("fileId"), request.PathValue("versionId")
	if s.protected == nil {
		s.writeError(response, request, http.StatusServiceUnavailable, "FILE_CATALOG_UNAVAILABLE", "The protected file catalog is unavailable.")
		return
	}
	idempotencyKey := request.Header.Get("Idempotency-Key")
	if len(strings.TrimSpace(idempotencyKey)) < 8 || len(idempotencyKey) > 128 {
		s.writeError(response, request, http.StatusBadRequest, "INVALID_IDEMPOTENCY_KEY", "A valid Idempotency-Key header is required.")
		return
	}
	intent, err := s.audit.NewMutationIntent(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_VERSION_RESTORE_COMPLETED", ResourceType: "file", ResourceID: fileID, Outcome: "success", ReasonCode: "new_immutable_version_created", CorrelationID: correlationID(request.Context()), FromState: versionID})
	if err != nil {
		s.internalError(response, request, err)
		return
	}
	version, durable, err := s.protected.RestoreAudited(request.Context(), session.User.ID, fileID, versionID, idempotencyKey, intent)
	if err != nil {
		s.bestEffortAudit(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_VERSION_RESTORE_COMPLETED", ResourceType: "file", ResourceID: fileID, Outcome: "failed", ReasonCode: "restore_unavailable", CorrelationID: correlationID(request.Context())})
		if errors.Is(err, protectedstore.ErrNotFound) {
			s.writeError(response, request, http.StatusNotFound, "FILE_VERSION_NOT_FOUND", "The file version could not be found.")
			return
		}
		s.internalError(response, request, err)
		return
	}
	if err := s.audit.DeliverMutationIntent(intent, durable); err != nil {
		s.internalError(response, request, err)
		return
	}
	writeJSON(response, http.StatusCreated, version)
}

func (s *Server) downloadUserFile(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireStandardUser(response, request)
	if !ok {
		return
	}
	fileID := request.PathValue("fileId")
	if s.protected == nil {
		s.writeError(response, request, http.StatusNotFound, "FILE_NOT_AVAILABLE", "The protected file could not be found.")
		return
	}
	details, err := s.protected.AuthorizedDetails(session.User.ID, fileID)
	if err != nil {
		s.bestEffortAudit(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_DOWNLOAD", ResourceType: "file", ResourceID: fileID, Outcome: "denied", ReasonCode: "not_authorized_or_missing", CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request)})
		s.writeError(response, request, http.StatusNotFound, "FILE_NOT_AVAILABLE", "The protected file could not be found.")
		return
	}
	file, err := s.protected.OpenCurrentAuthorized(session.User.ID, fileID)
	if err != nil {
		if errors.Is(err, protectedstore.ErrNotFound) {
			s.bestEffortAudit(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_DOWNLOAD", ResourceType: "file", ResourceID: fileID, Outcome: "denied", ReasonCode: "download_permission_required", CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request)})
			s.writeError(response, request, http.StatusNotFound, "FILE_NOT_AVAILABLE", "The protected file could not be found.")
			return
		}
		s.writeError(response, request, http.StatusServiceUnavailable, "PROTECTED_FILE_UNAVAILABLE", "The protected file could not be verified.")
		return
	}
	defer clear(file.Bytes)
	reason := "grant_authorized_current_version"
	if details.File.OwnerID == session.User.ID {
		reason = "owner_authorized_current_version"
	}
	if _, err := s.audit.Append(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_DOWNLOAD", ResourceType: "file", ResourceID: fileID, Outcome: "success", ReasonCode: reason, CorrelationID: correlationID(request.Context()), NetworkAddress: clientAddress(request)}); err != nil {
		s.internalError(response, request, err)
		return
	}
	mediaType := file.Metadata.MediaType
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	disposition := mime.FormatMediaType("attachment", map[string]string{"filename": details.File.Name})
	response.Header().Set("Content-Type", mediaType)
	response.Header().Set("Content-Disposition", disposition)
	response.Header().Set("Content-Length", strconv.Itoa(len(file.Bytes)))
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(file.Bytes)
}

func (s *Server) downloadUpload(response http.ResponseWriter, request *http.Request) {
	_, session, ok := s.requireStandardUser(response, request)
	if !ok {
		return
	}
	uploadID := request.PathValue("uploadId")
	upload, err := s.ingest.Get(session.User.ID, uploadID)
	if err != nil || upload.Status != ingest.StatusStored || s.protected == nil {
		s.bestEffortAudit(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_DOWNLOAD", ResourceType: "upload", ResourceID: uploadID, Outcome: "denied", ReasonCode: "resource_unavailable", CorrelationID: correlationID(request.Context())})
		s.writeError(response, request, http.StatusNotFound, "FILE_NOT_AVAILABLE", "The protected file could not be found.")
		return
	}
	file, err := s.protected.Open(session.User.ID, uploadID)
	if err != nil {
		s.bestEffortAudit(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_DOWNLOAD", ResourceType: "upload", ResourceID: uploadID, Outcome: "failed", ReasonCode: "integrity_or_storage_failure", CorrelationID: correlationID(request.Context())})
		s.writeError(response, request, http.StatusServiceUnavailable, "PROTECTED_FILE_UNAVAILABLE", "The protected file could not be verified.")
		return
	}
	defer clear(file.Bytes)
	// A required audit append happens before any plaintext headers or bytes are
	// released. Audit unavailability therefore fails this sensitive read closed.
	if _, err := s.audit.Append(audit.Input{ActorType: "user", ActorID: session.User.ID, Action: "FILE_DOWNLOAD", ResourceType: "upload", ResourceID: uploadID, Outcome: "success", ReasonCode: "owner_authorized", CorrelationID: correlationID(request.Context())}); err != nil {
		s.internalError(response, request, err)
		return
	}
	mediaType := file.Metadata.MediaType
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	disposition := mime.FormatMediaType("attachment", map[string]string{"filename": upload.Name})
	if disposition == "" {
		disposition = "attachment"
	}
	response.Header().Set("Content-Type", mediaType)
	response.Header().Set("Content-Disposition", disposition)
	response.Header().Set("Content-Length", strconv.Itoa(len(file.Bytes)))
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(file.Bytes)
}

func (s *Server) requireSession(response http.ResponseWriter, request *http.Request) (string, authn.Session, bool) {
	cookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		s.writeError(response, request, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Sign in to continue.")
		return "", authn.Session{}, false
	}
	session, err := s.auth.Authenticate(cookie.Value)
	if err != nil {
		s.writeError(response, request, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Sign in to continue.")
		return "", authn.Session{}, false
	}
	return cookie.Value, session, true
}

func (s *Server) requireAdmin(response http.ResponseWriter, request *http.Request) (string, authn.Session, bool) {
	token, session, ok := s.requireSession(response, request)
	if !ok {
		return "", authn.Session{}, false
	}
	if session.Audience != authn.SessionAudiencePrivileged || session.User.Role != "admin" {
		s.writeError(response, request, http.StatusForbidden, "ADMINISTRATOR_REQUIRED", "Administrator access is required.")
		return "", authn.Session{}, false
	}
	return token, session, true
}

func (s *Server) requirePrivileged(response http.ResponseWriter, request *http.Request) (string, authn.Session, bool) {
	token, session, ok := s.requireSession(response, request)
	if !ok {
		return "", authn.Session{}, false
	}
	if session.Audience != authn.SessionAudiencePrivileged || (session.User.Role != "admin" && session.User.Role != "auditor") {
		s.writeError(response, request, http.StatusForbidden, "PRIVILEGED_ACCESS_REQUIRED", "Privileged access is required.")
		return "", authn.Session{}, false
	}
	return token, session, true
}

func (s *Server) requireStandardUser(response http.ResponseWriter, request *http.Request) (string, authn.Session, bool) {
	token, session, ok := s.requireSession(response, request)
	if !ok {
		return "", authn.Session{}, false
	}
	if session.Audience != authn.SessionAudienceUser || session.User.Role != "user" {
		s.writeError(response, request, http.StatusForbidden, "STANDARD_USER_REQUIRED", "A standard-user account is required for file operations.")
		return "", authn.Session{}, false
	}
	return token, session, true
}

func (s *Server) setSessionCookie(response http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(response, &http.Cookie{
		Name: sessionCookieName, Value: token, Path: "/", Expires: expiresAt,
		HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) originCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead && request.Method != http.MethodOptions {
			origin := request.Header.Get("Origin")
			if origin != "" {
				if _, allowed := s.allowedOrigins[origin]; !allowed {
					s.writeError(response, request, http.StatusForbidden, "ORIGIN_REJECTED", "The request origin is not allowed.")
					return
				}
			}
		}
		next.ServeHTTP(response, request)
	})
}

func (s *Server) correlation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		correlationID := request.Header.Get("X-Correlation-ID")
		if !validCorrelationID(correlationID) {
			correlationID = randomCorrelationID()
		}
		response.Header().Set("X-Correlation-ID", correlationID)
		ctx := context.WithValue(request.Context(), correlationKey, correlationID)
		next.ServeHTTP(response, request.WithContext(ctx))
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("X-Frame-Options", "DENY")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		response.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if request.TLS != nil {
			response.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(response, request)
	})
}

func (s *Server) writeError(response http.ResponseWriter, request *http.Request, status int, code, message string) {
	writeJSONStatus(response, status, errorResponse{Code: code, Message: message, CorrelationID: correlationID(request.Context())})
}

func (s *Server) internalError(response http.ResponseWriter, request *http.Request, err error) {
	s.logger.Error("request failed", "correlation_id", correlationID(request.Context()), "error", err)
	s.writeError(response, request, http.StatusInternalServerError, "INTERNAL_ERROR", "The request could not be completed.")
}

func readJSON(response http.ResponseWriter, request *http.Request, destination any) error {
	request.Body = http.MaxBytesReader(response, request.Body, 1<<20)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request must contain one JSON object")
	}
	return nil
}

func nextFilePart(reader *multipart.Reader) (*multipart.Part, error) {
	for {
		part, err := reader.NextPart()
		if err != nil {
			return nil, err
		}
		if part.FormName() == "file" && part.FileName() != "" {
			return part, nil
		}
		_ = part.Close()
	}
}

func validCSRF(provided, expected string) bool {
	if provided == "" || len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func validCorrelationID(value string) bool {
	return len(value) >= 8 && len(value) <= 80 && !strings.ContainsAny(value, "\r\n\x00")
}

func randomCorrelationID() string {
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err != nil {
		return "corr_unavailable"
	}
	return "corr_" + base64.RawURLEncoding.EncodeToString(buffer)
}

func correlationID(ctx context.Context) string {
	value, _ := ctx.Value(correlationKey).(string)
	if value == "" {
		return "corr_unavailable"
	}
	return value
}

func parsePositiveInt(value string, fallback int) int {
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return fallback
	}
	return parsed
}

func parseAuditQuery(request *http.Request) (audit.Query, error) {
	values := request.URL.Query()
	query := audit.Query{
		Search: values.Get("search"), ActorID: values.Get("actorId"), Action: values.Get("action"),
		ResourceType: values.Get("resourceType"), Outcome: values.Get("outcome"), NetworkAddress: values.Get("ipAddress"),
		Limit: parsePositiveInt(values.Get("limit"), 50), Offset: parsePositiveInt(values.Get("offset"), 0),
	}
	var err error
	if value := values.Get("from"); value != "" {
		query.From, err = time.Parse(time.RFC3339, value)
		if err != nil {
			return audit.Query{}, err
		}
	}
	if value := values.Get("to"); value != "" {
		query.To, err = time.Parse(time.RFC3339, value)
		if err != nil {
			return audit.Query{}, err
		}
	}
	if !query.From.IsZero() && !query.To.IsZero() && query.From.After(query.To) {
		return audit.Query{}, errors.New("invalid audit date range")
	}
	return query, nil
}

// clientAddress intentionally ignores forwarding headers. A deployment may
// trust those headers only after configuring a known reverse-proxy boundary.
func clientAddress(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err == nil {
		return host
	}
	return request.RemoteAddr
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	writeJSONStatus(response, status, value)
}

func writeJSONStatus(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
