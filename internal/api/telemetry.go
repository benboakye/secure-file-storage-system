package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"securestore/internal/ingest"
)

type telemetryPosture struct {
	ExporterEnabled   bool       `json:"exporterEnabled"`
	Connected         bool       `json:"connected"`
	ScrapesTotal      uint64     `json:"scrapesTotal"`
	LastScrapeAt      *time.Time `json:"lastScrapeAt,omitempty"`
	StaleAfterSeconds int64      `json:"staleAfterSeconds"`
}

type httpMetricKey struct {
	Method, Route, StatusClass string
}

type httpMetricValue struct {
	Count           uint64
	DurationSeconds float64
}

// telemetryRegistry is intentionally process-local. It stores only aggregate,
// bounded HTTP dimensions and a digest of the collector credential; durable
// business-state gauges are reconstructed from authoritative repositories for
// every scrape instead of being cached here.
type telemetryRegistry struct {
	mu         sync.RWMutex
	tokenHash  [sha256.Size]byte
	enabled    bool
	staleAfter time.Duration
	requests   map[httpMetricKey]httpMetricValue
	scrapes    uint64
	lastScrape *time.Time
}

func newTelemetryRegistry(token string, staleAfter time.Duration) (*telemetryRegistry, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return &telemetryRegistry{staleAfter: staleAfter, requests: make(map[httpMetricKey]httpMetricValue)}, nil
	}
	if len(token) < 32 || len(token) > 256 || strings.ContainsAny(token, " \t\r\n\x00") {
		return nil, fmt.Errorf("metrics bearer token must contain 32 to 256 non-whitespace characters")
	}
	if staleAfter <= 0 {
		staleAfter = 5 * time.Minute
	}
	return &telemetryRegistry{tokenHash: sha256.Sum256([]byte(token)), enabled: true, staleAfter: staleAfter, requests: make(map[httpMetricKey]httpMetricValue)}, nil
}

func (registry *telemetryRegistry) authorized(header string) bool {
	if !registry.enabled || !strings.HasPrefix(header, "Bearer ") {
		return false
	}
	provided := strings.TrimPrefix(header, "Bearer ")
	digest := sha256.Sum256([]byte(provided))
	return subtle.ConstantTimeCompare(digest[:], registry.tokenHash[:]) == 1
}

// observe resolves the registered ServeMux pattern before the middleware chain
// copies or decorates the request. Recording the template (rather than the raw
// URL) prevents resource identifiers from entering metrics and bounds label
// cardinality to the application's finite route set.
func (registry *telemetryRegistry) observe(routes *http.ServeMux, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		started := time.Now()
		_, matchedPattern := routes.Handler(request)
		writer := &metricResponseWriter{ResponseWriter: response, status: http.StatusOK}
		next.ServeHTTP(writer, request)
		pattern := safeMetricRoute(matchedPattern)
		key := httpMetricKey{Method: safeMetricMethod(request.Method), Route: pattern, StatusClass: strconv.Itoa(writer.status/100) + "xx"}
		registry.mu.Lock()
		value := registry.requests[key]
		value.Count++
		value.DurationSeconds += time.Since(started).Seconds()
		registry.requests[key] = value
		registry.mu.Unlock()
	})
}

type metricResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (writer *metricResponseWriter) WriteHeader(status int) {
	if writer.wroteHeader {
		return
	}
	writer.wroteHeader = true
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *metricResponseWriter) Unwrap() http.ResponseWriter { return writer.ResponseWriter }

func safeMetricMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
		return method
	default:
		return "OTHER"
	}
}

func safeMetricRoute(pattern string) string {
	if fields := strings.Fields(pattern); len(fields) == 2 {
		pattern = fields[1]
	}
	if pattern == "" || len(pattern) > 160 || !strings.HasPrefix(pattern, "/") {
		return "unmatched"
	}
	return pattern
}

func (registry *telemetryRegistry) recordScrape(now time.Time) {
	now = now.UTC().Truncate(time.Microsecond)
	registry.mu.Lock()
	registry.scrapes++
	registry.lastScrape = &now
	registry.mu.Unlock()
}

// posture treats a collector as connected only when an authenticated scrape is
// recent. Merely enabling the endpoint—or receiving a rejected request—must not
// create false evidence that external monitoring is operational.
func (registry *telemetryRegistry) posture(now time.Time) telemetryPosture {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	result := telemetryPosture{ExporterEnabled: registry.enabled, ScrapesTotal: registry.scrapes, StaleAfterSeconds: int64(registry.staleAfter.Seconds())}
	if registry.lastScrape != nil {
		value := *registry.lastScrape
		result.LastScrapeAt = &value
		result.Connected = registry.enabled && now.UTC().Sub(value) <= registry.staleAfter
	}
	return result
}

func (registry *telemetryRegistry) renderHTTP(builder *strings.Builder) {
	registry.mu.RLock()
	keys := make([]httpMetricKey, 0, len(registry.requests))
	values := make(map[httpMetricKey]httpMetricValue, len(registry.requests))
	for key, value := range registry.requests {
		keys = append(keys, key)
		values[key] = value
	}
	scrapes := registry.scrapes
	registry.mu.RUnlock()
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Route != keys[j].Route {
			return keys[i].Route < keys[j].Route
		}
		if keys[i].Method != keys[j].Method {
			return keys[i].Method < keys[j].Method
		}
		return keys[i].StatusClass < keys[j].StatusClass
	})
	builder.WriteString("# HELP securestore_http_requests_total Completed HTTP requests by bounded route template.\n# TYPE securestore_http_requests_total counter\n")
	for _, key := range keys {
		value := values[key]
		labels := fmt.Sprintf("method=%q,route=%q,status_class=%q", key.Method, key.Route, key.StatusClass)
		fmt.Fprintf(builder, "securestore_http_requests_total{%s} %d\n", labels, value.Count)
	}
	builder.WriteString("# HELP securestore_http_request_duration_seconds Request processing time by bounded route template.\n# TYPE securestore_http_request_duration_seconds summary\n")
	for _, key := range keys {
		value := values[key]
		labels := fmt.Sprintf("method=%q,route=%q,status_class=%q", key.Method, key.Route, key.StatusClass)
		fmt.Fprintf(builder, "securestore_http_request_duration_seconds_sum{%s} %.6f\n", labels, value.DurationSeconds)
		fmt.Fprintf(builder, "securestore_http_request_duration_seconds_count{%s} %d\n", labels, value.Count)
	}
	builder.WriteString("# HELP securestore_telemetry_scrapes_total Successful authenticated metric scrapes.\n# TYPE securestore_telemetry_scrapes_total counter\n")
	fmt.Fprintf(builder, "securestore_telemetry_scrapes_total %d\n", scrapes)
}

type operationalMetrics struct {
	UptimeSeconds, QuarantineBytes, ReservedCapacityBytes, StorageCapacityBytes, StorageReserveBytes     int64
	ScannerSignatureAgeSeconds, ScannerSignatureMaxAgeSeconds                                            int64
	PendingProcessing, FailedRecords, ActiveReservations, OrphanedQuarantineObjects                      int
	ProtectedCiphertextBytes, AuditPendingEvidence                                                       int64
	AuditAnchorLagEvents                                                                                 int64
	ProtectedObjects, ProtectedOrphans, ProtectedMissing                                                 int
	IngestionDurable, ProtectedDurable, ScannerConnected, ScannerProductionReady, ScannerSignaturesFresh bool
	KeyServiceConnected, KeyServiceProductionReady, KeyServiceHardwareBacked                             bool
	AuditAnchorConnected, AuditAnchorProductionReady, AuditAnchorValid                                   bool
}

// renderOperationalMetrics exposes aggregate operational state without labels.
// Keeping these gauges unlabelled prevents future callers from accidentally
// introducing owner, file, object, path, or other sensitive dimensions.
func renderOperationalMetrics(builder *strings.Builder, metrics operationalMetrics) {
	gauge := func(name, help string, value any) {
		fmt.Fprintf(builder, "# HELP %s %s\n# TYPE %s gauge\n%s %v\n", name, help, name, name, value)
	}
	boolValue := func(value bool) int {
		if value {
			return 1
		}
		return 0
	}
	gauge("securestore_uptime_seconds", "Current API process uptime.", metrics.UptimeSeconds)
	gauge("securestore_ingestion_pending_records", "Uploads awaiting a terminal lifecycle state.", metrics.PendingProcessing)
	gauge("securestore_ingestion_failed_records", "Durable failed upload records.", metrics.FailedRecords)
	gauge("securestore_quarantine_bytes", "Measured regular-file bytes in quarantine.", metrics.QuarantineBytes)
	gauge("securestore_quarantine_orphan_objects", "Unmatched regular objects in quarantine.", metrics.OrphanedQuarantineObjects)
	gauge("securestore_capacity_active_reservations", "Active durable upload capacity reservations.", metrics.ActiveReservations)
	gauge("securestore_capacity_reserved_bytes", "Bytes held by active durable capacity reservations.", metrics.ReservedCapacityBytes)
	gauge("securestore_capacity_configured_bytes", "Configured logical protected-storage pool.", metrics.StorageCapacityBytes)
	gauge("securestore_capacity_safety_reserve_bytes", "Configured non-admissible safety reserve.", metrics.StorageReserveBytes)
	gauge("securestore_protected_objects", "Tracked encrypted storage objects.", metrics.ProtectedObjects)
	gauge("securestore_protected_ciphertext_bytes", "Tracked encrypted object bytes.", metrics.ProtectedCiphertextBytes)
	gauge("securestore_protected_orphan_objects", "Encrypted objects without active metadata.", metrics.ProtectedOrphans)
	gauge("securestore_protected_missing_objects", "Metadata records whose encrypted object is absent.", metrics.ProtectedMissing)
	gauge("securestore_audit_pending_evidence", "Committed audit intents awaiting signed-chain delivery.", metrics.AuditPendingEvidence)
	gauge("securestore_audit_anchor_connected", "Whether a checkpoint anchor is reachable.", boolValue(metrics.AuditAnchorConnected))
	gauge("securestore_audit_anchor_production_ready", "Whether checkpoint anchoring is independent, immutable, and server-attested.", boolValue(metrics.AuditAnchorProductionReady))
	gauge("securestore_audit_anchor_valid", "Whether the latest trusted anchor receipt agrees with the database checkpoint.", boolValue(metrics.AuditAnchorValid))
	gauge("securestore_audit_anchor_lag_events", "Number of verified audit events beyond the latest valid anchored checkpoint.", metrics.AuditAnchorLagEvents)
	gauge("securestore_ingestion_repository_durable", "Whether ingestion metadata uses durable persistence.", boolValue(metrics.IngestionDurable))
	gauge("securestore_protected_repository_durable", "Whether protected metadata uses durable persistence.", boolValue(metrics.ProtectedDurable))
	gauge("securestore_scanner_connected", "Whether an inspection adapter is connected.", boolValue(metrics.ScannerConnected))
	gauge("securestore_scanner_production_ready", "Whether scanner posture satisfies production requirements.", boolValue(metrics.ScannerProductionReady))
	gauge("securestore_scanner_signatures_fresh", "Whether scanner signature timestamp evidence is within policy.", boolValue(metrics.ScannerSignaturesFresh))
	gauge("securestore_scanner_signature_age_seconds", "Age of the scanner signature database timestamp, or zero when unavailable.", metrics.ScannerSignatureAgeSeconds)
	gauge("securestore_scanner_signature_max_age_seconds", "Maximum signature database age permitted by policy.", metrics.ScannerSignatureMaxAgeSeconds)
	gauge("securestore_key_service_connected", "Whether the managed key-service control plane is reachable.", boolValue(metrics.KeyServiceConnected))
	gauge("securestore_key_service_production_ready", "Whether managed key custody satisfies the production policy.", boolValue(metrics.KeyServiceProductionReady))
	gauge("securestore_key_service_hardware_backed", "Whether the active wrapping key reports hardware-backed custody.", boolValue(metrics.KeyServiceHardwareBacked))
}

func metricsFromResources(resources ingest.AdminResourcePage) operationalMetrics {
	return operationalMetrics{
		QuarantineBytes: resources.Summary.QuarantineBytes, PendingProcessing: resources.Summary.PendingProcessing,
		FailedRecords: resources.Summary.StatusCounts[ingest.StatusFailed], ActiveReservations: resources.Summary.ActiveReservations,
		ReservedCapacityBytes: resources.Summary.ReservedCapacityBytes, StorageCapacityBytes: resources.Summary.StorageCapacityBytes,
		StorageReserveBytes: resources.Summary.StorageReserveBytes, OrphanedQuarantineObjects: resources.Summary.OrphanedObjects,
		IngestionDurable: resources.Summary.MetadataDurable,
	}
}
