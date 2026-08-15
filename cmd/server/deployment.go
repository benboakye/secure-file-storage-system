package main

import (
	"errors"
	"net/url"
	"strings"
)

type deploymentConfig struct {
	Mode, PublicAppURL, DatabaseURL                                           string
	TLSCertificateFile, TLSKeyFile                                            string
	ScannerMode, KeyProviderMode, AuditAnchorMode, MailerMode                 string
	AuditKeyFile, MFAKeyFile, MetricsTokenFile, ResendKeyFile                 string
	AuditKeyInjected, MFAKeyInjected, MetricsTokenInjected, ResendKeyInjected bool
	AllowedOrigins                                                            []string
	SecureCookies, RequirePrivilegedMFA, RequireAdminStepUp                   bool
}

func validateDeployment(config deploymentConfig) error {
	switch config.Mode {
	case "development":
		return nil
	case "production":
	default:
		return errors.New("SECURESTORE_DEPLOYMENT_MODE must be development or production")
	}
	if config.TLSCertificateFile == "" || config.TLSKeyFile == "" {
		return errors.New("production requires SECURESTORE_TLS_CERT_FILE and SECURESTORE_TLS_KEY_FILE")
	}
	if !config.SecureCookies {
		return errors.New("production requires SECURESTORE_SECURE_COOKIES=true")
	}
	if !config.RequirePrivilegedMFA || !config.RequireAdminStepUp {
		return errors.New("production requires privileged MFA and administrator step-up authorization")
	}
	if config.ScannerMode != "clamd" || config.KeyProviderMode != "remote" || config.AuditAnchorMode != "remote" {
		return errors.New("production requires clamd, remote key custody, and remote audit anchoring")
	}
	if config.MailerMode != "resend" {
		return errors.New("production requires the Resend delivery adapter")
	}
	if err := requireHTTPSURL(config.PublicAppURL, true); err != nil {
		return errors.New("production public application URL must be an HTTPS origin")
	}
	if len(config.AllowedOrigins) == 0 {
		return errors.New("production requires at least one HTTPS allowed origin")
	}
	for _, origin := range config.AllowedOrigins {
		if err := requireHTTPSURL(origin, true); err != nil {
			return errors.New("production allowed origins must be exact HTTPS origins")
		}
	}
	if err := requireVerifiedPostgres(config.DatabaseURL); err != nil {
		return err
	}
	for name, source := range map[string]struct {
		path     string
		injected bool
	}{
		"audit HMAC":     {config.AuditKeyFile, config.AuditKeyInjected},
		"MFA encryption": {config.MFAKeyFile, config.MFAKeyInjected},
		"metrics bearer": {config.MetricsTokenFile, config.MetricsTokenInjected},
		"Resend API":     {config.ResendKeyFile, config.ResendKeyInjected},
	} {
		if !source.injected && isDevelopmentSecretPath(source.path) {
			return errors.New("production " + name + " secret must be injected or mounted outside .data")
		}
	}
	return nil
}

func configuredOrigins(value string) []string {
	result := make([]string, 0)
	for _, origin := range strings.Split(value, ",") {
		if origin = strings.TrimSpace(origin); origin != "" {
			result = append(result, origin)
		}
	}
	return result
}

func requireHTTPSURL(value string, exactOrigin bool) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("invalid HTTPS URL")
	}
	if exactOrigin && (parsed.Path != "" || parsed.RawQuery != "") {
		return errors.New("origin must not contain a path or query")
	}
	return nil
}

func requireVerifiedPostgres(value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" {
		return errors.New("production requires a PostgreSQL connection URL")
	}
	if parsed.Query().Get("sslmode") != "verify-full" {
		return errors.New("production PostgreSQL must use sslmode=verify-full")
	}
	return nil
}

func isDevelopmentSecretPath(value string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "\\", "/"))
	return normalized == "" || normalized == ".data" || strings.HasPrefix(normalized, ".data/")
}
