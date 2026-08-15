package main

import "testing"

func productionDeploymentConfig() deploymentConfig {
	return deploymentConfig{
		Mode: "production", PublicAppURL: "https://files.example.test", DatabaseURL: "postgres://securestore@example.test/securestore?sslmode=verify-full",
		TLSCertificateFile: "/run/secrets/tls.crt", TLSKeyFile: "/run/secrets/tls.key",
		ScannerMode: "clamd", KeyProviderMode: "remote", AuditAnchorMode: "remote",
		MailerMode: "resend", AuditKeyFile: "/run/secrets/audit-hmac", MFAKeyFile: "/run/secrets/mfa-key", MetricsTokenFile: "/run/secrets/metrics-token", ResendKeyFile: "/run/secrets/resend-api-key",
		AllowedOrigins: []string{"https://files.example.test"}, SecureCookies: true, RequirePrivilegedMFA: true, RequireAdminStepUp: true,
	}
}

func TestProductionDeploymentRequiresHardenedBoundaries(t *testing.T) {
	valid := productionDeploymentConfig()
	if err := validateDeployment(valid); err != nil {
		t.Fatalf("valid production profile was rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*deploymentConfig)
	}{
		{"missing TLS", func(config *deploymentConfig) { config.TLSKeyFile = "" }},
		{"insecure cookie", func(config *deploymentConfig) { config.SecureCookies = false }},
		{"HTTP public URL", func(config *deploymentConfig) { config.PublicAppURL = "http://files.example.test" }},
		{"origin path", func(config *deploymentConfig) { config.AllowedOrigins = []string{"https://files.example.test/path"} }},
		{"plaintext database", func(config *deploymentConfig) {
			config.DatabaseURL = "postgres://example.test/securestore?sslmode=disable"
		}},
		{"development scanner", func(config *deploymentConfig) { config.ScannerMode = "deterministic" }},
		{"local key custody", func(config *deploymentConfig) { config.KeyProviderMode = "local" }},
		{"local audit anchor", func(config *deploymentConfig) { config.AuditAnchorMode = "local" }},
		{"file mailer", func(config *deploymentConfig) { config.MailerMode = "file" }},
		{"disabled MFA", func(config *deploymentConfig) { config.RequirePrivilegedMFA = false }},
		{"development secret file", func(config *deploymentConfig) { config.AuditKeyFile = ".data/audit-hmac.key" }},
		{"development Resend secret file", func(config *deploymentConfig) { config.ResendKeyFile = ".data/resend-api-key" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if err := validateDeployment(config); err == nil {
				t.Fatal("insecure production profile was accepted")
			}
		})
	}
}

func TestDevelopmentDeploymentRetainsLocalWorkflow(t *testing.T) {
	if err := validateDeployment(deploymentConfig{Mode: "development"}); err != nil {
		t.Fatalf("development profile was rejected: %v", err)
	}
	if err := validateDeployment(deploymentConfig{Mode: "unknown"}); err == nil {
		t.Fatal("unknown deployment mode was accepted")
	}
}
