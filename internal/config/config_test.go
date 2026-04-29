package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// validYAML returns a minimal valid YAML config as bytes.
const validYAML = `
defaults:
  renew_before: 720h
  check_interval: 12h
  key_type: RSA2048
  key_algorithm: rsa
  challenge: http-01
  cert_dir_mode: 0750
  cert_file_mode: 0640
backends:
  vault:
    acme:
      enabled: true
      directory_url: "https://vault.example.com:8200/v1/pki/acme/directory"
      eab:
        kid: "my-kid"
        hmac_key: "my-hmac-key"
output:
  base_dir: "/etc/certmaid/certs"
hooks:
  pre_renew:
    command: "echo pre"
  post_renew:
    nginx_reload: true
    nginx_config_test: true
    command: "systemctl reload nginx"
logging:
  level: info
  format: json
  file: "/var/log/certmaid/certmaid.log"
certificates:
  - name: example-web
    domains:
      - example.com
      - www.example.com
    backend: vault
    output:
      cert_path: "/etc/nginx/ssl/example.com.crt"
      key_path: "/etc/nginx/ssl/example.com.key"
      chain_path: "/etc/nginx/ssl/example.com.chain.crt"
`

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	return path
}

func TestLoadValidConfig(t *testing.T) {
	path := writeTempConfig(t, validYAML)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	if cfg == nil {
		t.Fatal("Load() returned nil config")
	}

	// Check defaults parsed correctly.
	if cfg.Defaults.RenewBefore != 720*time.Hour {
		t.Errorf("Defaults.RenewBefore = %v, want %v", cfg.Defaults.RenewBefore, 720*time.Hour)
	}
	if cfg.Defaults.KeyType != "RSA2048" {
		t.Errorf("Defaults.KeyType = %q, want %q", cfg.Defaults.KeyType, "RSA2048")
	}
	if cfg.Defaults.CertDirMode != 0750 {
		t.Errorf("Defaults.CertDirMode = %o, want %o", cfg.Defaults.CertDirMode, 0750)
	}
	if cfg.Defaults.CertFileMode != 0640 {
		t.Errorf("Defaults.CertFileMode = %o, want %o", cfg.Defaults.CertFileMode, 0640)
	}

	// Check backends.
	if !cfg.Backends.Vault.ACME.Enabled {
		t.Error("Backends.Vault.ACME.Enabled should be true")
	}
	if cfg.Backends.Vault.ACME.EAB.KID != "my-kid" {
		t.Errorf("Backends.Vault.ACME.EAB.KID = %q, want %q", cfg.Backends.Vault.ACME.EAB.KID, "my-kid")
	}

	// Check output.
	if cfg.Output.BaseDir != "/etc/certmaid/certs" {
		t.Errorf("Output.BaseDir = %q, want %q", cfg.Output.BaseDir, "/etc/certmaid/certs")
	}

	// Check hooks.
	if !cfg.Hooks.PostRenew.NginxReload {
		t.Error("Hooks.PostRenew.NginxReload should be true")
	}
	if cfg.Hooks.PreRenew.Command != "echo pre" {
		t.Errorf("Hooks.PreRenew.Command = %q, want %q", cfg.Hooks.PreRenew.Command, "echo pre")
	}

	// Check logging.
	if cfg.Logging.Level != "info" {
		t.Errorf("Logging.Level = %q, want %q", cfg.Logging.Level, "info")
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Logging.Format = %q, want %q", cfg.Logging.Format, "json")
	}

	// Check certificates.
	if len(cfg.Certificates) != 1 {
		t.Fatalf("len(Certificates) = %d, want 1", len(cfg.Certificates))
	}
	cert := cfg.Certificates[0]
	if cert.Name != "example-web" {
		t.Errorf("Certificates[0].Name = %q, want %q", cert.Name, "example-web")
	}
	if len(cert.Domains) != 2 {
		t.Errorf("len(Certificates[0].Domains) = %d, want 2", len(cert.Domains))
	}
	if cert.Backend != "vault" {
		t.Errorf("Certificates[0].Backend = %q, want %q", cert.Backend, "vault")
	}
	if cert.Output.CertPath != "/etc/nginx/ssl/example.com.crt" {
		t.Errorf("Certificates[0].Output.CertPath = %q, want %q", cert.Output.CertPath, "/etc/nginx/ssl/example.com.crt")
	}
}

func TestLoadDefaultsApplied(t *testing.T) {
	// YAML with only required fields — everything else should get defaults.
	const minimalYAML = `
certificates:
  - name: test-cert
    domains:
      - test.local
    backend: vault
`
	path := writeTempConfig(t, minimalYAML)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	// Defaults from SetDefault should be present.
	if cfg.Defaults.RenewBefore != 720*time.Hour {
		t.Errorf("Defaults.RenewBefore = %v, want 720h (default)", cfg.Defaults.RenewBefore)
	}
	if cfg.Defaults.KeyType != "RSA2048" {
		t.Errorf("Defaults.KeyType = %q, want RSA2048 (default)", cfg.Defaults.KeyType)
	}
	if cfg.Defaults.CertDirMode != 0750 {
		t.Errorf("Defaults.CertDirMode = %o, want 0750 (default)", cfg.Defaults.CertDirMode)
	}
	if cfg.Defaults.CertFileMode != 0640 {
		t.Errorf("Defaults.CertFileMode = %o, want 0640 (default)", cfg.Defaults.CertFileMode)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("Logging.Level = %q, want info (default)", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Logging.Format = %q, want json (default)", cfg.Logging.Format)
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("Load() should return error for nonexistent file")
	}
}

func TestLoadNoCertificates(t *testing.T) {
	const noCertsYAML = `
defaults:
  renew_before: 720h
certificates:
`
	path := writeTempConfig(t, noCertsYAML)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() should return error when no certificates defined")
	}
}

func TestLoadMissingName(t *testing.T) {
	const missingNameYAML = `
certificates:
  - domains:
      - example.com
    backend: vault
`
	path := writeTempConfig(t, missingNameYAML)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() should return error when certificate name is missing")
	}
}

func TestLoadMissingDomains(t *testing.T) {
	const missingDomainsYAML = `
certificates:
  - name: test-cert
    backend: vault
`
	path := writeTempConfig(t, missingDomainsYAML)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() should return error when domains are missing")
	}
}

func TestLoadMissingBackend(t *testing.T) {
	const missingBackendYAML = `
certificates:
  - name: test-cert
    domains:
      - example.com
`
	path := writeTempConfig(t, missingBackendYAML)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() should return error when backend is missing")
	}
}

func TestLoadUnsupportedBackend(t *testing.T) {
	const unsupportedBackendYAML = `
certificates:
  - name: test-cert
    domains:
      - example.com
    backend: adcs
`
	path := writeTempConfig(t, unsupportedBackendYAML)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() should return error for unsupported backend")
	}
}

func TestLoadEmptyDomains(t *testing.T) {
	const emptyDomainsYAML = `
certificates:
  - name: test-cert
    domains: []
    backend: vault
`
	path := writeTempConfig(t, emptyDomainsYAML)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() should return error when domains list is empty")
	}
}
