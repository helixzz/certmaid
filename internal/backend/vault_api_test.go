package backend

import (
	"context"
	"os"
	"testing"
	"time"

	certmaid "github.com/helixzz/certmaid"
)

func TestNewVaultAPIBackend(t *testing.T) {
	backend, err := NewVaultAPIBackend("https://vault.example.com:8200", "pki", "web-server")
	if err != nil {
		t.Fatalf("NewVaultAPIBackend() unexpected error: %v", err)
	}
	if backend == nil {
		t.Fatal("NewVaultAPIBackend() returned nil")
	}
	if backend.mountPath != "pki" {
		t.Errorf("mountPath = %q, want %q", backend.mountPath, "pki")
	}
	if backend.role != "web-server" {
		t.Errorf("role = %q, want %q", backend.role, "web-server")
	}
	if backend.vaultClient == nil {
		t.Error("vaultClient is nil")
	}
}

func TestNewVaultAPIBackend_InvalidAddress(t *testing.T) {
	_, err := NewVaultAPIBackend("://invalid-url", "pki", "web-server")
	if err == nil {
		t.Fatal("expected error for invalid address, got nil")
	}
}

func TestVaultAPIBackend_SetToken(t *testing.T) {
	backend, err := NewVaultAPIBackend("https://vault.example.com:8200", "pki", "web-server")
	if err != nil {
		t.Fatalf("NewVaultAPIBackend() unexpected error: %v", err)
	}

	backend.SetToken("test-token-123")
	if backend.vaultClient.Token() != "test-token-123" {
		t.Errorf("Token() = %q, want %q", backend.vaultClient.Token(), "test-token-123")
	}
}

func TestVaultAPIBackend_Issue_BadAddress(t *testing.T) {
	backend, err := NewVaultAPIBackend("http://127.0.0.1:19999", "pki", "web-server")
	if err != nil {
		t.Fatalf("NewVaultAPIBackend() unexpected error: %v", err)
	}
	backend.SetToken("test-token")

	spec := certmaid.CertificateSpec{
		Name:    "test-cert",
		Domains: []string{"example.com"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = backend.Issue(ctx, spec)
	if err == nil {
		t.Fatal("expected error for bad address, got nil")
	}
}

func TestVaultAPIBackend_Issue_NoDomains(t *testing.T) {
	backend, err := NewVaultAPIBackend("https://vault.example.com:8200", "pki", "web-server")
	if err != nil {
		t.Fatalf("NewVaultAPIBackend() unexpected error: %v", err)
	}

	spec := certmaid.CertificateSpec{
		Name:    "test-cert",
		Domains: nil,
	}

	ctx := context.Background()
	_, err = backend.Issue(ctx, spec)
	if err == nil {
		t.Fatal("expected error for spec with no domains, got nil")
	}
}

func TestVaultAPIBackend_Issue_CancelledContext(t *testing.T) {
	backend, err := NewVaultAPIBackend("https://vault.example.com:8200", "pki", "web-server")
	if err != nil {
		t.Fatalf("NewVaultAPIBackend() unexpected error: %v", err)
	}

	spec := certmaid.CertificateSpec{
		Name:    "test-cert",
		Domains: []string{"example.com"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = backend.Issue(ctx, spec)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestVaultAPIBackend_Issue_RealVault(t *testing.T) {
	vaultAddr := os.Getenv("CERTMAID_TEST_VAULT_ADDR")
	if vaultAddr == "" {
		t.Skip("CERTMAID_TEST_VAULT_ADDR not set, skipping real Vault test")
	}

	vaultToken := os.Getenv("CERTMAID_TEST_VAULT_TOKEN")
	if vaultToken == "" {
		t.Skip("CERTMAID_TEST_VAULT_TOKEN not set, skipping real Vault test")
	}

	mountPath := os.Getenv("CERTMAID_TEST_VAULT_PKI_MOUNT")
	if mountPath == "" {
		mountPath = "pki"
	}

	role := os.Getenv("CERTMAID_TEST_VAULT_PKI_ROLE")
	if role == "" {
		role = "web-server"
	}

	testDomain := os.Getenv("CERTMAID_TEST_DOMAIN")
	if testDomain == "" {
		t.Skip("CERTMAID_TEST_DOMAIN not set, skipping real Vault test")
	}

	backend, err := NewVaultAPIBackend(vaultAddr, mountPath, role)
	if err != nil {
		t.Fatalf("NewVaultAPIBackend() unexpected error: %v", err)
	}
	backend.SetToken(vaultToken)

	spec := certmaid.CertificateSpec{
		Name:    "integration-test",
		Domains: []string{testDomain},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bundle, err := backend.Issue(ctx, spec)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if len(bundle.Certificate) == 0 {
		t.Error("Certificate is empty")
	}
	if len(bundle.PrivateKey) == 0 {
		t.Error("PrivateKey is empty")
	}
	if len(bundle.IssuingCA) == 0 {
		t.Error("IssuingCA is empty")
	}
	if len(bundle.CAChain) == 0 {
		t.Error("CAChain is empty")
	}
	if len(bundle.Domains) == 0 {
		t.Error("Domains is empty")
	}
	if bundle.NotAfter.IsZero() {
		t.Error("NotAfter is zero")
	}
	if bundle.NotAfter.Before(time.Now()) {
		t.Error("NotAfter is in the past")
	}
}

func TestParseCAChain(t *testing.T) {
	chain, err := parseCAChain(nil)
	if err != nil {
		t.Fatalf("parseCAChain(nil) unexpected error: %v", err)
	}
	if chain != nil {
		t.Errorf("parseCAChain(nil) = %v, want nil", chain)
	}
}

func TestParseCAChain_Valid(t *testing.T) {
	raw := []interface{}{
		"-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHf0qNH0qNHMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv\n-----END CERTIFICATE-----",
		"-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHf0qNH0qNHMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv\n-----END CERTIFICATE-----",
	}

	chain, err := parseCAChain(raw)
	if err != nil {
		t.Fatalf("parseCAChain() unexpected error: %v", err)
	}
	if len(chain) != 2 {
		t.Errorf("len(chain) = %d, want 2", len(chain))
	}
}

func TestParseCAChain_InvalidType(t *testing.T) {
	_, err := parseCAChain("not-an-array")
	if err == nil {
		t.Fatal("expected error for non-array input, got nil")
	}
}

func TestParseCAChain_InvalidElement(t *testing.T) {
	raw := []interface{}{123}
	_, err := parseCAChain(raw)
	if err == nil {
		t.Fatal("expected error for non-string element, got nil")
	}
}

func TestParseExpiration_Nil(t *testing.T) {
	_, err := parseExpiration(nil)
	if err == nil {
		t.Fatal("expected error for nil expiration, got nil")
	}
}

func TestParseExpiration_Valid(t *testing.T) {
	ts, err := parseExpiration(float64(1700000000))
	if err != nil {
		t.Fatalf("parseExpiration() unexpected error: %v", err)
	}
	expected := time.Unix(1700000000, 0)
	if !ts.Equal(expected) {
		t.Errorf("parseExpiration() = %v, want %v", ts, expected)
	}
}

func TestParseExpiration_InvalidType(t *testing.T) {
	_, err := parseExpiration([]int{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for invalid type, got nil")
	}
}

func TestParseExpiration_InvalidString(t *testing.T) {
	_, err := parseExpiration("not-a-number")
	if err == nil {
		t.Fatal("expected error for invalid string, got nil")
	}
}

func TestParseExpiration_Zero(t *testing.T) {
	_, err := parseExpiration(float64(0))
	if err == nil {
		t.Fatal("expected error for zero timestamp, got nil")
	}
}

func TestGetStringField_Missing(t *testing.T) {
	_, err := getStringField(map[string]interface{}{}, "missing")
	if err == nil {
		t.Fatal("expected error for missing field, got nil")
	}
}

func TestGetStringField_WrongType(t *testing.T) {
	_, err := getStringField(map[string]interface{}{"key": 123}, "key")
	if err == nil {
		t.Fatal("expected error for wrong type, got nil")
	}
}

func TestGetStringField_Valid(t *testing.T) {
	val, err := getStringField(map[string]interface{}{"key": "value"}, "key")
	if err != nil {
		t.Fatalf("getStringField() unexpected error: %v", err)
	}
	if val != "value" {
		t.Errorf("getStringField() = %q, want %q", val, "value")
	}
}