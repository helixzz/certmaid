package backend

import (
	"context"
	"os"
	"testing"
	"time"

	certmaid "github.com/helixzz/certmaid"
)

func TestNewVaultBackend(t *testing.T) {
	backend := NewVaultBackend("https://vault.example.com:8200/v1/pki/acme/directory", "kid-123", "hmac-secret")

	if backend.directoryURL != "https://vault.example.com:8200/v1/pki/acme/directory" {
		t.Errorf("directoryURL = %q, want %q", backend.directoryURL, "https://vault.example.com:8200/v1/pki/acme/directory")
	}
	if backend.eabKid != "kid-123" {
		t.Errorf("eabKid = %q, want %q", backend.eabKid, "kid-123")
	}
	if backend.eabHMACKey != "hmac-secret" {
		t.Errorf("eabHMACKey = %q, want %q", backend.eabHMACKey, "hmac-secret")
	}
}

func TestNewVaultBackend_EmptyEAB(t *testing.T) {
	backend := NewVaultBackend("https://vault.example.com:8200/v1/pki/acme/directory", "", "")

	if backend.eabKid != "" {
		t.Errorf("eabKid = %q, want empty", backend.eabKid)
	}
	if backend.eabHMACKey != "" {
		t.Errorf("eabHMACKey = %q, want empty", backend.eabHMACKey)
	}
}

func TestVaultBackend_Issue_InvalidDirectoryURL(t *testing.T) {
	backend := NewVaultBackend("http://127.0.0.1:19999/nonexistent", "", "")

	spec := certmaid.CertificateSpec{
		Name:    "test-cert",
		Domains: []string{"example.com"},
		KeyType: "RSA2048",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := backend.Issue(ctx, spec)
	if err == nil {
		t.Fatal("expected error for invalid directory URL, got nil")
	}
}

func TestVaultBackend_Issue_NoDomains(t *testing.T) {
	backend := NewVaultBackend("https://vault.example.com:8200/v1/pki/acme/directory", "", "")

	spec := certmaid.CertificateSpec{
		Name:    "test-cert",
		Domains: nil,
		KeyType: "RSA2048",
	}

	ctx := context.Background()
	_, err := backend.Issue(ctx, spec)
	if err == nil {
		t.Fatal("expected error for spec with no domains, got nil")
	}
}

func TestVaultBackend_Issue_CancelledContext(t *testing.T) {
	backend := NewVaultBackend("https://vault.example.com:8200/v1/pki/acme/directory", "", "")

	spec := certmaid.CertificateSpec{
		Name:    "test-cert",
		Domains: []string{"example.com"},
		KeyType: "RSA2048",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := backend.Issue(ctx, spec)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestVaultBackend_Issue_RealVault(t *testing.T) {
	vaultURL := os.Getenv("CERTMAID_TEST_VAULT_ACME_URL")
	if vaultURL == "" {
		t.Skip("CERTMAID_TEST_VAULT_ACME_URL not set, skipping real Vault test")
	}

	eabKid := os.Getenv("CERTMAID_TEST_VAULT_EAB_KID")
	eabHMACKey := os.Getenv("CERTMAID_TEST_VAULT_EAB_HMAC_KEY")
	testDomain := os.Getenv("CERTMAID_TEST_DOMAIN")
	if testDomain == "" {
		t.Skip("CERTMAID_TEST_DOMAIN not set, skipping real Vault test")
	}

	backend := NewVaultBackend(vaultURL, eabKid, eabHMACKey)

	spec := certmaid.CertificateSpec{
		Name:    "integration-test",
		Domains: []string{testDomain},
		KeyType: "ECDSA256",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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

func TestMapKeyType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"RSA2048", "2048"},
		{"ECDSA256", "P256"},
		{"ECDSA384", "P384"},
		{"", "2048"},
		{"UNKNOWN", "2048"},
	}

	for _, tt := range tests {
		result := mapKeyType(tt.input)
		if string(result) != tt.expected {
			t.Errorf("mapKeyType(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSplitCertChain(t *testing.T) {
	// Single certificate (no chain).
	singlePEM := []byte(`-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHf0qNH0qNHMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv
Y2FsaG9zdDAeFw0yMTAxMDEwMDAwMDBaFw0zMTAxMDEwMDAwMDBaMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA0Q==
-----END CERTIFICATE-----`)

	leaf, chain, err := splitCertChain(singlePEM)
	if err != nil {
		t.Fatalf("splitCertChain failed: %v", err)
	}
	if len(leaf) == 0 {
		t.Error("leaf is empty")
	}
	if len(chain) != 0 {
		t.Errorf("chain length = %d, want 0", len(chain))
	}
}

func TestSplitCertChain_Empty(t *testing.T) {
	_, _, err := splitCertChain([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
}

func TestExtractNotAfter_InvalidPEM(t *testing.T) {
	_, err := extractNotAfter([]byte("not a certificate"))
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
}