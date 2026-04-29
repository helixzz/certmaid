package backend

import (
	"context"
	"os"
	"testing"
	"time"

	certmaid "github.com/helixzz/certmaid"
)

func TestNewADCSBackend(t *testing.T) {
	backend := NewADCSBackend(
		"https://ndes.example.com/certsrv/mscep/mscep.dll",
		"challenge-password-123",
		"AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01",
		5*time.Second,
		60*time.Second,
	)

	if backend.serverURL != "https://ndes.example.com/certsrv/mscep/mscep.dll" {
		t.Errorf("serverURL = %q, want %q", backend.serverURL, "https://ndes.example.com/certsrv/mscep/mscep.dll")
	}
	if backend.challengePass != "challenge-password-123" {
		t.Errorf("challengePass = %q, want %q", backend.challengePass, "challenge-password-123")
	}
	if backend.caFingerprint != "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01" {
		t.Errorf("caFingerprint = %q, want %q", backend.caFingerprint, "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01")
	}
	if backend.pollInterval != 5*time.Second {
		t.Errorf("pollInterval = %v, want %v", backend.pollInterval, 5*time.Second)
	}
	if backend.pollTimeout != 60*time.Second {
		t.Errorf("pollTimeout = %v, want %v", backend.pollTimeout, 60*time.Second)
	}
	if backend.httpClient != nil {
		t.Error("httpClient should be nil before first Issue call")
	}
}

func TestADCSBackend_Issue_NoDomains(t *testing.T) {
	backend := NewADCSBackend(
		"https://ndes.example.com/certsrv/mscep/mscep.dll",
		"challenge-password",
		"",
		5*time.Second,
		60*time.Second,
	)

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

func TestADCSBackend_Issue_ECKeyType(t *testing.T) {
	backend := NewADCSBackend(
		"https://ndes.example.com/certsrv/mscep/mscep.dll",
		"challenge-password",
		"",
		5*time.Second,
		60*time.Second,
	)

	tests := []struct {
		keyType string
	}{
		{"ECDSA256"},
		{"ECDSA384"},
	}

	for _, tt := range tests {
		t.Run(tt.keyType, func(t *testing.T) {
			spec := certmaid.CertificateSpec{
				Name:    "test-cert",
				Domains: []string{"example.com"},
				KeyType: tt.keyType,
			}

			ctx := context.Background()
			_, err := backend.Issue(ctx, spec)
			if err == nil {
				t.Fatalf("expected error for key type %q, got nil", tt.keyType)
			}

			expectedMsg := "AD CS SCEP backend only supports RSA keys; use RSA2048 or RSA4096"
			if err.Error() != expectedMsg {
				t.Errorf("error message = %q, want %q", err.Error(), expectedMsg)
			}
		})
	}
}

func TestADCSBackend_Issue_CancelledContext(t *testing.T) {
	backend := NewADCSBackend(
		"https://ndes.example.com/certsrv/mscep/mscep.dll",
		"challenge-password",
		"",
		5*time.Second,
		60*time.Second,
	)

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

func TestADCSBackend_Issue_RealNDES(t *testing.T) {
	serverURL := os.Getenv("CERTMAID_TEST_ADCS_SERVER_URL")
	if serverURL == "" {
		t.Skip("CERTMAID_TEST_ADCS_SERVER_URL not set, skipping real NDES test")
	}

	challengePass := os.Getenv("CERTMAID_TEST_ADCS_CHALLENGE_PASSWORD")
	if challengePass == "" {
		t.Skip("CERTMAID_TEST_ADCS_CHALLENGE_PASSWORD not set, skipping real NDES test")
	}

	caFingerprint := os.Getenv("CERTMAID_TEST_ADCS_CA_FINGERPRINT")

	testDomain := os.Getenv("CERTMAID_TEST_DOMAIN")
	if testDomain == "" {
		t.Skip("CERTMAID_TEST_DOMAIN not set, skipping real NDES test")
	}

	backend := NewADCSBackend(
		serverURL,
		challengePass,
		caFingerprint,
		5*time.Second,
		120*time.Second,
	)

	spec := certmaid.CertificateSpec{
		Name:    "integration-test",
		Domains: []string{testDomain},
		KeyType: "RSA2048",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
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
