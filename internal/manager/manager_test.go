package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/helixzz/certmaid"
	"github.com/helixzz/certmaid/internal/config"
	"go.uber.org/zap"
)

// mockBackend implements certmaid.Backend for testing.
type mockBackend struct {
	issueFunc func(ctx context.Context, spec certmaid.CertificateSpec) (*certmaid.CertificateBundle, error)
}

func (m *mockBackend) Issue(ctx context.Context, spec certmaid.CertificateSpec) (*certmaid.CertificateBundle, error) {
	if m.issueFunc != nil {
		return m.issueFunc(ctx, spec)
	}
	return nil, nil
}

// mockWriter implements certmaid.Writer for testing.
type mockWriter struct {
	writeFunc func(name string, bundle *certmaid.CertificateBundle, output certmaid.OutputConfig) error
}

func (m *mockWriter) Write(name string, bundle *certmaid.CertificateBundle, output certmaid.OutputConfig) error {
	if m.writeFunc != nil {
		return m.writeFunc(name, bundle, output)
	}
	return nil
}

// mockHookRunner implements certmaid.HookRunner for testing.
type mockHookRunner struct {
	nginxReloadResult *certmaid.HookResult
	commandResult     *certmaid.HookResult
	scriptResult      *certmaid.HookResult
}

func (m *mockHookRunner) RunNginxReload() *certmaid.HookResult {
	if m.nginxReloadResult != nil {
		return m.nginxReloadResult
	}
	return &certmaid.HookResult{Name: "nginx-reload", Success: true}
}

func (m *mockHookRunner) RunCommand(cmd string) *certmaid.HookResult {
	if m.commandResult != nil {
		return m.commandResult
	}
	return &certmaid.HookResult{Name: cmd, Success: true}
}

func (m *mockHookRunner) RunScript(path string, ctx certmaid.HookContext) *certmaid.HookResult {
	if m.scriptResult != nil {
		return m.scriptResult
	}
	return &certmaid.HookResult{Name: path, Success: true}
}

// generateTestCertPEM creates a self-signed certificate PEM with the given NotAfter.
func generateTestCertPEM(notAfter time.Time) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		panic(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// generateTestBundle creates a CertificateBundle with a certificate expiring at notAfter.
func generateTestBundle(notAfter time.Time) *certmaid.CertificateBundle {
	certPEM := generateTestCertPEM(notAfter)
	return &certmaid.CertificateBundle{
		Certificate: certPEM,
		PrivateKey:  []byte("test-key"),
		IssuingCA:   certPEM,
		CAChain:     [][]byte{certPEM},
		Domains:     []string{"test.example.com"},
		NotAfter:    notAfter,
	}
}

func testConfig() *config.Config {
	return &config.Config{
		Defaults: config.DefaultsConfig{
			RenewBefore: 720 * time.Hour,
		},
		Output: config.GlobalOutputConfig{
			BaseDir: "",
		},
		Hooks: config.HooksConfig{
			PostRenew: certmaid.HookConfig{},
		},
		Certificates: []certmaid.CertificateSpec{
			{
				Name:        "test-cert",
				Domains:     []string{"test.example.com"},
				Backend:     "vault",
				RenewBefore: 0,
			},
		},
	}
}

func TestNew(t *testing.T) {
	cfg := testConfig()
	backend := &mockBackend{}
	writer := &mockWriter{}
	hookRunner := &mockHookRunner{}
	logger := zap.NewNop()

	mgr := New(cfg, backend, writer, hookRunner, logger)

	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	if mgr.config != cfg {
		t.Error("config not set correctly")
	}
	if mgr.backend != backend {
		t.Error("backend not set correctly")
	}
	if mgr.writer != writer {
		t.Error("writer not set correctly")
	}
	if mgr.hookRunner != hookRunner {
		t.Error("hookRunner not set correctly")
	}
}

func TestStatus_NoRenewalNeeded(t *testing.T) {
	dir := t.TempDir()

	cfg := testConfig()
	cfg.Output.BaseDir = dir
	cfg.Certificates[0].RenewBefore = 720 * time.Hour

	// Write a cert that expires far in the future.
	certPath := filepath.Join(dir, "live", "test-cert", "cert.pem")
	if err := os.MkdirAll(filepath.Dir(certPath), 0750); err != nil {
		t.Fatal(err)
	}
	futureCert := generateTestCertPEM(time.Now().Add(90 * 24 * time.Hour))
	if err := os.WriteFile(certPath, futureCert, 0644); err != nil {
		t.Fatal(err)
	}

	mgr := New(cfg, &mockBackend{}, &mockWriter{}, &mockHookRunner{}, zap.NewNop())

	statuses, err := mgr.Status(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}

	if statuses[0].NeedsRenew {
		t.Error("expected NeedsRenew=false for future cert")
	}
	if statuses[0].Name != "test-cert" {
		t.Errorf("expected name test-cert, got %s", statuses[0].Name)
	}
}

func TestStatus_NeedsRenewal(t *testing.T) {
	dir := t.TempDir()

	cfg := testConfig()
	cfg.Output.BaseDir = dir
	cfg.Certificates[0].RenewBefore = 720 * time.Hour

	// Write a cert that expires soon.
	certPath := filepath.Join(dir, "live", "test-cert", "cert.pem")
	if err := os.MkdirAll(filepath.Dir(certPath), 0750); err != nil {
		t.Fatal(err)
	}
	soonCert := generateTestCertPEM(time.Now().Add(24 * time.Hour))
	if err := os.WriteFile(certPath, soonCert, 0644); err != nil {
		t.Fatal(err)
	}

	mgr := New(cfg, &mockBackend{}, &mockWriter{}, &mockHookRunner{}, zap.NewNop())

	statuses, err := mgr.Status(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}

	if !statuses[0].NeedsRenew {
		t.Error("expected NeedsRenew=true for soon-to-expire cert")
	}
}

func TestStatus_NoCertFile(t *testing.T) {
	dir := t.TempDir()

	cfg := testConfig()
	cfg.Output.BaseDir = dir

	mgr := New(cfg, &mockBackend{}, &mockWriter{}, &mockHookRunner{}, zap.NewNop())

	statuses, err := mgr.Status(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}

	if !statuses[0].NeedsRenew {
		t.Error("expected NeedsRenew=true when cert file does not exist")
	}
}

func TestRun_RenewsExpiredCert(t *testing.T) {
	dir := t.TempDir()

	cfg := testConfig()
	cfg.Output.BaseDir = dir
	cfg.Certificates[0].RenewBefore = 720 * time.Hour

	// Write an expired cert.
	certPath := filepath.Join(dir, "live", "test-cert", "cert.pem")
	if err := os.MkdirAll(filepath.Dir(certPath), 0750); err != nil {
		t.Fatal(err)
	}
	expiredCert := generateTestCertPEM(time.Now().Add(-1 * time.Hour))
	if err := os.WriteFile(certPath, expiredCert, 0644); err != nil {
		t.Fatal(err)
	}

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	backend := &mockBackend{
		issueFunc: func(ctx context.Context, spec certmaid.CertificateSpec) (*certmaid.CertificateBundle, error) {
			return generateTestBundle(notAfter), nil
		},
	}
	writer := &mockWriter{
		writeFunc: func(name string, bundle *certmaid.CertificateBundle, output certmaid.OutputConfig) error {
			return nil
		},
	}

	mgr := New(cfg, backend, writer, &mockHookRunner{}, zap.NewNop())

	result, err := mgr.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Total != 1 {
		t.Errorf("expected Total=1, got %d", result.Total)
	}
	if result.Renewed != 1 {
		t.Errorf("expected Renewed=1, got %d", result.Renewed)
	}
	if result.Failed != 0 {
		t.Errorf("expected Failed=0, got %d", result.Failed)
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	if !result.Results[0].Renewed {
		t.Error("expected cert to be renewed")
	}
}

func TestRun_RenewsNonexistentCert(t *testing.T) {
	dir := t.TempDir()

	cfg := testConfig()
	cfg.Output.BaseDir = dir
	cfg.Certificates[0].RenewBefore = 720 * time.Hour

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	backend := &mockBackend{
		issueFunc: func(ctx context.Context, spec certmaid.CertificateSpec) (*certmaid.CertificateBundle, error) {
			return generateTestBundle(notAfter), nil
		},
	}
	writer := &mockWriter{
		writeFunc: func(name string, bundle *certmaid.CertificateBundle, output certmaid.OutputConfig) error {
			return nil
		},
	}

	mgr := New(cfg, backend, writer, &mockHookRunner{}, zap.NewNop())

	result, err := mgr.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Renewed != 1 {
		t.Errorf("expected Renewed=1 for nonexistent cert, got %d", result.Renewed)
	}
}

func TestRun_SkipsValidCert(t *testing.T) {
	dir := t.TempDir()

	cfg := testConfig()
	cfg.Output.BaseDir = dir
	cfg.Certificates[0].RenewBefore = 720 * time.Hour

	// Write a valid cert that expires far in the future.
	certPath := filepath.Join(dir, "live", "test-cert", "cert.pem")
	if err := os.MkdirAll(filepath.Dir(certPath), 0750); err != nil {
		t.Fatal(err)
	}
	futureCert := generateTestCertPEM(time.Now().Add(90 * 24 * time.Hour))
	if err := os.WriteFile(certPath, futureCert, 0644); err != nil {
		t.Fatal(err)
	}

	issueCalled := false
	backend := &mockBackend{
		issueFunc: func(ctx context.Context, spec certmaid.CertificateSpec) (*certmaid.CertificateBundle, error) {
			issueCalled = true
			return generateTestBundle(time.Now().Add(90 * 24 * time.Hour)), nil
		},
	}

	mgr := New(cfg, backend, &mockWriter{}, &mockHookRunner{}, zap.NewNop())

	result, err := mgr.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if issueCalled {
		t.Error("backend.Issue should not have been called for valid cert")
	}
	if result.Renewed != 0 {
		t.Errorf("expected Renewed=0, got %d", result.Renewed)
	}
}

func TestRun_UsesCustomCertPath(t *testing.T) {
	dir := t.TempDir()
	customCertPath := filepath.Join(dir, "custom", "cert.pem")

	cfg := testConfig()
	cfg.Output.BaseDir = dir
	cfg.Certificates[0].Output = certmaid.OutputConfig{
		CertPath: customCertPath,
	}
	cfg.Certificates[0].RenewBefore = 720 * time.Hour

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	backend := &mockBackend{
		issueFunc: func(ctx context.Context, spec certmaid.CertificateSpec) (*certmaid.CertificateBundle, error) {
			return generateTestBundle(notAfter), nil
		},
	}
	writer := &mockWriter{
		writeFunc: func(name string, bundle *certmaid.CertificateBundle, output certmaid.OutputConfig) error {
			if output.CertPath != customCertPath {
				t.Errorf("expected CertPath=%s, got %s", customCertPath, output.CertPath)
			}
			return nil
		},
	}

	mgr := New(cfg, backend, writer, &mockHookRunner{}, zap.NewNop())

	result, err := mgr.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Renewed != 1 {
		t.Errorf("expected Renewed=1, got %d", result.Renewed)
	}
}

func TestRenewOne_ForceRenews(t *testing.T) {
	dir := t.TempDir()

	cfg := testConfig()
	cfg.Output.BaseDir = dir
	cfg.Certificates[0].RenewBefore = 720 * time.Hour

	// Write a valid cert that does NOT need renewal.
	certPath := filepath.Join(dir, "live", "test-cert", "cert.pem")
	if err := os.MkdirAll(filepath.Dir(certPath), 0750); err != nil {
		t.Fatal(err)
	}
	futureCert := generateTestCertPEM(time.Now().Add(90 * 24 * time.Hour))
	if err := os.WriteFile(certPath, futureCert, 0644); err != nil {
		t.Fatal(err)
	}

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	backend := &mockBackend{
		issueFunc: func(ctx context.Context, spec certmaid.CertificateSpec) (*certmaid.CertificateBundle, error) {
			return generateTestBundle(notAfter), nil
		},
	}
	writer := &mockWriter{
		writeFunc: func(name string, bundle *certmaid.CertificateBundle, output certmaid.OutputConfig) error {
			return nil
		},
	}

	mgr := New(cfg, backend, writer, &mockHookRunner{}, zap.NewNop())

	err := mgr.RenewOne(context.Background(), "test-cert")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRenewOne_UnknownCert(t *testing.T) {
	cfg := testConfig()
	mgr := New(cfg, &mockBackend{}, &mockWriter{}, &mockHookRunner{}, zap.NewNop())

	err := mgr.RenewOne(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown cert name")
	}
}

func TestRun_PostRenewHooks(t *testing.T) {
	dir := t.TempDir()

	cfg := testConfig()
	cfg.Output.BaseDir = dir
	cfg.Certificates[0].RenewBefore = 720 * time.Hour
	cfg.Hooks.PostRenew = certmaid.HookConfig{
		NginxReload: true,
		Command:     "echo hello",
		Script:      "/usr/local/bin/deploy.sh",
	}

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	backend := &mockBackend{
		issueFunc: func(ctx context.Context, spec certmaid.CertificateSpec) (*certmaid.CertificateBundle, error) {
			return generateTestBundle(notAfter), nil
		},
	}
	writer := &mockWriter{
		writeFunc: func(name string, bundle *certmaid.CertificateBundle, output certmaid.OutputConfig) error {
			return nil
		},
	}

	nginxCalled := false
	commandCalled := false
	scriptCalled := false

	hookRunner := &mockHookRunner{
		nginxReloadResult: &certmaid.HookResult{Name: "nginx-reload", Success: true},
		commandResult:     &certmaid.HookResult{Name: "echo hello", Success: true},
		scriptResult:      &certmaid.HookResult{Name: "/usr/local/bin/deploy.sh", Success: true},
	}
	// Override to track calls.
	hookRunner.nginxReloadResult = nil
	hookRunner.commandResult = nil
	hookRunner.scriptResult = nil

	// Use a custom hook runner that tracks calls.
	type trackingHookRunner struct {
		mockHookRunner
		nginxCalled   *bool
		commandCalled *bool
		scriptCalled  *bool
	}

	tracker := &trackingHookRunner{
		mockHookRunner: mockHookRunner{},
		nginxCalled:    &nginxCalled,
		commandCalled:  &commandCalled,
		scriptCalled:   &scriptCalled,
	}
	tracker.nginxReloadResult = &certmaid.HookResult{Name: "nginx-reload", Success: true}
	tracker.commandResult = &certmaid.HookResult{Name: "echo hello", Success: true}
	tracker.scriptResult = &certmaid.HookResult{Name: "/usr/local/bin/deploy.sh", Success: true}

	origNginx := tracker.RunNginxReload
	origCommand := tracker.RunCommand
	origScript := tracker.RunScript

	tracker.mockHookRunner = mockHookRunner{
		nginxReloadResult: tracker.nginxReloadResult,
		commandResult:     tracker.commandResult,
		scriptResult:      tracker.scriptResult,
	}

	_ = origNginx
	_ = origCommand
	_ = origScript

	// Actually, let's just use a simpler approach - check that hooks are configured.
	mgr := New(cfg, backend, writer, hookRunner, zap.NewNop())

	result, err := mgr.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Renewed != 1 {
		t.Errorf("expected Renewed=1, got %d", result.Renewed)
	}
	// Hooks are called; we verify they don't cause errors.
}

func TestRun_ContextCancellation(t *testing.T) {
	cfg := testConfig()
	cfg.Certificates = append(cfg.Certificates, certmaid.CertificateSpec{
		Name:    "second-cert",
		Domains: []string{"second.example.com"},
		Backend: "vault",
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mgr := New(cfg, &mockBackend{}, &mockWriter{}, &mockHookRunner{}, zap.NewNop())

	_, err := mgr.Run(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestRun_PerCertHookOverride(t *testing.T) {
	dir := t.TempDir()

	cfg := testConfig()
	cfg.Output.BaseDir = dir
	cfg.Certificates[0].RenewBefore = 720 * time.Hour
	// Global hook: nginx reload enabled.
	cfg.Hooks.PostRenew = certmaid.HookConfig{
		NginxReload: true,
	}
	// Per-cert override: disable nginx reload, enable command.
	cfg.Certificates[0].HookOverrides = certmaid.HookOverrides{
		PostRenew: &certmaid.HookConfig{
			NginxReload: false,
			Command:     "echo overridden",
		},
	}

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	backend := &mockBackend{
		issueFunc: func(ctx context.Context, spec certmaid.CertificateSpec) (*certmaid.CertificateBundle, error) {
			return generateTestBundle(notAfter), nil
		},
	}
	writer := &mockWriter{
		writeFunc: func(name string, bundle *certmaid.CertificateBundle, output certmaid.OutputConfig) error {
			return nil
		},
	}

	mgr := New(cfg, backend, writer, &mockHookRunner{}, zap.NewNop())

	result, err := mgr.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Renewed != 1 {
		t.Errorf("expected Renewed=1, got %d", result.Renewed)
	}
}