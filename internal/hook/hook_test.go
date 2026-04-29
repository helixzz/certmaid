package hook

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	certmaid "github.com/helixzz/certmaid"
)

func TestRunCommand_Echo(t *testing.T) {
	r := NewRunner()
	result := r.RunCommand("echo hello")
	if !result.Success {
		t.Fatalf("expected success, got error: %v", result.Error)
	}
	if result.Name != "echo hello" {
		t.Errorf("expected name 'echo hello', got %q", result.Name)
	}
}

func TestRunCommand_CapturesOutput(t *testing.T) {
	r := NewRunner()
	result := r.RunCommand("echo captured-output")
	if !result.Success {
		t.Fatalf("expected success, got error: %v", result.Error)
	}
	if result.Output != "captured-output" {
		t.Errorf("expected output 'captured-output', got %q", result.Output)
	}
}

func TestRunCommand_Failure(t *testing.T) {
	r := NewRunner()
	result := r.RunCommand("exit 42")
	if result.Success {
		t.Fatal("expected failure, got success")
	}
	if result.Error == nil {
		t.Fatal("expected non-nil error")
	}
}

func TestRunScript_PassesEnvVars(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "print-env")
	content := "#!/bin/sh\necho \"ACTION=$CERTMAID_ACTION\"\necho \"CERT=$CERTMAID_CERT_PATH\"\necho \"KEY=$CERTMAID_KEY_PATH\"\necho \"CHAIN=$CERTMAID_CHAIN_PATH\"\necho \"DOMAINS=$CERTMAID_DOMAINS\"\n"
	if err := os.WriteFile(scriptPath, []byte(content), 0755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}

	r := NewRunner()
	ctx := certmaid.HookContext{
		Action:    "renew",
		CertPath:  "/etc/certs/test.crt",
		KeyPath:   "/etc/certs/test.key",
		ChainPath: "/etc/certs/test-chain.pem",
		Domains:   []string{"example.com", "www.example.com"},
	}
	result := r.RunScript(scriptPath, ctx)

	if !result.Success {
		t.Fatalf("expected success, got error: %v, output: %s", result.Error, result.Output)
	}

	if !strings.Contains(result.Output, "ACTION=renew") {
		t.Errorf("expected ACTION=renew in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "CERT=/etc/certs/test.crt") {
		t.Errorf("expected CERT path in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "KEY=/etc/certs/test.key") {
		t.Errorf("expected KEY path in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "CHAIN=/etc/certs/test-chain.pem") {
		t.Errorf("expected CHAIN path in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "DOMAINS=example.com www.example.com") {
		t.Errorf("expected DOMAINS in output, got: %s", result.Output)
	}
}

func TestRunScript_NonExecutable(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "not-executable")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho nope\n"), 0644); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}

	r := NewRunner()
	ctx := certmaid.HookContext{
		Action: "renew",
	}
	result := r.RunScript(scriptPath, ctx)

	if result.Success {
		t.Fatal("expected failure for non-executable script")
	}
	if result.Error == nil {
		t.Fatal("expected non-nil error")
	}
	if !strings.Contains(result.Error.Error(), "not executable") {
		t.Errorf("expected 'not executable' error, got: %v", result.Error)
	}
}

func TestRunScript_FileNotFound(t *testing.T) {
	r := NewRunner()
	ctx := certmaid.HookContext{
		Action: "renew",
	}
	result := r.RunScript("/nonexistent/script.sh", ctx)

	if result.Success {
		t.Fatal("expected failure for missing script")
	}
	if result.Error == nil {
		t.Fatal("expected non-nil error")
	}
}

// nginx may not be installed; skip unless explicitly opted in.
func TestRunNginxReload_SkipIfNotInstalled(t *testing.T) {
	if os.Getenv("CERTMAID_TEST_NGINX") != "1" {
		t.Skip("skipping nginx test (set CERTMAID_TEST_NGINX=1 to run)")
	}
	r := NewRunner()
	result := r.RunNginxReload()
	t.Logf("nginx result: success=%v name=%s output=%s err=%v", result.Success, result.Name, result.Output, result.Error)
}
