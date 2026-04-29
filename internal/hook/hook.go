// Package hook implements the HookRunner interface for executing
// post-renewal hooks: Nginx reload, custom commands, and scripts.
package hook

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	certmaid "github.com/helixzz/certmaid"
)

// Runner executes post-renewal hooks.
type Runner struct{}

// NewRunner creates a new Runner.
func NewRunner() *Runner {
	return &Runner{}
}

// RunNginxReload tests the Nginx configuration and reloads if valid.
func (r *Runner) RunNginxReload() *certmaid.HookResult {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	testCmd := exec.CommandContext(ctx, "nginx", "-t", "-q")
	var testStderr bytes.Buffer
	testCmd.Stderr = &testStderr

	if err := testCmd.Run(); err != nil {
		return &certmaid.HookResult{
			Name:    "nginx-test",
			Success: false,
			Output:  strings.TrimSpace(testStderr.String()),
			Error:   fmt.Errorf("nginx config test failed: %w", err),
		}
	}

	reloadCtx, reloadCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer reloadCancel()

	reloadCmd := exec.CommandContext(reloadCtx, "nginx", "-s", "reload")
	var reloadStderr bytes.Buffer
	reloadCmd.Stderr = &reloadStderr

	if err := reloadCmd.Run(); err != nil {
		return &certmaid.HookResult{
			Name:    "nginx-reload",
			Success: false,
			Output:  strings.TrimSpace(reloadStderr.String()),
			Error:   fmt.Errorf("nginx reload failed: %w", err),
		}
	}

	return &certmaid.HookResult{
		Name:    "nginx-reload",
		Success: true,
		Output:  "nginx reloaded successfully",
	}
}

// RunCommand executes a shell command and returns the result.
// The command is run via /bin/sh -c with a 60-second timeout.
func (r *Runner) RunCommand(cmd string) *certmaid.HookResult {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
	var output bytes.Buffer
	c.Stdout = &output
	c.Stderr = &output

	err := c.Run()
	out := strings.TrimSpace(output.String())

	if err != nil {
		return &certmaid.HookResult{
			Name:    cmd,
			Success: false,
			Output:  out,
			Error:   fmt.Errorf("command failed: %w", err),
		}
	}

	return &certmaid.HookResult{
		Name:    cmd,
		Success: true,
		Output:  out,
	}
}

// RunScript executes a script file with environment variables from the
// HookContext. The script must be executable. Timeout is 120 seconds.
func (r *Runner) RunScript(path string, ctx certmaid.HookContext) *certmaid.HookResult {
	info, err := os.Stat(path)
	if err != nil {
		return &certmaid.HookResult{
			Name:    path,
			Success: false,
			Output:  "",
			Error:   fmt.Errorf("cannot stat script: %w", err),
		}
	}

	if info.Mode()&0111 == 0 {
		return &certmaid.HookResult{
			Name:    path,
			Success: false,
			Output:  "",
			Error:   fmt.Errorf("script is not executable: %s", path),
		}
	}

	execCtx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	c := exec.CommandContext(execCtx, path)
	c.Env = append(os.Environ(),
		"CERTMAID_ACTION="+ctx.Action,
		"CERTMAID_CERT_PATH="+ctx.CertPath,
		"CERTMAID_KEY_PATH="+ctx.KeyPath,
		"CERTMAID_CHAIN_PATH="+ctx.ChainPath,
		"CERTMAID_DOMAINS="+strings.Join(ctx.Domains, " "),
	)

	var output bytes.Buffer
	c.Stdout = &output
	c.Stderr = &output

	err = c.Run()
	out := strings.TrimSpace(output.String())

	if err != nil {
		return &certmaid.HookResult{
			Name:    path,
			Success: false,
			Output:  out,
			Error:   fmt.Errorf("script failed: %w", err),
		}
	}

	return &certmaid.HookResult{
		Name:    path,
		Success: true,
		Output:  out,
	}
}

// Ensure Runner implements certmaid.HookRunner.
var _ certmaid.HookRunner = (*Runner)(nil)
