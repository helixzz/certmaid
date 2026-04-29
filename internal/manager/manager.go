// Package manager provides the orchestration layer that ties config, backend,
// writer, and hook together to run full certificate lifecycle checks and renewals.
package manager

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/helixzz/certmaid"
	"github.com/helixzz/certmaid/internal/config"
	"go.uber.org/zap"
)

// Manager orchestrates certificate lifecycle checks and renewals.
type Manager struct {
	config     *config.Config
	backend    certmaid.Backend
	writer     certmaid.Writer
	hookRunner certmaid.HookRunner
	logger     *zap.Logger
}

// RunResult summarizes the outcome of a Run operation.
type RunResult struct {
	Total   int
	Renewed int
	Failed  int
	Results []CertResult
}

// CertResult captures the outcome for a single certificate during Run.
type CertResult struct {
	Name    string
	Renewed bool
	Error   string
}

// New creates a new Manager with the given dependencies.
func New(cfg *config.Config, backend certmaid.Backend, writer certmaid.Writer, hookRunner certmaid.HookRunner, logger *zap.Logger) *Manager {
	return &Manager{
		config:     cfg,
		backend:    backend,
		writer:     writer,
		hookRunner: hookRunner,
		logger:     logger,
	}
}

// Run iterates all certificate specs, checks expiration, and renews certificates
// that are expired or approaching expiration. It returns a summary of the run.
func (m *Manager) Run(ctx context.Context) (*RunResult, error) {
	result := &RunResult{
		Total:   len(m.config.Certificates),
		Results: make([]CertResult, 0, len(m.config.Certificates)),
	}

	for _, spec := range m.config.Certificates {
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("context cancelled during run: %w", err)
		}

		certResult := m.processCert(ctx, spec)
		result.Results = append(result.Results, certResult)
		if certResult.Renewed {
			result.Renewed++
		}
		if certResult.Error != "" {
			result.Failed++
		}
	}

	return result, nil
}

// processCert handles a single certificate spec: checks if renewal is needed,
// issues a new certificate, writes it, and runs post-renew hooks.
func (m *Manager) processCert(ctx context.Context, spec certmaid.CertificateSpec) CertResult {
	logger := m.logger.With(zap.String("cert", spec.Name))

	needsRenew, err := m.needsRenewal(spec)
	if err != nil {
		logger.Warn("Failed to check certificate, will attempt renewal", zap.Error(err))
		needsRenew = true
	}

	if !needsRenew {
		logger.Debug("Certificate does not need renewal")
		return CertResult{Name: spec.Name, Renewed: false}
	}

	logger.Info("Certificate needs renewal, issuing new certificate")

	bundle, err := m.backend.Issue(ctx, spec)
	if err != nil {
		errMsg := fmt.Sprintf("issuing certificate: %v", err)
		logger.Error(errMsg)
		return CertResult{Name: spec.Name, Renewed: false, Error: errMsg}
	}

	if err := m.writer.Write(spec.Name, bundle, spec.Output); err != nil {
		errMsg := fmt.Sprintf("writing certificate: %v", err)
		logger.Error(errMsg)
		return CertResult{Name: spec.Name, Renewed: false, Error: errMsg}
	}

	logger.Info("Certificate renewed successfully", zap.Time("not_after", bundle.NotAfter))

	m.runPostRenewHooks(spec, bundle)

	return CertResult{Name: spec.Name, Renewed: true}
}

// needsRenewal checks whether a certificate needs to be renewed by reading the
// on-disk certificate file and comparing its NotAfter with the renewal threshold.
func (m *Manager) needsRenewal(spec certmaid.CertificateSpec) (bool, error) {
	certPath := m.resolveCertPath(spec)

	data, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return true, fmt.Errorf("reading cert file %q: %w", certPath, err)
	}

	notAfter, err := extractNotAfter(data)
	if err != nil {
		return true, fmt.Errorf("parsing cert %q: %w", certPath, err)
	}

	renewBefore := m.resolveRenewBefore(spec)
	if time.Until(notAfter) < renewBefore {
		return true, nil
	}

	return false, nil
}

// resolveRenewBefore returns the effective renew_before duration for a spec.
// Per-certificate value takes precedence over the global default.
func (m *Manager) resolveRenewBefore(spec certmaid.CertificateSpec) time.Duration {
	if spec.RenewBefore > 0 {
		return spec.RenewBefore
	}
	return m.config.Defaults.RenewBefore
}

// resolveCertPath returns the on-disk path for a certificate's PEM file.
// If a custom path is configured in the spec's output, it is used directly.
// Otherwise the path is derived from the global base directory and live structure.
func (m *Manager) resolveCertPath(spec certmaid.CertificateSpec) string {
	if spec.Output.CertPath != "" {
		return spec.Output.CertPath
	}
	return filepath.Join(m.config.Output.BaseDir, "live", spec.Name, "cert.pem")
}

// resolveKeyPath returns the on-disk path for a certificate's private key file.
func (m *Manager) resolveKeyPath(spec certmaid.CertificateSpec) string {
	if spec.Output.KeyPath != "" {
		return spec.Output.KeyPath
	}
	return filepath.Join(m.config.Output.BaseDir, "live", spec.Name, "key.pem")
}

// resolveChainPath returns the on-disk path for a certificate's chain file.
func (m *Manager) resolveChainPath(spec certmaid.CertificateSpec) string {
	if spec.Output.ChainPath != "" {
		return spec.Output.ChainPath
	}
	return filepath.Join(m.config.Output.BaseDir, "live", spec.Name, "chain.pem")
}

// resolveEffectiveHook returns the effective post-renew hook configuration,
// preferring per-certificate overrides over the global configuration.
func (m *Manager) resolveEffectiveHook(spec certmaid.CertificateSpec) certmaid.HookConfig {
	if spec.HookOverrides.PostRenew != nil {
		return *spec.HookOverrides.PostRenew
	}
	return m.config.Hooks.PostRenew
}

// runPostRenewHooks executes all configured post-renewal hooks for a certificate.
func (m *Manager) runPostRenewHooks(spec certmaid.CertificateSpec, bundle *certmaid.CertificateBundle) {
	hookCfg := m.resolveEffectiveHook(spec)
	hookCtx := certmaid.HookContext{
		Action:    "renew",
		CertPath:  m.resolveCertPath(spec),
		KeyPath:   m.resolveKeyPath(spec),
		ChainPath: m.resolveChainPath(spec),
		Domains:   spec.Domains,
	}

	if hookCfg.NginxReload {
		m.logger.Info("Running nginx reload hook", zap.String("cert", spec.Name))
		result := m.hookRunner.RunNginxReload()
		if !result.Success {
			m.logger.Warn("Nginx reload hook failed",
				zap.String("cert", spec.Name),
				zap.Error(result.Error),
				zap.String("output", result.Output),
			)
		}
	}

	if hookCfg.Command != "" {
		m.logger.Info("Running post-renew command hook", zap.String("cert", spec.Name), zap.String("command", hookCfg.Command))
		result := m.hookRunner.RunCommand(hookCfg.Command)
		if !result.Success {
			m.logger.Warn("Post-renew command hook failed",
				zap.String("cert", spec.Name),
				zap.Error(result.Error),
				zap.String("output", result.Output),
			)
		}
	}

	if hookCfg.Script != "" {
		m.logger.Info("Running post-renew script hook", zap.String("cert", spec.Name), zap.String("script", hookCfg.Script))
		result := m.hookRunner.RunScript(hookCfg.Script, hookCtx)
		if !result.Success {
			m.logger.Warn("Post-renew script hook failed",
				zap.String("cert", spec.Name),
				zap.Error(result.Error),
				zap.String("output", result.Output),
			)
		}
	}
}

// Status checks all configured certificates and reports their current state
// without performing any renewals.
func (m *Manager) Status(ctx context.Context) ([]certmaid.CertificateStatus, error) {
	statuses := make([]certmaid.CertificateStatus, 0, len(m.config.Certificates))

	for _, spec := range m.config.Certificates {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("context cancelled during status check: %w", err)
		}

		status := m.certStatus(spec)
		statuses = append(statuses, status)
	}

	return statuses, nil
}

// certStatus builds a CertificateStatus for a single spec.
func (m *Manager) certStatus(spec certmaid.CertificateSpec) certmaid.CertificateStatus {
	certPath := m.resolveCertPath(spec)
	keyPath := m.resolveKeyPath(spec)
	renewBefore := m.resolveRenewBefore(spec)

	status := certmaid.CertificateStatus{
		Name:        spec.Name,
		Domains:     spec.Domains,
		RenewBefore: renewBefore,
		CertPath:    certPath,
		KeyPath:     keyPath,
	}

	data, err := os.ReadFile(certPath)
	if err != nil {
		status.NeedsRenew = true
		return status
	}

	notAfter, err := extractNotAfter(data)
	if err != nil {
		status.NeedsRenew = true
		return status
	}

	status.NotAfter = notAfter
	status.NeedsRenew = time.Until(notAfter) < renewBefore

	m.checkAlert(status, spec)

	return status
}

// RenewOne force-renews a single certificate by name, regardless of its
// current expiration status.
func (m *Manager) RenewOne(ctx context.Context, name string) error {
	for _, spec := range m.config.Certificates {
		if spec.Name == name {
			result := m.processCert(ctx, spec)
			if result.Error != "" {
				return fmt.Errorf("renewing %q: %s", name, result.Error)
			}
			return nil
		}
	}
	return fmt.Errorf("certificate %q not found in configuration", name)
}

// extractNotAfter parses a PEM-encoded certificate and returns its NotAfter time.
func extractNotAfter(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing certificate: %w", err)
	}

	return cert.NotAfter, nil
}

// checkAlert logs a warning if the certificate is approaching expiry but has not
// yet entered the renewal window. This provides early visibility before auto-renewal.
func (m *Manager) checkAlert(status certmaid.CertificateStatus, spec certmaid.CertificateSpec) {
	if status.NotAfter.IsZero() {
		return // no cert file, nothing to alert on
	}

	alertBefore := spec.AlertBefore
	if alertBefore == 0 {
		alertBefore = m.config.Defaults.AlertBefore
	}
	renewBefore := spec.RenewBefore
	if renewBefore == 0 {
		renewBefore = m.config.Defaults.RenewBefore
	}

	// Only alert if alert_before is meaningful (longer than renew_before)
	// and the cert is within the alert window but NOT yet in the renew window
	daysRemaining := int(time.Until(status.NotAfter).Hours() / 24)

	if alertBefore > 0 && alertBefore > renewBefore {
		remaining := time.Until(status.NotAfter)
		if remaining < alertBefore && !status.NeedsRenew {
			m.logger.Warn("certificate approaching expiry",
				zap.String("name", spec.Name),
				zap.Int("days_remaining", daysRemaining),
				zap.Time("not_after", status.NotAfter),
			)
		}
	}
}