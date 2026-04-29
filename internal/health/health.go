// Package health provides certificate health checking logic used by the
// "certmaid health" CLI command.
package health

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/helixzz/certmaid"
	"github.com/helixzz/certmaid/internal/manager"
)

// Status constants for the overall health check result.
const (
	StatusHealthy  = "healthy"
	StatusDegraded = "degraded"
	StatusError    = "error"
)

// Sentinel errors for health check outcomes.
var (
	// ErrCheckFailed is returned when the underlying manager.Status call fails.
	ErrCheckFailed = errors.New("health check failed")

	// ErrNeedsRenewal is the sentinel for degraded health.  The concrete
	// *NeedsRenewalError carries the full HealthResult so callers can inspect
	// individual certificate details.
	ErrNeedsRenewal error = &NeedsRenewalError{}
)

// HealthResult summarises the outcome of a health check run.
type HealthResult struct {
	Status  string       `json:"status"`
	Details []CertHealth `json:"details"`
}

// CertHealth reports the health of a single certificate.
type CertHealth struct {
	Name          string   `json:"name"`
	Domains       []string `json:"domains"`
	DaysRemaining int      `json:"days_remaining"`
	Healthy       bool     `json:"healthy"`
}

// NeedsRenewalError is returned when one or more certificates need renewal.
// It acts as both an error and a carrier for the full HealthResult.
type NeedsRenewalError struct {
	Result *HealthResult
}

func (e *NeedsRenewalError) Error() string {
	return "one or more certificates need renewal"
}

// Is allows errors.Is(err, ErrNeedsRenewal) to match any *NeedsRenewalError.
func (e *NeedsRenewalError) Is(target error) bool {
	_, ok := target.(*NeedsRenewalError)
	return ok
}

// statusChecker is an internal interface satisfied by *manager.Manager.
// It exists purely for testability so tests can inject mocks.
type statusChecker interface {
	Status(ctx context.Context) ([]certmaid.CertificateStatus, error)
}

// Check runs a health check against the given manager and returns a
// HealthResult.  The overall Status is:
//
//	StatusHealthy  – all certificates are healthy
//	StatusDegraded – at least one certificate needs renewal or is expired
//	StatusError    – the manager.Status call itself failed
//
// On degraded health the returned error is a *NeedsRenewalError wrapping the
// result; use errors.Is(err, ErrNeedsRenewal) to detect it.  On a manager
// failure the error wraps ErrCheckFailed.
func Check(ctx context.Context, mgr *manager.Manager) (*HealthResult, error) {
	return check(ctx, mgr)
}

func check(ctx context.Context, sc statusChecker) (*HealthResult, error) {
	statuses, err := sc.Status(ctx)
	if err != nil {
		return &HealthResult{Status: StatusError}, fmt.Errorf("%w: %w", ErrCheckFailed, err)
	}

	details := make([]CertHealth, 0, len(statuses))
	allHealthy := true

	for _, s := range statuses {
		daysRemaining := 0
		if !s.NotAfter.IsZero() {
			daysRemaining = int(time.Until(s.NotAfter).Hours() / 24)
		}

		healthy := !s.NeedsRenew && daysRemaining > 0
		if !healthy {
			allHealthy = false
		}

		details = append(details, CertHealth{
			Name:          s.Name,
			Domains:       s.Domains,
			DaysRemaining: daysRemaining,
			Healthy:       healthy,
		})
	}

	result := &HealthResult{Details: details}

	if allHealthy {
		result.Status = StatusHealthy
		return result, nil
	}

	result.Status = StatusDegraded
	return result, &NeedsRenewalError{Result: result}
}
