package health

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/helixzz/certmaid"
)

type mockStatusChecker struct {
	statuses []certmaid.CertificateStatus
	err      error
}

func (m *mockStatusChecker) Status(_ context.Context) ([]certmaid.CertificateStatus, error) {
	return m.statuses, m.err
}

func TestCheckAllHealthy(t *testing.T) {
	notAfter := time.Now().Add(30 * 24 * time.Hour)
	mock := &mockStatusChecker{
		statuses: []certmaid.CertificateStatus{
			{
				Name:       "example.com",
				Domains:    []string{"example.com", "www.example.com"},
				NotAfter:   notAfter,
				NeedsRenew: false,
			},
			{
				Name:       "api.example.com",
				Domains:    []string{"api.example.com"},
				NotAfter:   notAfter,
				NeedsRenew: false,
			},
		},
	}

	result, err := check(context.Background(), mock)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Status != StatusHealthy {
		t.Errorf("expected status %q, got %q", StatusHealthy, result.Status)
	}
	if len(result.Details) != 2 {
		t.Fatalf("expected 2 details, got %d", len(result.Details))
	}
	for _, d := range result.Details {
		if !d.Healthy {
			t.Errorf("expected cert %q to be healthy", d.Name)
		}
		if d.DaysRemaining <= 0 {
			t.Errorf("expected cert %q to have positive days remaining, got %d", d.Name, d.DaysRemaining)
		}
	}
}

func TestCheckSomeNeedsRenewal(t *testing.T) {
	notAfter := time.Now().Add(30 * 24 * time.Hour)
	mock := &mockStatusChecker{
		statuses: []certmaid.CertificateStatus{
			{
				Name:       "healthy.example.com",
				Domains:    []string{"healthy.example.com"},
				NotAfter:   notAfter,
				NeedsRenew: false,
			},
			{
				Name:       "expiring.example.com",
				Domains:    []string{"expiring.example.com"},
				NotAfter:   time.Now().Add(5 * 24 * time.Hour),
				NeedsRenew: true,
			},
		},
	}

	result, err := check(context.Background(), mock)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNeedsRenewal) {
		t.Errorf("expected ErrNeedsRenewal, got %v", err)
	}

	renewalErr, ok := err.(*NeedsRenewalError)
	if !ok {
		t.Fatalf("expected *NeedsRenewalError, got %T", err)
	}
	if renewalErr.Result != result {
		t.Error("NeedsRenewalError.Result does not match returned result")
	}

	if result.Status != StatusDegraded {
		t.Errorf("expected status %q, got %q", StatusDegraded, result.Status)
	}
	if len(result.Details) != 2 {
		t.Fatalf("expected 2 details, got %d", len(result.Details))
	}
	if !result.Details[0].Healthy {
		t.Errorf("expected cert %q to be healthy", result.Details[0].Name)
	}
	if result.Details[1].Healthy {
		t.Errorf("expected cert %q to be unhealthy", result.Details[1].Name)
	}
}

func TestCheckAllExpired(t *testing.T) {
	pastDate := time.Now().Add(-30 * 24 * time.Hour)
	mock := &mockStatusChecker{
		statuses: []certmaid.CertificateStatus{
			{
				Name:       "expired-1.example.com",
				Domains:    []string{"expired-1.example.com"},
				NotAfter:   pastDate,
				NeedsRenew: true,
			},
			{
				Name:       "expired-2.example.com",
				Domains:    []string{"expired-2.example.com"},
				NotAfter:   pastDate,
				NeedsRenew: true,
			},
		},
	}

	result, err := check(context.Background(), mock)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNeedsRenewal) {
		t.Errorf("expected ErrNeedsRenewal, got %v", err)
	}
	if result.Status != StatusDegraded {
		t.Errorf("expected status %q, got %q", StatusDegraded, result.Status)
	}
	for _, d := range result.Details {
		if d.Healthy {
			t.Errorf("expected cert %q to be unhealthy", d.Name)
		}
		if d.DaysRemaining >= 0 {
			t.Errorf("expected cert %q to have negative days remaining, got %d", d.Name, d.DaysRemaining)
		}
	}
}

func TestCheckManagerFails(t *testing.T) {
	mock := &mockStatusChecker{
		err: errors.New("connection refused"),
	}

	result, err := check(context.Background(), mock)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrCheckFailed) {
		t.Errorf("expected ErrCheckFailed, got %v", err)
	}
	if result.Status != StatusError {
		t.Errorf("expected status %q, got %q", StatusError, result.Status)
	}
	if result.Details != nil {
		t.Errorf("expected nil details on error, got %v", result.Details)
	}
}

func TestCheckEmptyCertificates(t *testing.T) {
	mock := &mockStatusChecker{
		statuses: []certmaid.CertificateStatus{},
	}

	result, err := check(context.Background(), mock)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Status != StatusHealthy {
		t.Errorf("expected status %q for empty certs, got %q", StatusHealthy, result.Status)
	}
	if len(result.Details) != 0 {
		t.Errorf("expected 0 details, got %d", len(result.Details))
	}
}

func TestCheckDaysRemainingCalculation(t *testing.T) {
	notAfter := time.Now().Add(72 * time.Hour)
	mock := &mockStatusChecker{
		statuses: []certmaid.CertificateStatus{
			{
				Name:       "three-days.example.com",
				Domains:    []string{"three-days.example.com"},
				NotAfter:   notAfter,
				NeedsRenew: false,
			},
		},
	}

	result, err := check(context.Background(), mock)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	days := result.Details[0].DaysRemaining
	if days < 2 || days > 3 {
		t.Errorf("expected DaysRemaining around 3, got %d", days)
	}
}

func TestCheckZeroNotAfter(t *testing.T) {
	mock := &mockStatusChecker{
		statuses: []certmaid.CertificateStatus{
			{
				Name:       "missing.example.com",
				Domains:    []string{"missing.example.com"},
				NotAfter:   time.Time{},
				NeedsRenew: true,
			},
		},
	}

	result, err := check(context.Background(), mock)
	if err == nil {
		t.Fatal("expected error for zero NotAfter with NeedsRenew")
	}
	if result.Status != StatusDegraded {
		t.Errorf("expected status %q, got %q", StatusDegraded, result.Status)
	}
	if result.Details[0].DaysRemaining != 0 {
		t.Errorf("expected DaysRemaining 0 for zero NotAfter, got %d", result.Details[0].DaysRemaining)
	}
}
