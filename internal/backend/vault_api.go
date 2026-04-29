package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"

	certmaid "github.com/helixzz/certmaid"
)

// VaultAPIBackend issues certificates by calling the Vault PKI API directly.
type VaultAPIBackend struct {
	vaultClient *api.Client
	mountPath   string
	role        string
}

// NewVaultAPIBackend creates a new VaultAPIBackend connected to the given address.
func NewVaultAPIBackend(address, mountPath, role string) (*VaultAPIBackend, error) {
	cfg := api.DefaultConfig()
	if cfg.Error != nil {
		return nil, fmt.Errorf("creating vault default config: %w", cfg.Error)
	}
	cfg.Address = address

	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}

	return &VaultAPIBackend{
		vaultClient: client,
		mountPath:   mountPath,
		role:        role,
	}, nil
}

// SetToken sets the Vault token directly on the underlying client.
func (v *VaultAPIBackend) SetToken(token string) {
	v.vaultClient.SetToken(token)
}

// LoginWithAppRole authenticates to Vault using the AppRole auth method.
func (v *VaultAPIBackend) LoginWithAppRole(roleID, secretID string) error {
	secret, err := v.vaultClient.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return fmt.Errorf("approle login: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("approle login: no auth returned")
	}

	v.vaultClient.SetToken(secret.Auth.ClientToken)
	return nil
}

// LoginWithCert authenticates to Vault using TLS client certificate auth.
func (v *VaultAPIBackend) LoginWithCert(certFile, keyFile, roleName string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("loading client cert and key: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if err := v.setClientTLS(tlsConfig); err != nil {
		return fmt.Errorf("configuring TLS for cert auth: %w", err)
	}

	secret, err := v.vaultClient.Logical().Write("auth/cert/login", map[string]interface{}{
		"name": roleName,
	})
	if err != nil {
		return fmt.Errorf("cert login: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("cert login: no auth returned")
	}

	v.vaultClient.SetToken(secret.Auth.ClientToken)
	return nil
}

// setClientTLS configures the Vault client's HTTP transport with the given TLS config.
func (v *VaultAPIBackend) setClientTLS(tlsConfig *tls.Config) error {
	transport, ok := v.vaultClient.CloneConfig().HttpClient.Transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("vault client transport is not *http.Transport")
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.Certificates = tlsConfig.Certificates
	transport.TLSClientConfig.MinVersion = tlsConfig.MinVersion
	return nil
}

// Issue obtains a certificate from the Vault PKI API directly.
func (v *VaultAPIBackend) Issue(ctx context.Context, spec certmaid.CertificateSpec) (*certmaid.CertificateBundle, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled before issuing certificate %q: %w", spec.Name, err)
	}

	if len(spec.Domains) == 0 {
		return nil, fmt.Errorf("certificate spec %q has no domains", spec.Name)
	}

	ttl := "720h"
	if spec.RenewBefore > 0 {
		ttl = spec.RenewBefore.String()
	}

	altNames := ""
	if len(spec.Domains) > 1 {
		altNames = strings.Join(spec.Domains[1:], ",")
	}

	path := fmt.Sprintf("%s/issue/%s", strings.TrimRight(v.mountPath, "/"), v.role)
	secret, err := v.vaultClient.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"common_name": spec.Domains[0],
		"alt_names":   altNames,
		"ttl":         ttl,
	})
	if err != nil {
		return nil, fmt.Errorf("issuing certificate for %q: %w", spec.Name, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("issuing certificate for %q: empty response from Vault", spec.Name)
	}

	certPEM, err := getStringField(secret.Data, "certificate")
	if err != nil {
		return nil, fmt.Errorf("issuing certificate for %q: %w", spec.Name, err)
	}

	keyPEM, err := getStringField(secret.Data, "private_key")
	if err != nil {
		return nil, fmt.Errorf("issuing certificate for %q: %w", spec.Name, err)
	}

	issuingCA, err := getStringField(secret.Data, "issuing_ca")
	if err != nil {
		return nil, fmt.Errorf("issuing certificate for %q: %w", spec.Name, err)
	}

	caChain, err := parseCAChain(secret.Data["ca_chain"])
	if err != nil {
		return nil, fmt.Errorf("issuing certificate for %q: parsing ca_chain: %w", spec.Name, err)
	}

	notAfter, err := parseExpiration(secret.Data["expiration"])
	if err != nil {
		return nil, fmt.Errorf("issuing certificate for %q: parsing expiration: %w", spec.Name, err)
	}

	return &certmaid.CertificateBundle{
		Certificate: []byte(certPEM),
		PrivateKey:  []byte(keyPEM),
		IssuingCA:   []byte(issuingCA),
		CAChain:     caChain,
		Domains:     spec.Domains,
		NotAfter:    notAfter,
	}, nil
}

// getStringField extracts a string value from the Vault response data map.
func getStringField(data map[string]interface{}, key string) (string, error) {
	val, ok := data[key]
	if !ok {
		return "", fmt.Errorf("missing field %q in response", key)
	}
	s, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("field %q is not a string (got %T)", key, val)
	}
	return s, nil
}

// parseCAChain converts the ca_chain field from Vault's response into [][]byte.
func parseCAChain(raw interface{}) ([][]byte, error) {
	if raw == nil {
		return nil, nil
	}

	chain, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("ca_chain is not an array (got %T)", raw)
	}

	var result [][]byte
	for i, item := range chain {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("ca_chain[%d] is not a string (got %T)", i, item)
		}
		result = append(result, []byte(s))
	}
	return result, nil
}

// parseExpiration converts the expiration field from Vault's response to time.Time.
// Vault returns expiration as a Unix timestamp (int64 or json.Number).
func parseExpiration(raw interface{}) (time.Time, error) {
	if raw == nil {
		return time.Time{}, fmt.Errorf("expiration field is nil")
	}

	var unixSec int64
	switch v := raw.(type) {
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return time.Time{}, fmt.Errorf("expiration is not a valid integer: %w", err)
		}
		unixSec = n
	case float64:
		unixSec = int64(v)
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("expiration string %q is not a valid integer: %w", v, err)
		}
		unixSec = n
	default:
		return time.Time{}, fmt.Errorf("expiration has unexpected type %T", raw)
	}

	if unixSec <= 0 {
		return time.Time{}, fmt.Errorf("expiration timestamp %d is invalid", unixSec)
	}

	return time.Unix(unixSec, 0), nil
}

// extractNotAfterFromPEM parses a PEM-encoded certificate and returns its NotAfter time.
func extractNotAfterFromPEM(certPEM []byte) (time.Time, error) {
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