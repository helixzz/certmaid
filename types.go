package certmaid

import (
	"context"
	"crypto"
	"time"
)

// CertificateSpec defines a single certificate to manage.
type CertificateSpec struct {
	Name      string   `mapstructure:"name" yaml:"name"`
	Domains   []string `mapstructure:"domains" yaml:"domains"`
	Backend   string   `mapstructure:"backend" yaml:"backend"` // "vault"

	RenewBefore    time.Duration `mapstructure:"renew_before" yaml:"renew_before"`
	KeyType        string        `mapstructure:"key_type" yaml:"key_type"` // RSA2048, ECDSA256, ECDSA384

	Output         OutputConfig         `mapstructure:"output" yaml:"output"`
	BackendConfig  BackendOverrideConfig `mapstructure:"backend_config" yaml:"backend_config"`
	HookOverrides  HookOverrides         `mapstructure:"hooks" yaml:"hooks"`
}

// OutputConfig defines where to write certificate files.
type OutputConfig struct {
	CertPath  string `mapstructure:"cert_path" yaml:"cert_path"`
	KeyPath   string `mapstructure:"key_path" yaml:"key_path"`
	ChainPath string `mapstructure:"chain_path" yaml:"chain_path"`
}

// BackendOverrideConfig allows per-certificate backend overrides.
type BackendOverrideConfig struct {
	Vault *VaultOverride `mapstructure:"vault" yaml:"vault"`
}

// VaultOverride allows overriding Vault PKI settings per certificate.
type VaultOverride struct {
	PKI PKIOverride `mapstructure:"pki" yaml:"pki"`
}

// PKIOverride overrides Vault PKI mount path and role.
type PKIOverride struct {
	MountPath string `mapstructure:"mount_path" yaml:"mount_path"`
	Role      string `mapstructure:"role" yaml:"role"`
}

// HookConfig defines a hook that runs before or after certificate renewal.
type HookConfig struct {
	NginxReload     bool   `mapstructure:"nginx_reload" yaml:"nginx_reload"`
	NginxConfigTest bool   `mapstructure:"nginx_config_test" yaml:"nginx_config_test"`
	Command         string `mapstructure:"command" yaml:"command"`
	Script          string `mapstructure:"script" yaml:"script"`
}

// HookOverrides allows per-certificate hook configuration.
type HookOverrides struct {
	PostRenew *HookConfig `mapstructure:"post_renew" yaml:"post_renew"`
}

// CertificateBundle holds a newly issued certificate and its key material.
type CertificateBundle struct {
	Certificate []byte    // PEM-encoded leaf certificate
	PrivateKey  []byte    // PEM-encoded private key
	IssuingCA   []byte    // PEM-encoded issuing CA certificate
	CAChain     [][]byte  // PEM-encoded full CA chain
	Domains     []string  // SANs covered by this certificate
	NotAfter    time.Time // Expiration time
}

// CertificateStatus reports the current state of a managed certificate.
type CertificateStatus struct {
	Name        string
	Domains     []string
	NotAfter    time.Time
	RenewBefore time.Duration
	NeedsRenew  bool
	CertPath    string
	KeyPath     string
}

// Backend is the interface for CA backends that issue certificates.
type Backend interface {
	Issue(ctx context.Context, spec CertificateSpec) (*CertificateBundle, error)
}

// Writer handles persisting certificate material to disk atomically.
type Writer interface {
	Write(name string, bundle *CertificateBundle, output OutputConfig) error
}

// HookResult captures the outcome of a hook execution.
type HookResult struct {
	Name    string
	Success bool
	Output  string
	Error   error
}

// HookContext provides metadata to hook scripts via environment variables.
type HookContext struct {
	Action      string   // "renew", "deploy"
	CertPath    string
	KeyPath     string
	ChainPath   string
	Domains     []string
}

// HookRunner executes post-renewal hooks (Nginx reload, custom commands, scripts).
type HookRunner interface {
	RunNginxReload() *HookResult
	RunCommand(cmd string) *HookResult
	RunScript(path string, ctx HookContext) *HookResult
}

// KeyAlgorithm represents supported private key algorithms.
type KeyAlgorithm string

const (
	RSA2048 KeyAlgorithm = "RSA2048"
	RSA4096 KeyAlgorithm = "RSA4096"
	ECDSA256 KeyAlgorithm = "ECDSA256"
	ECDSA384 KeyAlgorithm = "ECDSA384"
)

// ToCryptoKeyType converts a KeyAlgorithm to the crypto library constants.
func (k KeyAlgorithm) ToCryptoKeyType() (crypto.PublicKey, error) {
	switch k {
	case RSA2048, RSA4096:
		return crypto.PublicKey(nil), nil // will be handled as RSA
	case ECDSA256, ECDSA384:
		return crypto.PublicKey(nil), nil // will be handled as ECDSA
	default:
		return nil, nil
	}
}
