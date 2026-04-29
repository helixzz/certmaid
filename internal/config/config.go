// Package config provides configuration loading and validation for certmaid.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/helixzz/certmaid"
	"github.com/spf13/viper"
)

// Config is the top-level configuration for certmaid.
type Config struct {
	Defaults     DefaultsConfig            `mapstructure:"defaults"`
	Backends     BackendsConfig            `mapstructure:"backends"`
	Output       GlobalOutputConfig        `mapstructure:"output"`
	Hooks        HooksConfig               `mapstructure:"hooks"`
	Logging      LoggingConfig             `mapstructure:"logging"`
	Certificates []certmaid.CertificateSpec `mapstructure:"certificates"`
}

// DefaultsConfig holds global default values for certificate management.
type DefaultsConfig struct {
	RenewBefore   time.Duration `mapstructure:"renew_before"`
	CheckInterval time.Duration `mapstructure:"check_interval"`
	KeyType       string        `mapstructure:"key_type"`
	KeyAlgorithm  string        `mapstructure:"key_algorithm"`
	Challenge     string        `mapstructure:"challenge"`
	CertDirMode   os.FileMode   `mapstructure:"cert_dir_mode"`
	CertFileMode  os.FileMode   `mapstructure:"cert_file_mode"`
}

// BackendsConfig holds CA backend configurations.
type BackendsConfig struct {
	Vault VaultConfig `mapstructure:"vault"`
}

// VaultConfig holds HashiCorp Vault backend configuration.
type VaultConfig struct {
	ACME ACMEConfig     `mapstructure:"acme"`
	API  VaultAPIConfig `mapstructure:"api"`
}

// ACMEConfig holds ACME-specific configuration for Vault.
type ACMEConfig struct {
	Enabled      bool      `mapstructure:"enabled"`
	DirectoryURL string    `mapstructure:"directory_url"`
	EAB          EABConfig `mapstructure:"eab"`
}

// EABConfig holds External Account Binding credentials for ACME.
type EABConfig struct {
	KID     string `mapstructure:"kid"`
	HMACKey string `mapstructure:"hmac_key"`
}

// VaultAPIConfig holds configuration for the Vault API direct connection backend.
type VaultAPIConfig struct {
	Enabled bool          `mapstructure:"enabled"`
	Address string        `mapstructure:"address"`
	Auth    APIAuthConfig `mapstructure:"auth"`
	PKI     PKIConfig     `mapstructure:"pki"`
	TLS     TLSConfig     `mapstructure:"tls"`
}

// APIAuthConfig holds authentication configuration for the Vault API backend.
type APIAuthConfig struct {
	TokenFile string        `mapstructure:"token_file"`
	AppRole   AppRoleConfig `mapstructure:"approle"`
	TLSCert   TLSCertConfig `mapstructure:"tls_cert"`
}

// AppRoleConfig holds AppRole authentication configuration.
type AppRoleConfig struct {
	RoleIDFile   string `mapstructure:"role_id_file"`
	SecretIDFile string `mapstructure:"secret_id_file"`
}

// TLSCertConfig holds TLS client certificate authentication configuration.
type TLSCertConfig struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
	RoleName string `mapstructure:"role_name"`
}

// PKIConfig holds Vault PKI mount and role configuration.
type PKIConfig struct {
	MountPath string `mapstructure:"mount_path"`
	Role      string `mapstructure:"role"`
}

// TLSConfig holds TLS connection configuration for the Vault API backend.
type TLSConfig struct {
	CACertFile         string `mapstructure:"ca_cert_file"`
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`
}

// GlobalOutputConfig holds global output path configuration.
type GlobalOutputConfig struct {
	BaseDir string `mapstructure:"base_dir"`
}

// HooksConfig holds pre- and post-renewal hook configurations.
type HooksConfig struct {
	PreRenew  certmaid.HookConfig `mapstructure:"pre_renew"`
	PostRenew certmaid.HookConfig `mapstructure:"post_renew"`
}

// LoggingConfig holds logging configuration.
type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	File   string `mapstructure:"file"`
}

// Load reads a YAML config file at the given path, applies defaults, validates,
// and returns a fully populated Config.
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	// Apply defaults before reading the file so they take effect when keys are absent.
	v.SetDefault("defaults.renew_before", "720h")
	v.SetDefault("defaults.key_type", "RSA2048")
	v.SetDefault("defaults.key_algorithm", "rsa")
	v.SetDefault("defaults.cert_dir_mode", 0750)
	v.SetDefault("defaults.cert_file_mode", 0640)
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg, viperDecoderOptions()...); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// viperDecoderOptions returns decoder config options that handle
// time.Duration strings and weakly-typed numeric conversions (e.g. octal file modes).
func viperDecoderOptions() []viper.DecoderConfigOption {
	return []viper.DecoderConfigOption{
		func(dc *mapstructure.DecoderConfig) {
			dc.DecodeHook = mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				mapstructure.StringToSliceHookFunc(","),
			)
			dc.WeaklyTypedInput = true
		},
	}
}

// validate checks that the configuration is semantically valid.
func (c *Config) validate() error {
	if len(c.Certificates) == 0 {
		return fmt.Errorf("at least one certificate must be defined")
	}

	for i, cert := range c.Certificates {
		prefix := fmt.Sprintf("certificates[%d]", i)
		if cert.Name != "" {
			prefix = fmt.Sprintf("certificates[%d] (%s)", i, cert.Name)
		}

		if cert.Name == "" {
			return fmt.Errorf("%s: name is required", prefix)
		}
		if len(cert.Domains) == 0 {
			return fmt.Errorf("%s: at least one domain is required", prefix)
		}
		if cert.Backend == "" {
			return fmt.Errorf("%s: backend is required", prefix)
		}
		if cert.Backend != "vault" {
			return fmt.Errorf("%s: unsupported backend %q, only \"vault\" is supported", prefix, cert.Backend)
		}
	}

	return nil
}
