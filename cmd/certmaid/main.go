package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/helixzz/certmaid/internal/backend"
	"github.com/helixzz/certmaid/internal/config"
	"github.com/helixzz/certmaid/internal/hook"
	"github.com/helixzz/certmaid/internal/manager"
	"github.com/helixzz/certmaid/internal/systemd"
	"github.com/helixzz/certmaid/internal/writer"
)

var version = "dev"

func main() {
	var cfgPath string
	var dryRun bool
	var logLevel string

	rootCmd := &cobra.Command{
		Use:   "certmaid",
		Short: "Automated SSL certificate lifecycle management for enterprise CAs",
	}

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Check all certificates and renew those nearing expiration",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := newLogger(logLevel)
			defer logger.Sync()

			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			logger.Info("certmaid starting",
				zap.Int("certificates", len(cfg.Certificates)),
				zap.Bool("dry_run", dryRun),
			)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go func() {
				sigCh := make(chan os.Signal, 1)
				signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
				<-sigCh
				logger.Info("received shutdown signal")
				cancel()
			}()

			mgr, err := buildManager(cfg, logger)
			if err != nil {
				return fmt.Errorf("building manager: %w", err)
			}

			if dryRun {
				logger.Info("dry-run mode: checking status without renewal")
				statuses, err := mgr.Status(ctx)
				if err != nil {
					return fmt.Errorf("checking status: %w", err)
				}
				for _, s := range statuses {
					if s.NeedsRenew {
						logger.Info("would renew certificate",
							zap.String("name", s.Name),
							zap.Time("not_after", s.NotAfter),
						)
					} else {
						logger.Info("certificate is valid",
							zap.String("name", s.Name),
							zap.Time("not_after", s.NotAfter),
						)
					}
				}
				return nil
			}

			result, err := mgr.Run(ctx)
			if err != nil {
				return fmt.Errorf("running renewal: %w", err)
			}

			logger.Info("renewal complete",
				zap.Int("total", result.Total),
				zap.Int("renewed", result.Renewed),
				zap.Int("failed", result.Failed),
			)

			for _, r := range result.Results {
				if r.Error != "" {
					logger.Error("certificate renewal failed",
						zap.String("name", r.Name),
						zap.String("error", r.Error),
					)
				}
			}

			if result.Failed > 0 {
				return fmt.Errorf("%d of %d certificates failed renewal", result.Failed, result.Total)
			}
			return nil
		},
	}
	runCmd.Flags().StringVarP(&cfgPath, "config", "c", "/etc/certmaid/config.yaml", "config file path")
	runCmd.Flags().BoolVar(&dryRun, "dry-run", false, "check status without renewal")
	runCmd.Flags().StringVar(&logLevel, "log-level", "info", "log level (debug, info, warn, error)")

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show certificate status",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := newLogger(logLevel)
			defer logger.Sync()

			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			mgr, err := buildManager(cfg, logger)
			if err != nil {
				return fmt.Errorf("building manager: %w", err)
			}

			ctx := context.Background()
			statuses, err := mgr.Status(ctx)
			if err != nil {
				return fmt.Errorf("checking status: %w", err)
			}

			fmt.Printf("%-25s %-12s %-10s %-30s\n", "NAME", "EXPIRES", "RENEW?", "DOMAINS")
			fmt.Println("-------------------------------------------------------------------------------------------")
			for _, s := range statuses {
				renew := "NO"
				if s.NeedsRenew {
					renew = "YES"
				}
				expires := s.NotAfter.Format("2006-01-02")
				if s.NotAfter.IsZero() {
					expires = "not found"
				}
				domains := s.Domains[0]
				if len(s.Domains) > 1 {
					domains += fmt.Sprintf(" (+%d more)", len(s.Domains)-1)
				}
				fmt.Printf("%-25s %-12s %-10s %-30s\n", s.Name, expires, renew, domains)
			}
			return nil
		},
	}
	statusCmd.Flags().StringVarP(&cfgPath, "config", "c", "/etc/certmaid/config.yaml", "config file path")
	statusCmd.Flags().StringVar(&logLevel, "log-level", "info", "log level")

	renewCmd := &cobra.Command{
		Use:   "renew [name]",
		Short: "Force renewal of a specific certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := newLogger(logLevel)
			defer logger.Sync()

			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			mgr, err := buildManager(cfg, logger)
			if err != nil {
				return fmt.Errorf("building manager: %w", err)
			}

			ctx := context.Background()
			if err := mgr.RenewOne(ctx, args[0]); err != nil {
				return fmt.Errorf("renewing %s: %w", args[0], err)
			}

			logger.Info("certificate renewed", zap.String("name", args[0]))
			return nil
		},
	}
	renewCmd.Flags().StringVarP(&cfgPath, "config", "c", "/etc/certmaid/config.yaml", "config file path")
	renewCmd.Flags().StringVar(&logLevel, "log-level", "info", "log level")

	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Install systemd service and timer units",
		RunE: func(cmd *cobra.Command, args []string) error {
			timer, _ := cmd.Flags().GetBool("timer")
			if !timer {
				return fmt.Errorf("--timer flag is required for install")
			}

			if os.Geteuid() != 0 {
				return fmt.Errorf("install must be run as root")
			}

			const svcPath = "/etc/systemd/system/certmaid.service"
			const timerPath = "/etc/systemd/system/certmaid.timer"

			if err := os.WriteFile(svcPath, systemd.ServiceUnit, 0644); err != nil {
				return fmt.Errorf("writing %s: %w", svcPath, err)
			}
			fmt.Printf("Wrote %s\n", svcPath)

			if err := os.WriteFile(timerPath, systemd.TimerUnit, 0644); err != nil {
				return fmt.Errorf("writing %s: %w", timerPath, err)
			}
			fmt.Printf("Wrote %s\n", timerPath)

			if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
				return fmt.Errorf("systemctl daemon-reload: %w", err)
			}

			if err := exec.Command("systemctl", "enable", "certmaid.timer").Run(); err != nil {
				return fmt.Errorf("systemctl enable certmaid.timer: %w", err)
			}

			if err := exec.Command("systemctl", "start", "certmaid.timer").Run(); err != nil {
				return fmt.Errorf("systemctl start certmaid.timer: %w", err)
			}

			fmt.Println()
			fmt.Println("CertMaid timer installed successfully.")
			fmt.Println()
			fmt.Println("Management commands:")
			fmt.Println("  systemctl status certmaid.timer   # Check timer status")
			fmt.Println("  systemctl start certmaid.service  # Trigger renewal manually")
			fmt.Println("  journalctl -u certmaid.service    # View logs")
			fmt.Println("  certmaid uninstall --timer        # Remove timer")
			return nil
		},
	}
	installCmd.Flags().Bool("timer", false, "install systemd timer unit")

	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove systemd service and timer units",
		RunE: func(cmd *cobra.Command, args []string) error {
			timer, _ := cmd.Flags().GetBool("timer")
			if !timer {
				return fmt.Errorf("--timer flag is required for uninstall")
			}

			if os.Geteuid() != 0 {
				return fmt.Errorf("uninstall must be run as root")
			}

			const svcPath = "/etc/systemd/system/certmaid.service"
			const timerPath = "/etc/systemd/system/certmaid.timer"

			_ = exec.Command("systemctl", "stop", "certmaid.timer").Run()
			_ = exec.Command("systemctl", "disable", "certmaid.timer").Run()

			if err := os.Remove(svcPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("removing %s: %w", svcPath, err)
			}
			fmt.Printf("Removed %s\n", svcPath)

			if err := os.Remove(timerPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("removing %s: %w", timerPath, err)
			}
			fmt.Printf("Removed %s\n", timerPath)

			if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
				return fmt.Errorf("systemctl daemon-reload: %w", err)
			}

			fmt.Println()
			fmt.Println("CertMaid timer uninstalled successfully.")
			return nil
		},
	}
	uninstallCmd.Flags().Bool("timer", false, "remove systemd timer unit")

	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage configuration",
	}

	configValidateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate the configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("config is invalid: %w", err)
			}
			fmt.Println("Configuration is valid.")
			return nil
		},
	}
	configValidateCmd.Flags().StringVarP(&cfgPath, "config", "c", "/etc/certmaid/config.yaml", "config file path")

	configShowCmd := &cobra.Command{
		Use:   "show",
		Short: "Show parsed configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			fmt.Printf("Certificates: %d\n", len(cfg.Certificates))
			for _, cert := range cfg.Certificates {
				fmt.Printf("  - %s (%s): %v\n", cert.Name, cert.Backend, cert.Domains)
			}
			return nil
		},
	}
	configShowCmd.Flags().StringVarP(&cfgPath, "config", "c", "/etc/certmaid/config.yaml", "config file path")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("certmaid version %s\n", version)
		},
	}

	configCmd.AddCommand(configValidateCmd, configShowCmd)
	rootCmd.AddCommand(runCmd, statusCmd, renewCmd, installCmd, uninstallCmd, configCmd, versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func buildManager(cfg *config.Config, logger *zap.Logger) (*manager.Manager, error) {
	var b backend.Backend

	v := cfg.Backends.Vault

	if v.ACME.Enabled {
		vaultURL := v.ACME.DirectoryURL
		if vaultURL == "" {
			return nil, fmt.Errorf("vault ACME directory URL is required when vault ACME is enabled")
		}
		eabKid := v.ACME.EAB.KID
		eabKey := v.ACME.EAB.HMACKey
		if eabKey == "" {
			eabKey = os.Getenv("VAULT_EAB_HMAC_KEY")
		}
		b = backend.NewVaultBackend(vaultURL, eabKid, eabKey)
	} else if v.API.Enabled {
		addr := v.API.Address
		if addr == "" {
			addr = os.Getenv("VAULT_ADDR")
		}
		if addr == "" {
			return nil, fmt.Errorf("vault API address is required when vault API is enabled")
		}

		mountPath := v.API.PKI.MountPath
		if mountPath == "" {
			mountPath = "pki"
		}
		role := v.API.PKI.Role
		if role == "" {
			return nil, fmt.Errorf("vault API PKI role is required when vault API is enabled")
		}

		vb, err := backend.NewVaultAPIBackend(addr, mountPath, role)
		if err != nil {
			return nil, fmt.Errorf("creating vault API backend: %w", err)
		}

		auth := v.API.Auth
		switch {
		case auth.TokenFile != "":
			tokenBytes, err := os.ReadFile(auth.TokenFile)
			if err != nil {
				return nil, fmt.Errorf("reading vault token file %s: %w", auth.TokenFile, err)
			}
			vb.SetToken(strings.TrimSpace(string(tokenBytes)))

		case os.Getenv("VAULT_TOKEN") != "":
			vb.SetToken(os.Getenv("VAULT_TOKEN"))

		case auth.AppRole.RoleIDFile != "" && auth.AppRole.SecretIDFile != "":
			roleIDBytes, err := os.ReadFile(auth.AppRole.RoleIDFile)
			if err != nil {
				return nil, fmt.Errorf("reading approle role_id file: %w", err)
			}
			secretIDBytes, err := os.ReadFile(auth.AppRole.SecretIDFile)
			if err != nil {
				return nil, fmt.Errorf("reading approle secret_id file: %w", err)
			}
			if err := vb.LoginWithAppRole(strings.TrimSpace(string(roleIDBytes)), strings.TrimSpace(string(secretIDBytes))); err != nil {
				return nil, fmt.Errorf("approle login: %w", err)
			}

		case auth.TLSCert.CertFile != "" && auth.TLSCert.KeyFile != "":
			roleName := auth.TLSCert.RoleName
			if roleName == "" {
				roleName = "certmaid"
			}
			if err := vb.LoginWithCert(auth.TLSCert.CertFile, auth.TLSCert.KeyFile, roleName); err != nil {
				return nil, fmt.Errorf("cert login: %w", err)
			}

		default:
			return nil, fmt.Errorf("vault API enabled but no authentication configured: set token_file, approle, tls_cert, or VAULT_TOKEN env var")
		}
		b = vb
	} else {
		return nil, fmt.Errorf("no CA backend configured: enable vault.acme or vault.api in config")
	}

	w := writer.NewFileWriter(cfg.Output.BaseDir)
	h := hook.NewRunner()

	return manager.New(cfg, b, w, h, logger), nil
}

func newLogger(level string) *zap.Logger {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	logFile := os.Getenv("CERTMAID_LOG_FILE")
	var ws zapcore.WriteSyncer
	if logFile != "" {
		lj := &lumberjack.Logger{
			Filename:   logFile,
			MaxSize:    100,
			MaxBackups: 7,
		}
		ws = zapcore.AddSync(lj)
	} else {
		ws = zapcore.AddSync(os.Stderr)
	}

	cfg := zap.NewProductionEncoderConfig()
	cfg.EncodeTime = zapcore.ISO8601TimeEncoder

	core := zapcore.NewCore(zapcore.NewConsoleEncoder(cfg), ws, zapLevel)
	return zap.New(core)
}