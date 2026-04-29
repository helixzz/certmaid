package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/helixzz/certmaid/internal/backend"
	"github.com/helixzz/certmaid/internal/config"
	"github.com/helixzz/certmaid/internal/hook"
	"github.com/helixzz/certmaid/internal/manager"
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
	rootCmd.AddCommand(runCmd, statusCmd, renewCmd, configCmd, versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func buildManager(cfg *config.Config, logger *zap.Logger) (*manager.Manager, error) {
	var b backend.Backend

	if cfg.Backends.Vault.ACME.Enabled {
		vaultURL := cfg.Backends.Vault.ACME.DirectoryURL
		if vaultURL == "" {
			return nil, fmt.Errorf("vault ACME directory URL is required when vault ACME is enabled")
		}
		eabKid := cfg.Backends.Vault.ACME.EAB.KID
		eabKey := cfg.Backends.Vault.ACME.EAB.HMACKey
		if eabKey == "" {
			eabKey = os.Getenv("VAULT_EAB_HMAC_KEY")
		}
		b = backend.NewVaultBackend(vaultURL, eabKid, eabKey)
	} else {
		return nil, fmt.Errorf("no CA backend configured: enable vault ACME")
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

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(zapLevel)
	cfg.Encoding = "console"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger, _ := cfg.Build()
	return logger
}