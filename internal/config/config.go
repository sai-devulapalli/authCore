package config

import (
	"github.com/authplex/pkg/sdk/database"
	sdkerrors "github.com/authplex/pkg/sdk/errors"
	"github.com/authplex/pkg/sdk/logger"
	"github.com/caarlos0/env/v11"
)

// Config holds all application configuration, loaded from environment variables.
type Config struct {
	Environment    logger.Environment `env:"AUTHPLEX_ENV"             envDefault:"local"`
	HTTPPort       int                `env:"AUTHPLEX_HTTP_PORT"       envDefault:"8080"`
	DatabaseDSN    string             `env:"AUTHPLEX_DATABASE_DSN"    envDefault:"postgres://authplex:authplex_dev@localhost:5432/authplex?sslmode=disable"`
	DatabaseDriver database.Driver    `env:"AUTHPLEX_DATABASE_DRIVER" envDefault:"postgres"`
	RedisURL       string             `env:"AUTHPLEX_REDIS_URL"       envDefault:"redis://localhost:6379"`
	LogLevel       string             `env:"AUTHPLEX_LOG_LEVEL"       envDefault:""`
	TenantMode     TenantMode         `env:"AUTHPLEX_TENANT_MODE"     envDefault:"header"`
	Issuer         string             `env:"AUTHPLEX_ISSUER"          envDefault:"http://localhost:8080"`
	CORSOrigins    string             `env:"AUTHPLEX_CORS_ORIGINS"    envDefault:"*"`
	AdminAPIKey    string             `env:"AUTHPLEX_ADMIN_API_KEY"   envDefault:""`
	SMTPHost       string             `env:"AUTHPLEX_SMTP_HOST"       envDefault:""`
	SMTPPort       int                `env:"AUTHPLEX_SMTP_PORT"       envDefault:"587"`
	SMTPUsername   string             `env:"AUTHPLEX_SMTP_USERNAME"   envDefault:""`
	SMTPPassword   string             `env:"AUTHPLEX_SMTP_PASSWORD"   envDefault:""`
	SMTPFrom       string             `env:"AUTHPLEX_SMTP_FROM"       envDefault:"noreply@authplex.local"`
	SMSProvider    string             `env:"AUTHPLEX_SMS_PROVIDER"    envDefault:""`
	SMSAccountID   string             `env:"AUTHPLEX_SMS_ACCOUNT_ID"  envDefault:""`
	SMSAuthToken   string             `env:"AUTHPLEX_SMS_AUTH_TOKEN"  envDefault:""`
	SMSFromNumber  string             `env:"AUTHPLEX_SMS_FROM_NUMBER" envDefault:""`
	EncryptionKey    string             `env:"AUTHPLEX_ENCRYPTION_KEY"    envDefault:""`
	KeyRotationDays  int                `env:"AUTHPLEX_KEY_ROTATION_DAYS" envDefault:"90"`
	WebAuthnRPID      string            `env:"AUTHPLEX_WEBAUTHN_RP_ID"      envDefault:"localhost"`
	WebAuthnRPName    string            `env:"AUTHPLEX_WEBAUTHN_RP_NAME"    envDefault:"AuthPlex"`
	WebAuthnRPOrigins string            `env:"AUTHPLEX_WEBAUTHN_RP_ORIGINS" envDefault:"http://localhost:8080"`
	Features          FeatureFlags      `envPrefix:""`
}

// TenantMode determines how tenants are resolved from incoming requests.
type TenantMode string

const (
	TenantModeHeader TenantMode = "header"
	TenantModeDomain TenantMode = "domain"
)

// Load reads configuration from environment variables.
// Returns Result[Config] — never panics.
func Load() sdkerrors.Result[Config] {
	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return sdkerrors.Err[Config](
			sdkerrors.Wrap(sdkerrors.ErrInternal, "failed to parse configuration", err),
		)
	}

	if validationErr := cfg.validate(); validationErr != nil {
		return sdkerrors.Err[Config](validationErr)
	}

	return sdkerrors.Ok(cfg)
}

func (c *Config) validate() *sdkerrors.AppError {
	if c.HTTPPort < 1 || c.HTTPPort > 65535 {
		return sdkerrors.New(sdkerrors.ErrBadRequest, "HTTP port must be between 1 and 65535")
	}

	switch c.TenantMode {
	case TenantModeHeader, TenantModeDomain:
		// valid
	default:
		return sdkerrors.New(sdkerrors.ErrBadRequest, "tenant mode must be 'header' or 'domain'")
	}

	switch c.DatabaseDriver {
	case database.Postgres, database.SQLServer:
		// valid
	default:
		return sdkerrors.New(sdkerrors.ErrBadRequest, "database driver must be 'postgres' or 'sqlserver'")
	}

	return nil
}
