package config

import (
	"github.com/authcore/pkg/sdk/database"
	sdkerrors "github.com/authcore/pkg/sdk/errors"
	"github.com/authcore/pkg/sdk/logger"
	"github.com/caarlos0/env/v11"
)

// Config holds all application configuration, loaded from environment variables.
type Config struct {
	Environment    logger.Environment `env:"AUTHCORE_ENV"             envDefault:"local"`
	HTTPPort       int                `env:"AUTHCORE_HTTP_PORT"       envDefault:"8080"`
	DatabaseDSN    string             `env:"AUTHCORE_DATABASE_DSN"    envDefault:"postgres://authcore:authcore_dev@localhost:5432/authcore?sslmode=disable"`
	DatabaseDriver database.Driver    `env:"AUTHCORE_DATABASE_DRIVER" envDefault:"postgres"`
	RedisURL       string             `env:"AUTHCORE_REDIS_URL"       envDefault:"redis://localhost:6379"`
	LogLevel       string             `env:"AUTHCORE_LOG_LEVEL"       envDefault:""`
	TenantMode     TenantMode         `env:"AUTHCORE_TENANT_MODE"     envDefault:"header"`
	Issuer         string             `env:"AUTHCORE_ISSUER"          envDefault:"http://localhost:8080"`
	CORSOrigins    string             `env:"AUTHCORE_CORS_ORIGINS"    envDefault:"*"`
	AdminAPIKey    string             `env:"AUTHCORE_ADMIN_API_KEY"   envDefault:""`
	SMTPHost       string             `env:"AUTHCORE_SMTP_HOST"       envDefault:""`
	SMTPPort       int                `env:"AUTHCORE_SMTP_PORT"       envDefault:"587"`
	SMTPUsername   string             `env:"AUTHCORE_SMTP_USERNAME"   envDefault:""`
	SMTPPassword   string             `env:"AUTHCORE_SMTP_PASSWORD"   envDefault:""`
	SMTPFrom       string             `env:"AUTHCORE_SMTP_FROM"       envDefault:"noreply@authcore.local"`
	SMSProvider    string             `env:"AUTHCORE_SMS_PROVIDER"    envDefault:""`
	SMSAccountID   string             `env:"AUTHCORE_SMS_ACCOUNT_ID"  envDefault:""`
	SMSAuthToken   string             `env:"AUTHCORE_SMS_AUTH_TOKEN"  envDefault:""`
	SMSFromNumber  string             `env:"AUTHCORE_SMS_FROM_NUMBER" envDefault:""`
	EncryptionKey    string             `env:"AUTHCORE_ENCRYPTION_KEY"    envDefault:""`
	KeyRotationDays  int                `env:"AUTHCORE_KEY_ROTATION_DAYS" envDefault:"90"`
	WebAuthnRPID      string            `env:"AUTHCORE_WEBAUTHN_RP_ID"      envDefault:"localhost"`
	WebAuthnRPName    string            `env:"AUTHCORE_WEBAUTHN_RP_NAME"    envDefault:"AuthCore"`
	WebAuthnRPOrigins string            `env:"AUTHCORE_WEBAUTHN_RP_ORIGINS" envDefault:"http://localhost:8080"`
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
