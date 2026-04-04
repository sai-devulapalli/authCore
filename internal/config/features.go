package config

// FeatureFlags controls runtime feature toggles via environment variables.
type FeatureFlags struct {
	SAMLEnabled     bool `env:"AUTHPLEX_FEATURE_SAML"     envDefault:"true"`
	WebAuthnEnabled bool `env:"AUTHPLEX_FEATURE_WEBAUTHN" envDefault:"true"`
	AdminUIEnabled  bool `env:"AUTHPLEX_FEATURE_ADMIN_UI" envDefault:"true"`
	AuditLogging    bool `env:"AUTHPLEX_FEATURE_AUDIT"    envDefault:"true"`
}
