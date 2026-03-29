package saml

// SSORequest contains the parameters to initiate a SAML SSO flow.
type SSORequest struct {
	ProviderID          string
	TenantID            string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}
