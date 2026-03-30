package client

import (
	"net/url"
	"strings"
	"time"
)

// ClientType determines the OAuth client classification.
type ClientType string

const (
	Public       ClientType = "public"
	Confidential ClientType = "confidential"
)

// GrantType represents an OAuth 2.0 grant type.
type GrantType string

const (
	GrantAuthorizationCode GrantType = "authorization_code"
	GrantClientCredentials GrantType = "client_credentials"
	GrantRefreshToken      GrantType = "refresh_token"
	GrantDeviceCode        GrantType = "urn:ietf:params:oauth:grant-type:device_code"
	GrantPassword          GrantType = "password"
)

// Client represents a registered OAuth 2.0 client.
type Client struct {
	ID                string
	TenantID          string
	ClientName        string
	ClientType        ClientType
	SecretHash        []byte
	RedirectURIs      []string
	AllowedScopes     []string
	AllowedGrantTypes []GrantType
	TokenVersion      int
	APIKey            string   // non-expiring static API key (hashed before storage)
	APIKeyHash        []byte   // SHA-256 hash of the API key
	IsAgent           bool     // marks this client as an AI agent/service account
	Description       string   // what this agent does
	AllowedEndpoints  []string // e.g., ["/api/data", "/api/reports"] — empty = all endpoints
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DeletedAt         *time.Time
}

// NewClient creates a validated Client.
func NewClient(id, tenantID, name string, clientType ClientType, redirectURIs []string, scopes []string, grantTypes []GrantType) (Client, error) {
	if id == "" {
		return Client{}, &ValidationError{Field: "id", Message: "must not be empty"}
	}
	if tenantID == "" {
		return Client{}, &ValidationError{Field: "tenant_id", Message: "must not be empty"}
	}
	if name == "" {
		return Client{}, &ValidationError{Field: "client_name", Message: "must not be empty"}
	}
	switch clientType {
	case Public, Confidential:
		// valid
	default:
		return Client{}, &ValidationError{Field: "client_type", Message: "must be 'public' or 'confidential'"}
	}

	for _, gt := range grantTypes {
		if !isValidGrantType(gt) {
			return Client{}, &ValidationError{Field: "grant_types", Message: "invalid grant type: " + string(gt)}
		}
		if clientType == Public && gt == GrantClientCredentials {
			return Client{}, &ValidationError{Field: "grant_types", Message: "public clients cannot use client_credentials"}
		}
	}

	for _, uri := range redirectURIs {
		if err := ValidateRedirectURI(uri); err != nil {
			return Client{}, err
		}
	}

	now := time.Now().UTC()
	return Client{
		ID:                id,
		TenantID:          tenantID,
		ClientName:        name,
		ClientType:        clientType,
		RedirectURIs:      redirectURIs,
		AllowedScopes:     scopes,
		AllowedGrantTypes: grantTypes,
		CreatedAt:         now,
		UpdatedAt:         now,
	}, nil
}

// HasGrantType checks if the client is allowed to use the given grant type.
func (c Client) HasGrantType(gt GrantType) bool {
	for _, allowed := range c.AllowedGrantTypes {
		if allowed == gt {
			return true
		}
	}
	return false
}

// HasRedirectURI checks if the given URI matches one of the client's registered URIs.
func (c Client) HasRedirectURI(uri string) bool {
	for _, allowed := range c.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

// HasScope checks if the given scope is allowed for this client.
func (c Client) HasScope(scope string) bool {
	for _, allowed := range c.AllowedScopes {
		if allowed == scope {
			return true
		}
	}
	return false
}

// ValidateScopes checks if all requested scopes are allowed.
// Returns the list of invalid scopes, or nil if all are valid.
// If the client has no allowed scopes configured, all scopes are permitted.
func (c Client) ValidateScopes(requestedScopes string) []string {
	if len(c.AllowedScopes) == 0 {
		return nil // no restrictions
	}
	if requestedScopes == "" {
		return nil
	}

	var invalid []string
	for _, scope := range strings.Split(requestedScopes, " ") {
		scope = strings.TrimSpace(scope)
		if scope != "" && !c.HasScope(scope) {
			invalid = append(invalid, scope)
		}
	}
	return invalid
}

// IsDeleted returns true if the client has been soft-deleted.
func (c Client) IsDeleted() bool {
	return c.DeletedAt != nil
}

// ValidateRedirectURI checks that a redirect URI is valid.
func ValidateRedirectURI(uri string) error {
	parsed, err := url.Parse(uri)
	if err != nil {
		return &ValidationError{Field: "redirect_uris", Message: "invalid URI: " + uri}
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return &ValidationError{Field: "redirect_uris", Message: "URI must have scheme and host: " + uri}
	}
	// Allow http only for localhost (development)
	if parsed.Scheme == "http" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" {
		return &ValidationError{Field: "redirect_uris", Message: "non-localhost URIs must use HTTPS: " + uri}
	}
	return nil
}

func isValidGrantType(gt GrantType) bool {
	switch gt {
	case GrantAuthorizationCode, GrantClientCredentials, GrantRefreshToken, GrantDeviceCode, GrantPassword:
		return true
	default:
		return false
	}
}
