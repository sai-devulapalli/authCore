package client

// CreateClientRequest is the DTO for creating a new OAuth client.
type CreateClientRequest struct {
	ClientID      string   `json:"client_id,omitempty"`      // optional; auto-generated if empty
	ClientSecret  string   `json:"client_secret,omitempty"`  // optional; auto-generated if empty (confidential only)
	ClientName    string   `json:"client_name"`
	ClientType    string   `json:"client_type"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedScopes []string `json:"allowed_scopes"`
	GrantTypes    []string `json:"grant_types"`
	TenantID      string   `json:"-"`
}

// UpdateClientRequest is the DTO for updating an existing client.
type UpdateClientRequest struct {
	ClientName    string   `json:"client_name,omitempty"`
	RedirectURIs  []string `json:"redirect_uris,omitempty"`
	AllowedScopes []string `json:"allowed_scopes,omitempty"`
	TenantID      string   `json:"-"`
}

// ClientResponse is the DTO returned to the caller.
type ClientResponse struct {
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret,omitempty"`
	ClientName    string   `json:"client_name"`
	ClientType    string   `json:"client_type"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedScopes []string `json:"allowed_scopes"`
	GrantTypes    []string `json:"grant_types"`
}
