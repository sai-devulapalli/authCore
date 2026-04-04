package oauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/authplex/internal/domain/identity"
)

// HTTPOAuthClient implements identity.OAuthClient using net/http.
type HTTPOAuthClient struct {
	httpClient *http.Client
}

// NewHTTPOAuthClient creates a new OAuth client with sensible timeouts.
func NewHTTPOAuthClient() *HTTPOAuthClient {
	return &HTTPOAuthClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

var _ identity.OAuthClient = (*HTTPOAuthClient)(nil)

// ExchangeCode exchanges an authorization code for tokens with the external provider.
func (c *HTTPOAuthClient) ExchangeCode(ctx context.Context, tokenURL, code, redirectURI, clientID, clientSecret string) (identity.OAuthTokenResponse, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return identity.OAuthTokenResponse{}, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return identity.OAuthTokenResponse{}, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return identity.OAuthTokenResponse{}, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return identity.OAuthTokenResponse{}, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return identity.OAuthTokenResponse{}, fmt.Errorf("failed to decode token response: %w", err)
	}

	return identity.OAuthTokenResponse{
		AccessToken:  tokenResp.AccessToken,
		IDToken:      tokenResp.IDToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
	}, nil
}

// FetchUserInfo retrieves user profile from the provider's userinfo endpoint.
func (c *HTTPOAuthClient) FetchUserInfo(ctx context.Context, userInfoURL, accessToken string) (identity.UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return identity.UserInfo{}, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return identity.UserInfo{}, fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return identity.UserInfo{}, fmt.Errorf("failed to read userinfo response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return identity.UserInfo{}, fmt.Errorf("userinfo request failed with status %d", resp.StatusCode)
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return identity.UserInfo{}, fmt.Errorf("failed to decode userinfo response: %w", err)
	}

	return identity.UserInfo{
		Subject:       getStringField(raw, "sub", "id"),
		Email:         getStringField(raw, "email"),
		EmailVerified: getBoolField(raw, "email_verified"),
		Name:          getStringField(raw, "name"),
		Picture:       getStringField(raw, "picture", "avatar_url"),
		RawClaims:     raw,
	}, nil
}

// FetchOIDCDiscovery retrieves the OIDC discovery document.
func (c *HTTPOAuthClient) FetchOIDCDiscovery(ctx context.Context, discoveryURL string) (identity.OIDCConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return identity.OIDCConfig{}, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return identity.OIDCConfig{}, fmt.Errorf("discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	var config identity.OIDCConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return identity.OIDCConfig{}, fmt.Errorf("failed to decode discovery response: %w", err)
	}

	return config, nil
}

// ExchangeCodeWithConfig is like ExchangeCode but supports provider-specific configuration.
// For Apple providers, it generates a JWT client_secret from the ExtraConfig fields.
func (c *HTTPOAuthClient) ExchangeCodeWithConfig(ctx context.Context, tokenURL, code, redirectURI, clientID, clientSecret string, extraConfig map[string]string) (identity.OAuthTokenResponse, error) {
	secret := clientSecret
	if teamID, ok := extraConfig["apple_team_id"]; ok && teamID != "" {
		keyID := extraConfig["apple_key_id"]
		privateKey := extraConfig["apple_private_key"]
		jwt, err := GenerateAppleClientSecret(teamID, clientID, keyID, []byte(privateKey))
		if err != nil {
			return identity.OAuthTokenResponse{}, fmt.Errorf("failed to generate Apple client secret: %w", err)
		}
		secret = jwt
	}
	return c.ExchangeCode(ctx, tokenURL, code, redirectURI, clientID, secret)
}

// DecodeIDToken decodes and validates a JWT id_token using the provider's JWKS.
// Returns the extracted user info from the token claims.
func (c *HTTPOAuthClient) DecodeIDToken(ctx context.Context, idToken, jwksURI string) (identity.UserInfo, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return identity.UserInfo{}, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode header to get kid and alg
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return identity.UserInfo{}, fmt.Errorf("failed to decode JWT header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return identity.UserInfo{}, fmt.Errorf("failed to parse JWT header: %w", err)
	}

	// Fetch JWKS and verify signature
	if jwksURI != "" {
		if err := c.verifyJWTSignature(ctx, parts, header.Kid, header.Alg, jwksURI); err != nil {
			return identity.UserInfo{}, fmt.Errorf("JWT signature verification failed: %w", err)
		}
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return identity.UserInfo{}, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return identity.UserInfo{}, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return identity.UserInfo{
		Subject:       getStringField(claims, "sub"),
		Email:         getStringField(claims, "email"),
		EmailVerified: getBoolField(claims, "email_verified"),
		Name:          getStringField(claims, "name"),
		Picture:       getStringField(claims, "picture"),
		RawClaims:     claims,
	}, nil
}

// verifyJWTSignature fetches the JWKS and verifies the JWT signature.
func (c *HTTPOAuthClient) verifyJWTSignature(ctx context.Context, parts []string, kid, alg, jwksURI string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Find matching key
	for _, rawKey := range jwks.Keys {
		var key struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}
		if err := json.Unmarshal(rawKey, &key); err != nil {
			continue
		}

		if kid != "" && key.Kid != kid {
			continue
		}

		signingInput := parts[0] + "." + parts[1]
		sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return fmt.Errorf("failed to decode signature: %w", err)
		}

		switch key.Kty {
		case "RSA":
			return verifyRSASignature(signingInput, sigBytes, key.N, key.E, alg)
		case "EC":
			return verifyECSignature(signingInput, sigBytes, key.X, key.Y, key.Crv, alg)
		}
	}

	return fmt.Errorf("no matching key found for kid=%s", kid)
}

func verifyRSASignature(signingInput string, sig []byte, nB64, eB64, alg string) error {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return err
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	pubKey := &rsa.PublicKey{N: n, E: e}

	var hashFunc crypto.Hash
	switch alg {
	case "RS256":
		hashFunc = crypto.SHA256
	case "RS384":
		hashFunc = crypto.SHA384
	case "RS512":
		hashFunc = crypto.SHA512
	default:
		return fmt.Errorf("unsupported RSA algorithm: %s", alg)
	}

	h := hashFunc.New()
	h.Write([]byte(signingInput))
	return rsa.VerifyPKCS1v15(pubKey, hashFunc, h.Sum(nil), sig)
}

func verifyECSignature(signingInput string, sig []byte, xB64, yB64, crv, alg string) error {
	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return err
	}

	var curve elliptic.Curve
	var hashBytes []byte
	switch crv {
	case "P-256":
		curve = elliptic.P256()
		h := sha256.Sum256([]byte(signingInput))
		hashBytes = h[:]
	case "P-384":
		curve = elliptic.P384()
		h := sha512.Sum384([]byte(signingInput))
		hashBytes = h[:]
	default:
		return fmt.Errorf("unsupported EC curve: %s", crv)
	}

	_ = alg // curve determines hash

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	// EC signature is r || s, each half the signature length
	keySize := (curve.Params().BitSize + 7) / 8
	if len(sig) != 2*keySize {
		return fmt.Errorf("invalid EC signature length: got %d, expected %d", len(sig), 2*keySize)
	}

	r := new(big.Int).SetBytes(sig[:keySize])
	s := new(big.Int).SetBytes(sig[keySize:])

	if !ecdsa.Verify(pubKey, hashBytes, r, s) {
		return fmt.Errorf("EC signature verification failed")
	}
	return nil
}

// getStringField extracts a string value from a map, trying multiple keys.
func getStringField(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if val, ok := m[key]; ok {
			if s, ok := val.(string); ok {
				return s
			}
			// GitHub returns `id` as a number
			if f, ok := val.(float64); ok {
				return fmt.Sprintf("%.0f", f)
			}
		}
	}
	return ""
}

func getBoolField(m map[string]any, key string) bool {
	if val, ok := m[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}
