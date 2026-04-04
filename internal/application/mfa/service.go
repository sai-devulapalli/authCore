package mfa

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/authplex/internal/application/auth"
	auditsvc "github.com/authplex/internal/application/audit"
	domainaudit "github.com/authplex/internal/domain/audit"
	domainmfa "github.com/authplex/internal/domain/mfa"
	apperrors "github.com/authplex/pkg/sdk/errors"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// webauthnUser is a thin adapter satisfying the webauthn.User interface.
type webauthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webauthnUser) WebAuthnName() string                       { return u.name }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// webauthnSessionData is the envelope stored in ChallengeRepository for WebAuthn flows.
type webauthnSessionData struct {
	Session  *webauthn.SessionData `json:"session"`
	Subject  string                `json:"subject"`
	TenantID string                `json:"tenant_id"`
}

// Service provides MFA operations.
type Service struct {
	totpRepo      domainmfa.TOTPRepository
	challengeRepo domainmfa.ChallengeRepository
	webauthnRepo  domainmfa.WebAuthnRepository
	authSvc       *auth.Service
	auditSvc      *auditsvc.Service
	logger        *slog.Logger
	challengeTTL  time.Duration
	// WebAuthn relying party configuration
	webauthnRPID      string
	webauthnRPName    string
	webauthnRPOrigins []string
}

// NewService creates a new MFA service.
func NewService(
	totpRepo domainmfa.TOTPRepository,
	challengeRepo domainmfa.ChallengeRepository,
	authSvc *auth.Service,
	logger *slog.Logger,
) *Service {
	return &Service{
		totpRepo:      totpRepo,
		challengeRepo: challengeRepo,
		authSvc:       authSvc,
		logger:        logger,
		challengeTTL:  5 * time.Minute,
	}
}

// WithAudit configures audit event logging.
func (s *Service) WithAudit(a *auditsvc.Service) *Service {
	s.auditSvc = a
	return s
}

// EnrollTOTP generates a new TOTP secret for the user.
func (s *Service) EnrollTOTP(ctx context.Context, req EnrollRequest) (EnrollResponse, *apperrors.AppError) {
	if req.Subject == "" {
		return EnrollResponse{}, apperrors.New(apperrors.ErrBadRequest, "subject is required")
	}

	// Check if already enrolled
	existing, err := s.totpRepo.GetBySubject(ctx, req.TenantID, req.Subject)
	if err == nil && existing.Confirmed {
		return EnrollResponse{}, apperrors.New(apperrors.ErrConflict, "TOTP already enrolled")
	}

	// Generate secret
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return EnrollResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate secret", err)
	}

	id, err := generateID()
	if err != nil {
		return EnrollResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate ID", err)
	}

	enrollment := domainmfa.TOTPEnrollment{
		ID:        id,
		Subject:   req.Subject,
		TenantID:  req.TenantID,
		Secret:    secret,
		Confirmed: false,
		CreatedAt: time.Now().UTC(),
	}

	if storeErr := s.totpRepo.Store(ctx, enrollment); storeErr != nil {
		return EnrollResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to store enrollment", storeErr)
	}

	encodedSecret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	otpauthURI := domainmfa.BuildOTPAuthURI("AuthPlex", req.Subject, encodedSecret)

	s.logger.Info("TOTP enrollment initiated", "subject", req.Subject, "tenant_id", req.TenantID)
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, req.TenantID, req.Subject, "user", domainaudit.EventMFAEnrolled, "mfa", req.Subject, nil, map[string]any{"method": "totp"})
	}

	return EnrollResponse{
		Secret:     encodedSecret,
		OTPAuthURI: otpauthURI,
	}, nil
}

// ConfirmTOTP confirms enrollment after the user verifies their first code.
func (s *Service) ConfirmTOTP(ctx context.Context, req VerifyRequest) *apperrors.AppError {
	enrollment, err := s.totpRepo.GetBySubject(ctx, req.TenantID, req.Subject)
	if err != nil {
		return apperrors.New(apperrors.ErrNotFound, "no pending TOTP enrollment")
	}
	if enrollment.Confirmed {
		return apperrors.New(apperrors.ErrConflict, "TOTP already confirmed")
	}

	if !domainmfa.VerifyTOTP(enrollment.Secret, req.Code, time.Now().UTC()) {
		return apperrors.New(apperrors.ErrBadRequest, "invalid TOTP code")
	}

	if confirmErr := s.totpRepo.Confirm(ctx, enrollment.ID); confirmErr != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to confirm enrollment", confirmErr)
	}

	s.logger.Info("TOTP enrollment confirmed", "subject", req.Subject)
	return nil
}

// VerifyMFA verifies a TOTP code against an MFA challenge and completes the auth flow.
func (s *Service) VerifyMFA(ctx context.Context, req MFAVerifyRequest) (auth.AuthorizeResponse, *apperrors.AppError) {
	challenge, err := s.challengeRepo.GetByID(ctx, req.ChallengeID)
	if err != nil {
		return auth.AuthorizeResponse{}, apperrors.New(apperrors.ErrNotFound, "challenge not found")
	}
	if challenge.IsExpired() {
		return auth.AuthorizeResponse{}, apperrors.New(apperrors.ErrExpiredCode, "MFA challenge has expired")
	}
	if challenge.Verified {
		return auth.AuthorizeResponse{}, apperrors.New(apperrors.ErrBadRequest, "challenge already verified")
	}

	// Verify based on method.
	switch req.Method {
	case "webauthn":
		if verifyErr := s.VerifyMFAWebAuthn(ctx, challenge, []byte(req.Code)); verifyErr != nil {
			return auth.AuthorizeResponse{}, verifyErr
		}
	default:
		// Default to TOTP verification.
		enrollment, getErr := s.totpRepo.GetBySubject(ctx, challenge.TenantID, challenge.Subject)
		if getErr != nil {
			return auth.AuthorizeResponse{}, apperrors.New(apperrors.ErrBadRequest, "TOTP not enrolled")
		}
		if !enrollment.Confirmed {
			return auth.AuthorizeResponse{}, apperrors.New(apperrors.ErrBadRequest, "TOTP not confirmed")
		}

		if !domainmfa.VerifyTOTP(enrollment.Secret, req.Code, time.Now().UTC()) {
			return auth.AuthorizeResponse{}, apperrors.New(apperrors.ErrBadRequest, "invalid TOTP code")
		}
	}

	// Mark challenge as verified
	s.challengeRepo.MarkVerified(ctx, req.ChallengeID) //nolint:errcheck

	// Complete the original authorize flow
	authReq := auth.AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            challenge.OriginalClientID,
		RedirectURI:         challenge.OriginalRedirectURI,
		Scope:               challenge.OriginalScope,
		State:               challenge.OriginalState,
		CodeChallenge:       challenge.CodeChallenge,
		CodeChallengeMethod: challenge.CodeChallengeMethod,
		Subject:             challenge.Subject,
		TenantID:            challenge.TenantID,
		Nonce:               challenge.Nonce,
	}

	resp, authErr := s.authSvc.Authorize(ctx, authReq)
	if authErr != nil {
		return auth.AuthorizeResponse{}, authErr
	}

	// Clean up challenge
	s.challengeRepo.Delete(ctx, req.ChallengeID) //nolint:errcheck

	s.logger.Info("MFA verified, auth code issued", "subject", challenge.Subject)
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, challenge.TenantID, challenge.Subject, "user", domainaudit.EventMFAVerified, "mfa", challenge.Subject, nil, nil)
	}
	return resp, nil
}

// CreateChallenge creates an MFA challenge for the authorize flow.
func (s *Service) CreateChallenge(ctx context.Context, req CreateChallengeRequest) (ChallengeResponse, *apperrors.AppError) {
	id, err := generateID()
	if err != nil {
		return ChallengeResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate challenge ID", err)
	}

	challenge := domainmfa.MFAChallenge{
		ID:                  id,
		Subject:             req.Subject,
		TenantID:            req.TenantID,
		Methods:             req.Methods,
		ExpiresAt:           time.Now().UTC().Add(s.challengeTTL),
		OriginalClientID:    req.OriginalClientID,
		OriginalRedirectURI: req.OriginalRedirectURI,
		OriginalScope:       req.OriginalScope,
		OriginalState:       req.OriginalState,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
	}

	if storeErr := s.challengeRepo.Store(ctx, challenge); storeErr != nil {
		return ChallengeResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to store challenge", storeErr)
	}

	return ChallengeResponse{
		MFARequired: true,
		ChallengeID: id,
		Methods:     req.Methods,
		ExpiresIn:   int(s.challengeTTL.Seconds()),
	}, nil
}

// WithWebAuthn configures the service with WebAuthn support.
func (s *Service) WithWebAuthn(repo domainmfa.WebAuthnRepository, rpID, rpName string, rpOrigins []string) *Service {
	s.webauthnRepo = repo
	s.webauthnRPID = rpID
	s.webauthnRPName = rpName
	s.webauthnRPOrigins = rpOrigins
	return s
}

// HasEnrolledMFA checks if a user has a confirmed TOTP enrollment or WebAuthn credential.
func (s *Service) HasEnrolledMFA(ctx context.Context, tenantID, subject string) bool {
	enrollment, err := s.totpRepo.GetBySubject(ctx, tenantID, subject)
	if err == nil && enrollment.Confirmed {
		return true
	}

	if s.webauthnRepo != nil {
		creds, err := s.webauthnRepo.GetBySubject(ctx, tenantID, subject)
		if err == nil && len(creds) > 0 {
			return true
		}
	}

	return false
}

// newWebAuthn creates a configured webauthn.WebAuthn instance.
func (s *Service) newWebAuthn() (*webauthn.WebAuthn, *apperrors.AppError) {
	w, err := webauthn.New(&webauthn.Config{
		RPID:          s.webauthnRPID,
		RPDisplayName: s.webauthnRPName,
		RPOrigins:     s.webauthnRPOrigins,
	})
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to initialize WebAuthn", err)
	}
	return w, nil
}

// buildWebAuthnUser constructs a webauthn.User adapter from stored credentials.
func (s *Service) buildWebAuthnUser(ctx context.Context, tenantID, subject, displayName string) (*webauthnUser, *apperrors.AppError) {
	stored, err := s.webauthnRepo.GetBySubject(ctx, tenantID, subject)
	if err != nil {
		// No credentials yet — that's fine for registration.
		stored = nil
	}

	var credentials []webauthn.Credential
	for _, c := range stored {
		credentials = append(credentials, webauthn.Credential{
			ID:              c.CredentialID,
			PublicKey:       c.PublicKey,
			AttestationType: c.AttestationType,
			Authenticator: webauthn.Authenticator{
				AAGUID:    c.AAGUID,
				SignCount: c.SignCount,
			},
		})
	}

	dn := displayName
	if dn == "" {
		dn = subject
	}

	return &webauthnUser{
		id:          []byte(subject),
		name:        subject,
		displayName: dn,
		credentials: credentials,
	}, nil
}

// BeginWebAuthnRegistration starts a WebAuthn credential registration ceremony.
func (s *Service) BeginWebAuthnRegistration(ctx context.Context, req WebAuthnRegisterRequest) (json.RawMessage, *apperrors.AppError) {
	if s.webauthnRepo == nil {
		return nil, apperrors.New(apperrors.ErrBadRequest, "WebAuthn is not configured")
	}
	if req.Subject == "" {
		return nil, apperrors.New(apperrors.ErrBadRequest, "subject is required")
	}

	w, appErr := s.newWebAuthn()
	if appErr != nil {
		return nil, appErr
	}

	user, appErr := s.buildWebAuthnUser(ctx, req.TenantID, req.Subject, req.DisplayName)
	if appErr != nil {
		return nil, appErr
	}

	creation, session, err := w.BeginRegistration(user)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to begin WebAuthn registration", err)
	}

	// Store the session data in the challenge repo for later retrieval.
	sessionID, idErr := generateID()
	if idErr != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to generate session ID", idErr)
	}

	sessionEnvelope := webauthnSessionData{
		Session:  session,
		Subject:  req.Subject,
		TenantID: req.TenantID,
	}
	sessionJSON, marshalErr := json.Marshal(sessionEnvelope)
	if marshalErr != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to serialize session", marshalErr)
	}

	challenge := domainmfa.MFAChallenge{
		ID:        sessionID,
		Subject:   req.Subject,
		TenantID:  req.TenantID,
		Methods:   []string{"webauthn"},
		ExpiresAt: time.Now().UTC().Add(s.challengeTTL),
		// Store the serialized session in the Nonce field (repurposed for WebAuthn).
		Nonce: string(sessionJSON),
	}
	if storeErr := s.challengeRepo.Store(ctx, challenge); storeErr != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to store WebAuthn session", storeErr)
	}

	// Build response with the session ID included.
	creationJSON, marshalErr := json.Marshal(creation)
	if marshalErr != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to serialize options", marshalErr)
	}

	// Wrap creation options with the session ID for the client.
	resp := map[string]json.RawMessage{
		"session_id": json.RawMessage(`"` + sessionID + `"`),
		"options":    creationJSON,
	}
	respJSON, marshalErr := json.Marshal(resp)
	if marshalErr != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to serialize response", marshalErr)
	}

	s.logger.Info("WebAuthn registration started", "subject", req.Subject, "tenant_id", req.TenantID)
	return respJSON, nil
}

// FinishWebAuthnRegistration completes a WebAuthn credential registration ceremony.
func (s *Service) FinishWebAuthnRegistration(ctx context.Context, req WebAuthnRegisterFinishRequest) *apperrors.AppError {
	if s.webauthnRepo == nil {
		return apperrors.New(apperrors.ErrBadRequest, "WebAuthn is not configured")
	}
	if req.Subject == "" {
		return apperrors.New(apperrors.ErrBadRequest, "subject is required")
	}

	// Parse the session ID from the response envelope.
	var envelope struct {
		SessionID string          `json:"session_id"`
		Response  json.RawMessage `json:"response"`
	}
	if unmarshalErr := json.Unmarshal(req.Response, &envelope); unmarshalErr != nil {
		return apperrors.New(apperrors.ErrBadRequest, "invalid response format")
	}

	if envelope.SessionID == "" {
		return apperrors.New(apperrors.ErrBadRequest, "session_id is required")
	}

	// Retrieve stored session data.
	challenge, getErr := s.challengeRepo.GetByID(ctx, envelope.SessionID)
	if getErr != nil {
		return apperrors.New(apperrors.ErrNotFound, "WebAuthn session not found")
	}
	if challenge.IsExpired() {
		return apperrors.New(apperrors.ErrExpiredCode, "WebAuthn session has expired")
	}

	var sessionEnvelope webauthnSessionData
	if unmarshalErr := json.Unmarshal([]byte(challenge.Nonce), &sessionEnvelope); unmarshalErr != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to deserialize session", unmarshalErr)
	}

	w, appErr := s.newWebAuthn()
	if appErr != nil {
		return appErr
	}

	user, appErr := s.buildWebAuthnUser(ctx, req.TenantID, req.Subject, "")
	if appErr != nil {
		return appErr
	}

	// Parse the attestation response.
	parsedResponse, parseErr := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(envelope.Response))
	if parseErr != nil {
		return apperrors.New(apperrors.ErrBadRequest, "invalid attestation response: "+parseErr.Error())
	}

	credential, finishErr := w.CreateCredential(user, *sessionEnvelope.Session, parsedResponse)
	if finishErr != nil {
		return apperrors.New(apperrors.ErrBadRequest, "WebAuthn registration failed: "+finishErr.Error())
	}

	// Store the credential.
	credID, idErr := generateID()
	if idErr != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to generate credential ID", idErr)
	}

	storedCred := domainmfa.WebAuthnCredential{
		ID:              credID,
		Subject:         req.Subject,
		TenantID:        req.TenantID,
		CredentialID:    credential.ID,
		PublicKey:       credential.PublicKey,
		AAGUID:          credential.Authenticator.AAGUID,
		SignCount:       credential.Authenticator.SignCount,
		AttestationType: credential.AttestationType,
		DisplayName:     req.Subject,
		CreatedAt:       time.Now().UTC(),
	}

	if storeErr := s.webauthnRepo.Store(ctx, storedCred); storeErr != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to store WebAuthn credential", storeErr)
	}

	// Clean up session.
	s.challengeRepo.Delete(ctx, envelope.SessionID) //nolint:errcheck

	s.logger.Info("WebAuthn credential registered", "subject", req.Subject, "tenant_id", req.TenantID)
	return nil
}

// BeginWebAuthnLogin starts a WebAuthn authentication ceremony.
func (s *Service) BeginWebAuthnLogin(ctx context.Context, req WebAuthnLoginRequest) (json.RawMessage, *apperrors.AppError) {
	if s.webauthnRepo == nil {
		return nil, apperrors.New(apperrors.ErrBadRequest, "WebAuthn is not configured")
	}
	if req.Subject == "" {
		return nil, apperrors.New(apperrors.ErrBadRequest, "subject is required")
	}

	w, appErr := s.newWebAuthn()
	if appErr != nil {
		return nil, appErr
	}

	user, appErr := s.buildWebAuthnUser(ctx, req.TenantID, req.Subject, "")
	if appErr != nil {
		return nil, appErr
	}

	if len(user.credentials) == 0 {
		return nil, apperrors.New(apperrors.ErrNotFound, "no WebAuthn credentials registered")
	}

	assertion, session, err := w.BeginLogin(user)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to begin WebAuthn login", err)
	}

	sessionID, idErr := generateID()
	if idErr != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to generate session ID", idErr)
	}

	sessionEnvelope := webauthnSessionData{
		Session:  session,
		Subject:  req.Subject,
		TenantID: req.TenantID,
	}
	sessionJSON, marshalErr := json.Marshal(sessionEnvelope)
	if marshalErr != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to serialize session", marshalErr)
	}

	challenge := domainmfa.MFAChallenge{
		ID:        sessionID,
		Subject:   req.Subject,
		TenantID:  req.TenantID,
		Methods:   []string{"webauthn"},
		ExpiresAt: time.Now().UTC().Add(s.challengeTTL),
		Nonce:     string(sessionJSON),
	}
	if storeErr := s.challengeRepo.Store(ctx, challenge); storeErr != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to store WebAuthn session", storeErr)
	}

	assertionJSON, marshalErr := json.Marshal(assertion)
	if marshalErr != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to serialize assertion options", marshalErr)
	}

	resp := map[string]json.RawMessage{
		"challenge_id": json.RawMessage(`"` + sessionID + `"`),
		"options":      assertionJSON,
	}
	respJSON, marshalErr := json.Marshal(resp)
	if marshalErr != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to serialize response", marshalErr)
	}

	s.logger.Info("WebAuthn login started", "subject", req.Subject, "tenant_id", req.TenantID)
	return respJSON, nil
}

// FinishWebAuthnLogin completes a WebAuthn authentication ceremony.
func (s *Service) FinishWebAuthnLogin(ctx context.Context, req WebAuthnLoginFinishRequest) *apperrors.AppError {
	if s.webauthnRepo == nil {
		return apperrors.New(apperrors.ErrBadRequest, "WebAuthn is not configured")
	}
	if req.ChallengeID == "" {
		return apperrors.New(apperrors.ErrBadRequest, "challenge_id is required")
	}

	challenge, getErr := s.challengeRepo.GetByID(ctx, req.ChallengeID)
	if getErr != nil {
		return apperrors.New(apperrors.ErrNotFound, "WebAuthn session not found")
	}
	if challenge.IsExpired() {
		return apperrors.New(apperrors.ErrExpiredCode, "WebAuthn session has expired")
	}

	var sessionEnvelope webauthnSessionData
	if unmarshalErr := json.Unmarshal([]byte(challenge.Nonce), &sessionEnvelope); unmarshalErr != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to deserialize session", unmarshalErr)
	}

	w, appErr := s.newWebAuthn()
	if appErr != nil {
		return appErr
	}

	user, appErr := s.buildWebAuthnUser(ctx, sessionEnvelope.TenantID, sessionEnvelope.Subject, "")
	if appErr != nil {
		return appErr
	}

	parsedResponse, parseErr := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(req.Response))
	if parseErr != nil {
		return apperrors.New(apperrors.ErrBadRequest, "invalid assertion response: "+parseErr.Error())
	}

	credential, finishErr := w.ValidateLogin(user, *sessionEnvelope.Session, parsedResponse)
	if finishErr != nil {
		return apperrors.New(apperrors.ErrBadRequest, "WebAuthn authentication failed: "+finishErr.Error())
	}

	// Update sign count for the matched credential.
	storedCred, credErr := s.webauthnRepo.GetByCredentialID(ctx, credential.ID)
	if credErr == nil {
		s.webauthnRepo.UpdateSignCount(ctx, storedCred.ID, credential.Authenticator.SignCount) //nolint:errcheck
	}

	// Clean up session.
	s.challengeRepo.Delete(ctx, req.ChallengeID) //nolint:errcheck

	s.logger.Info("WebAuthn login verified", "subject", sessionEnvelope.Subject)
	return nil
}

// VerifyMFAWebAuthn handles WebAuthn verification within the MFA challenge flow.
func (s *Service) VerifyMFAWebAuthn(ctx context.Context, challenge domainmfa.MFAChallenge, assertionJSON []byte) *apperrors.AppError {
	if s.webauthnRepo == nil {
		return apperrors.New(apperrors.ErrBadRequest, "WebAuthn is not configured")
	}

	w, appErr := s.newWebAuthn()
	if appErr != nil {
		return appErr
	}

	user, appErr := s.buildWebAuthnUser(ctx, challenge.TenantID, challenge.Subject, "")
	if appErr != nil {
		return appErr
	}
	if len(user.credentials) == 0 {
		return apperrors.New(apperrors.ErrBadRequest, "no WebAuthn credentials registered")
	}

	// For MFA verify, we need a login session. Create one on the fly.
	_, session, err := w.BeginLogin(user)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to create WebAuthn session", err)
	}

	// Create a mock HTTP request from the assertion JSON to parse it.
	parsedResponse, parseErr := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(assertionJSON))
	if parseErr != nil {
		return apperrors.New(apperrors.ErrBadRequest, "invalid assertion response: "+parseErr.Error())
	}

	credential, finishErr := w.ValidateLogin(user, *session, parsedResponse)
	if finishErr != nil {
		return apperrors.New(apperrors.ErrBadRequest, "WebAuthn verification failed: "+finishErr.Error())
	}

	// Update sign count.
	storedCred, credErr := s.webauthnRepo.GetByCredentialID(ctx, credential.ID)
	if credErr == nil {
		s.webauthnRepo.UpdateSignCount(ctx, storedCred.ID, credential.Authenticator.SignCount) //nolint:errcheck
	}

	return nil
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
