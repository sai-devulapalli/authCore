package jwks

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/authplex/internal/domain/jwk"
	"github.com/authplex/internal/domain/tenant"
	apperrors "github.com/authplex/pkg/sdk/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock Repository ---

type mockRepo struct {
	storeFunc        func(ctx context.Context, kp jwk.KeyPair) error
	getActiveFunc    func(ctx context.Context, tenantID string) (jwk.KeyPair, error)
	getAllPublicFunc  func(ctx context.Context, tenantID string) ([]jwk.KeyPair, error)
	deactivateFunc   func(ctx context.Context, keyID string) error
}

func (m *mockRepo) Store(ctx context.Context, kp jwk.KeyPair) error {
	if m.storeFunc != nil {
		return m.storeFunc(ctx, kp)
	}
	return nil
}

func (m *mockRepo) GetActive(ctx context.Context, tenantID string) (jwk.KeyPair, error) {
	if m.getActiveFunc != nil {
		return m.getActiveFunc(ctx, tenantID)
	}
	return jwk.KeyPair{}, errors.New("not found")
}

func (m *mockRepo) GetAllPublic(ctx context.Context, tenantID string) ([]jwk.KeyPair, error) {
	if m.getAllPublicFunc != nil {
		return m.getAllPublicFunc(ctx, tenantID)
	}
	return nil, nil
}

func (m *mockRepo) Deactivate(ctx context.Context, keyID string) error {
	if m.deactivateFunc != nil {
		return m.deactivateFunc(ctx, keyID)
	}
	return nil
}

func (m *mockRepo) GetAllActiveTenantIDs(_ context.Context) ([]string, error) { return nil, nil }
func (m *mockRepo) DeleteInactive(_ context.Context, _ time.Time) (int64, error) { return 0, nil }

// --- Mock Generator ---

type mockGenerator struct {
	generateRSAFunc func() ([]byte, []byte, error)
	generateECFunc  func() ([]byte, []byte, error)
}

func (m *mockGenerator) GenerateRSA() ([]byte, []byte, error) {
	if m.generateRSAFunc != nil {
		return m.generateRSAFunc()
	}
	return []byte("rsa-priv"), []byte("rsa-pub"), nil
}

func (m *mockGenerator) GenerateEC() ([]byte, []byte, error) {
	if m.generateECFunc != nil {
		return m.generateECFunc()
	}
	return []byte("ec-priv"), []byte("ec-pub"), nil
}

// --- Mock Converter ---

type mockConverter struct {
	pemToPublicJWKFunc func(publicKeyPEM []byte, kid string, alg string) (jwk.PublicJWK, error)
}

func (m *mockConverter) PEMToPublicJWK(publicKeyPEM []byte, kid string, alg string) (jwk.PublicJWK, error) {
	if m.pemToPublicJWKFunc != nil {
		return m.pemToPublicJWKFunc(publicKeyPEM, kid, alg)
	}
	return jwk.PublicJWK{KTY: "RSA", KID: kid, ALG: alg, Use: "sig"}, nil
}

// --- Tests ---

func TestGetJWKS_ReturnsKeys(t *testing.T) {
	repo := &mockRepo{
		getAllPublicFunc: func(_ context.Context, _ string) ([]jwk.KeyPair, error) {
			return []jwk.KeyPair{
				{ID: "kid-1", Algorithm: "RS256", PublicKey: []byte("pub1")},
				{ID: "kid-2", Algorithm: "ES256", PublicKey: []byte("pub2")},
			}, nil
		},
	}
	conv := &mockConverter{}
	svc := NewService(repo, &mockGenerator{}, conv, slog.Default())

	set, appErr := svc.GetJWKS(context.Background(), "tenant-1")

	require.Nil(t, appErr)
	assert.Len(t, set.Keys, 2)
	assert.Equal(t, "kid-1", set.Keys[0].KID)
	assert.Equal(t, "kid-2", set.Keys[1].KID)
}

func TestGetJWKS_EmptyKeys(t *testing.T) {
	repo := &mockRepo{
		getAllPublicFunc: func(_ context.Context, _ string) ([]jwk.KeyPair, error) {
			return []jwk.KeyPair{}, nil
		},
	}
	svc := NewService(repo, &mockGenerator{}, &mockConverter{}, slog.Default())

	set, appErr := svc.GetJWKS(context.Background(), "tenant-1")

	require.Nil(t, appErr)
	assert.Empty(t, set.Keys)
}

func TestGetJWKS_RepoError(t *testing.T) {
	repo := &mockRepo{
		getAllPublicFunc: func(_ context.Context, _ string) ([]jwk.KeyPair, error) {
			return nil, errors.New("db error")
		},
	}
	svc := NewService(repo, &mockGenerator{}, &mockConverter{}, slog.Default())

	_, appErr := svc.GetJWKS(context.Background(), "tenant-1")

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInternal, appErr.Code)
}

func TestGetJWKS_ConverterError_SkipsKey(t *testing.T) {
	repo := &mockRepo{
		getAllPublicFunc: func(_ context.Context, _ string) ([]jwk.KeyPair, error) {
			return []jwk.KeyPair{
				{ID: "kid-bad", Algorithm: "RS256", PublicKey: []byte("bad")},
				{ID: "kid-good", Algorithm: "RS256", PublicKey: []byte("good")},
			}, nil
		},
	}
	callCount := 0
	conv := &mockConverter{
		pemToPublicJWKFunc: func(_ []byte, kid string, alg string) (jwk.PublicJWK, error) {
			callCount++
			if callCount == 1 {
				return jwk.PublicJWK{}, errors.New("conversion failed")
			}
			return jwk.PublicJWK{KTY: "RSA", KID: kid, ALG: alg, Use: "sig"}, nil
		},
	}
	svc := NewService(repo, &mockGenerator{}, conv, slog.Default())

	set, appErr := svc.GetJWKS(context.Background(), "tenant-1")

	require.Nil(t, appErr)
	assert.Len(t, set.Keys, 1)
	assert.Equal(t, "kid-good", set.Keys[0].KID)
}

func TestEnsureKeyPair_ReturnsExisting(t *testing.T) {
	existing := jwk.KeyPair{ID: "existing-kid", TenantID: "tenant-1", Active: true}
	repo := &mockRepo{
		getActiveFunc: func(_ context.Context, _ string) (jwk.KeyPair, error) {
			return existing, nil
		},
	}
	svc := NewService(repo, &mockGenerator{}, &mockConverter{}, slog.Default())

	kp, appErr := svc.EnsureKeyPair(context.Background(), "tenant-1", "new-kid", tenant.RS256)

	require.Nil(t, appErr)
	assert.Equal(t, "existing-kid", kp.ID)
}

func TestEnsureKeyPair_CreatesNew_RSA(t *testing.T) {
	var stored jwk.KeyPair
	repo := &mockRepo{
		storeFunc: func(_ context.Context, kp jwk.KeyPair) error {
			stored = kp
			return nil
		},
	}
	svc := NewService(repo, &mockGenerator{}, &mockConverter{}, slog.Default())

	kp, appErr := svc.EnsureKeyPair(context.Background(), "tenant-1", "new-kid", tenant.RS256)

	require.Nil(t, appErr)
	assert.Equal(t, "new-kid", kp.ID)
	assert.Equal(t, jwk.RSA, kp.KeyType)
	assert.Equal(t, "RS256", kp.Algorithm)
	assert.Equal(t, stored.ID, kp.ID)
}

func TestEnsureKeyPair_CreatesNew_EC(t *testing.T) {
	repo := &mockRepo{}
	svc := NewService(repo, &mockGenerator{}, &mockConverter{}, slog.Default())

	kp, appErr := svc.EnsureKeyPair(context.Background(), "tenant-1", "new-kid", tenant.ES256)

	require.Nil(t, appErr)
	assert.Equal(t, jwk.EC, kp.KeyType)
	assert.Equal(t, "ES256", kp.Algorithm)
}

func TestEnsureKeyPair_GeneratorError(t *testing.T) {
	gen := &mockGenerator{
		generateRSAFunc: func() ([]byte, []byte, error) {
			return nil, nil, errors.New("rng failure")
		},
	}
	svc := NewService(&mockRepo{}, gen, &mockConverter{}, slog.Default())

	_, appErr := svc.EnsureKeyPair(context.Background(), "tenant-1", "kid", tenant.RS256)

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInternal, appErr.Code)
}

func TestEnsureKeyPair_StoreError(t *testing.T) {
	repo := &mockRepo{
		storeFunc: func(_ context.Context, _ jwk.KeyPair) error {
			return errors.New("db error")
		},
	}
	svc := NewService(repo, &mockGenerator{}, &mockConverter{}, slog.Default())

	_, appErr := svc.EnsureKeyPair(context.Background(), "tenant-1", "kid", tenant.RS256)

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInternal, appErr.Code)
}

func TestRotateKey_DeactivatesOldAndCreatesNew(t *testing.T) {
	deactivated := false
	repo := &mockRepo{
		getActiveFunc: func(_ context.Context, _ string) (jwk.KeyPair, error) {
			return jwk.KeyPair{ID: "old-kid"}, nil
		},
		deactivateFunc: func(_ context.Context, keyID string) error {
			assert.Equal(t, "old-kid", keyID)
			deactivated = true
			return nil
		},
	}
	svc := NewService(repo, &mockGenerator{}, &mockConverter{}, slog.Default())

	kp, appErr := svc.RotateKey(context.Background(), "tenant-1", "new-kid", tenant.RS256)

	require.Nil(t, appErr)
	assert.True(t, deactivated)
	assert.Equal(t, "new-kid", kp.ID)
}

func TestRotateKey_NoExistingKey(t *testing.T) {
	svc := NewService(&mockRepo{}, &mockGenerator{}, &mockConverter{}, slog.Default())

	kp, appErr := svc.RotateKey(context.Background(), "tenant-1", "new-kid", tenant.RS256)

	require.Nil(t, appErr)
	assert.Equal(t, "new-kid", kp.ID)
}

func TestRotateKey_DeactivateError(t *testing.T) {
	repo := &mockRepo{
		getActiveFunc: func(_ context.Context, _ string) (jwk.KeyPair, error) {
			return jwk.KeyPair{ID: "old-kid"}, nil
		},
		deactivateFunc: func(_ context.Context, _ string) error {
			return errors.New("db error")
		},
	}
	svc := NewService(repo, &mockGenerator{}, &mockConverter{}, slog.Default())

	_, appErr := svc.RotateKey(context.Background(), "tenant-1", "new-kid", tenant.RS256)

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrInternal, appErr.Code)
}

func TestGetActiveKeyPair_Found(t *testing.T) {
	repo := &mockRepo{
		getActiveFunc: func(_ context.Context, _ string) (jwk.KeyPair, error) {
			return jwk.KeyPair{ID: "active-kid", Active: true}, nil
		},
	}
	svc := NewService(repo, &mockGenerator{}, &mockConverter{}, slog.Default())

	kp, appErr := svc.GetActiveKeyPair(context.Background(), "tenant-1")

	require.Nil(t, appErr)
	assert.Equal(t, "active-kid", kp.ID)
}

func TestGetActiveKeyPair_NotFound(t *testing.T) {
	svc := NewService(&mockRepo{}, &mockGenerator{}, &mockConverter{}, slog.Default())

	_, appErr := svc.GetActiveKeyPair(context.Background(), "tenant-1")

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrNotFound, appErr.Code)
}

func TestEnsureKeyPair_UnsupportedAlgorithm(t *testing.T) {
	svc := NewService(&mockRepo{}, &mockGenerator{}, &mockConverter{}, slog.Default())

	_, appErr := svc.EnsureKeyPair(context.Background(), "tenant-1", "kid", tenant.Algorithm("PS256"))

	require.NotNil(t, appErr)
	assert.Equal(t, apperrors.ErrBadRequest, appErr.Code)
}
