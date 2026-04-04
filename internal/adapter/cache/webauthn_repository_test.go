package cache

import (
	"context"
	"testing"
	"time"

	"github.com/authplex/internal/domain/mfa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebAuthnRepo_StoreAndGetBySubject(t *testing.T) {
	repo := NewInMemoryWebAuthnRepository()
	ctx := context.Background()

	cred := mfa.WebAuthnCredential{
		ID:           "c1",
		Subject:      "user-1",
		TenantID:     "t1",
		CredentialID: []byte("cred-id-1"),
		PublicKey:    []byte("pubkey-1"),
		AAGUID:       []byte("aaguid"),
		SignCount:    0,
		CreatedAt:    time.Now().UTC(),
	}
	require.NoError(t, repo.Store(ctx, cred))

	creds, err := repo.GetBySubject(ctx, "t1", "user-1")
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "c1", creds[0].ID)
	assert.Equal(t, []byte("pubkey-1"), creds[0].PublicKey)
}

func TestWebAuthnRepo_GetBySubject_Empty(t *testing.T) {
	repo := NewInMemoryWebAuthnRepository()
	ctx := context.Background()

	creds, err := repo.GetBySubject(ctx, "t1", "nonexistent")
	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestWebAuthnRepo_GetBySubject_MultipleCredentials(t *testing.T) {
	repo := NewInMemoryWebAuthnRepository()
	ctx := context.Background()

	cred1 := mfa.WebAuthnCredential{ID: "c1", Subject: "user-1", TenantID: "t1", CredentialID: []byte("id-1"), PublicKey: []byte("pk-1")}
	cred2 := mfa.WebAuthnCredential{ID: "c2", Subject: "user-1", TenantID: "t1", CredentialID: []byte("id-2"), PublicKey: []byte("pk-2")}
	cred3 := mfa.WebAuthnCredential{ID: "c3", Subject: "user-2", TenantID: "t1", CredentialID: []byte("id-3"), PublicKey: []byte("pk-3")}

	require.NoError(t, repo.Store(ctx, cred1))
	require.NoError(t, repo.Store(ctx, cred2))
	require.NoError(t, repo.Store(ctx, cred3))

	creds, err := repo.GetBySubject(ctx, "t1", "user-1")
	require.NoError(t, err)
	assert.Len(t, creds, 2)
}

func TestWebAuthnRepo_GetByCredentialID(t *testing.T) {
	repo := NewInMemoryWebAuthnRepository()
	ctx := context.Background()

	cred := mfa.WebAuthnCredential{
		ID:           "c1",
		Subject:      "user-1",
		TenantID:     "t1",
		CredentialID: []byte("unique-cred-id"),
		PublicKey:    []byte("pubkey"),
	}
	require.NoError(t, repo.Store(ctx, cred))

	got, err := repo.GetByCredentialID(ctx, []byte("unique-cred-id"))
	require.NoError(t, err)
	assert.Equal(t, "c1", got.ID)
}

func TestWebAuthnRepo_GetByCredentialID_NotFound(t *testing.T) {
	repo := NewInMemoryWebAuthnRepository()
	ctx := context.Background()

	_, err := repo.GetByCredentialID(ctx, []byte("nonexistent"))
	require.Error(t, err)
}

func TestWebAuthnRepo_UpdateSignCount(t *testing.T) {
	repo := NewInMemoryWebAuthnRepository()
	ctx := context.Background()

	cred := mfa.WebAuthnCredential{
		ID:           "c1",
		Subject:      "user-1",
		TenantID:     "t1",
		CredentialID: []byte("cred-id"),
		PublicKey:    []byte("pubkey"),
		SignCount:    0,
	}
	require.NoError(t, repo.Store(ctx, cred))

	require.NoError(t, repo.UpdateSignCount(ctx, "c1", 5))

	got, err := repo.GetByCredentialID(ctx, []byte("cred-id"))
	require.NoError(t, err)
	assert.Equal(t, uint32(5), got.SignCount)
}

func TestWebAuthnRepo_UpdateSignCount_NotFound(t *testing.T) {
	repo := NewInMemoryWebAuthnRepository()
	ctx := context.Background()

	err := repo.UpdateSignCount(ctx, "nonexistent", 1)
	require.Error(t, err)
}

func TestWebAuthnRepo_Delete(t *testing.T) {
	repo := NewInMemoryWebAuthnRepository()
	ctx := context.Background()

	cred := mfa.WebAuthnCredential{
		ID:           "c1",
		Subject:      "user-1",
		TenantID:     "t1",
		CredentialID: []byte("cred-id"),
		PublicKey:    []byte("pubkey"),
	}
	require.NoError(t, repo.Store(ctx, cred))
	require.NoError(t, repo.Delete(ctx, "c1"))

	_, err := repo.GetByCredentialID(ctx, []byte("cred-id"))
	require.Error(t, err)
}

func TestWebAuthnRepo_Delete_Idempotent(t *testing.T) {
	repo := NewInMemoryWebAuthnRepository()
	ctx := context.Background()

	// Deleting a nonexistent entry should not error.
	require.NoError(t, repo.Delete(ctx, "nonexistent"))
}

func TestWebAuthnRepo_TenantIsolation(t *testing.T) {
	repo := NewInMemoryWebAuthnRepository()
	ctx := context.Background()

	cred1 := mfa.WebAuthnCredential{ID: "c1", Subject: "user-1", TenantID: "t1", CredentialID: []byte("id-1"), PublicKey: []byte("pk-1")}
	cred2 := mfa.WebAuthnCredential{ID: "c2", Subject: "user-1", TenantID: "t2", CredentialID: []byte("id-2"), PublicKey: []byte("pk-2")}

	require.NoError(t, repo.Store(ctx, cred1))
	require.NoError(t, repo.Store(ctx, cred2))

	creds, err := repo.GetBySubject(ctx, "t1", "user-1")
	require.NoError(t, err)
	assert.Len(t, creds, 1)
	assert.Equal(t, "c1", creds[0].ID)
}
