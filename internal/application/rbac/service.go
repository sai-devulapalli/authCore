package rbac

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"

	auditsvc "github.com/authplex/internal/application/audit"
	domainaudit "github.com/authplex/internal/domain/audit"
	domainrbac "github.com/authplex/internal/domain/rbac"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// Service provides RBAC operations.
type Service struct {
	roleRepo   domainrbac.RoleRepository
	assignRepo domainrbac.AssignmentRepository
	auditSvc   *auditsvc.Service
	logger     *slog.Logger
}

// WithAudit configures audit event logging.
func (s *Service) WithAudit(a *auditsvc.Service) *Service {
	s.auditSvc = a
	return s
}

// NewService creates a new RBAC service.
func NewService(roleRepo domainrbac.RoleRepository, assignRepo domainrbac.AssignmentRepository, logger *slog.Logger) *Service {
	return &Service{roleRepo: roleRepo, assignRepo: assignRepo, logger: logger}
}

// CreateRole creates a new role.
func (s *Service) CreateRole(ctx context.Context, req CreateRoleRequest) (RoleResponse, *apperrors.AppError) {
	id, err := generateID()
	if err != nil {
		return RoleResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to generate ID", err)
	}

	role, valErr := domainrbac.NewRole(id, req.TenantID, req.Name, req.Description, req.Permissions)
	if valErr != nil {
		return RoleResponse{}, apperrors.Wrap(apperrors.ErrBadRequest, "invalid role", valErr)
	}

	if createErr := s.roleRepo.Create(ctx, role); createErr != nil {
		return RoleResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to create role", createErr)
	}

	s.logger.Info("role created", "role_id", role.ID, "name", role.Name, "tenant_id", role.TenantID)
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, req.TenantID, "system", "system", domainaudit.EventRoleCreated, "role", role.ID, nil, nil)
	}
	return toRoleResponse(role), nil
}

// GetRole returns a role by ID.
func (s *Service) GetRole(ctx context.Context, id, tenantID string) (RoleResponse, *apperrors.AppError) {
	role, err := s.roleRepo.GetByID(ctx, id, tenantID)
	if err != nil {
		return RoleResponse{}, apperrors.Wrap(apperrors.ErrNotFound, "role not found", err)
	}
	return toRoleResponse(role), nil
}

// ListRoles returns all roles for a tenant.
func (s *Service) ListRoles(ctx context.Context, tenantID string) ([]RoleResponse, *apperrors.AppError) {
	roles, err := s.roleRepo.List(ctx, tenantID)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to list roles", err)
	}
	result := make([]RoleResponse, len(roles))
	for i, r := range roles {
		result[i] = toRoleResponse(r)
	}
	return result, nil
}

// UpdateRole updates a role's permissions.
func (s *Service) UpdateRole(ctx context.Context, id string, req UpdateRoleRequest) (RoleResponse, *apperrors.AppError) {
	role, err := s.roleRepo.GetByID(ctx, id, req.TenantID)
	if err != nil {
		return RoleResponse{}, apperrors.Wrap(apperrors.ErrNotFound, "role not found", err)
	}

	if req.Description != "" {
		role.Description = req.Description
	}
	if req.Permissions != nil {
		role.Permissions = req.Permissions
	}

	if updateErr := s.roleRepo.Update(ctx, role); updateErr != nil {
		return RoleResponse{}, apperrors.Wrap(apperrors.ErrInternal, "failed to update role", updateErr)
	}

	s.logger.Info("role updated", "role_id", role.ID)
	return toRoleResponse(role), nil
}

// DeleteRole deletes a role.
func (s *Service) DeleteRole(ctx context.Context, id, tenantID string) *apperrors.AppError {
	if err := s.roleRepo.Delete(ctx, id, tenantID); err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to delete role", err)
	}
	s.logger.Info("role deleted", "role_id", id)
	return nil
}

// AssignRole assigns a role to a user.
func (s *Service) AssignRole(ctx context.Context, userID, roleID, tenantID string) *apperrors.AppError {
	if err := s.assignRepo.Assign(ctx, userID, roleID, tenantID); err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to assign role", err)
	}
	s.logger.Info("role assigned", "user_id", userID, "role_id", roleID)
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, tenantID, "system", "system", domainaudit.EventRoleAssigned, "role", roleID, nil, map[string]any{"user_id": userID})
	}
	return nil
}

// RevokeRole revokes a role from a user.
func (s *Service) RevokeRole(ctx context.Context, userID, roleID, tenantID string) *apperrors.AppError {
	if err := s.assignRepo.Revoke(ctx, userID, roleID, tenantID); err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to revoke role", err)
	}
	s.logger.Info("role revoked", "user_id", userID, "role_id", roleID)
	if s.auditSvc != nil {
		s.auditSvc.Log(ctx, tenantID, "system", "system", domainaudit.EventRoleRevoked, "role", roleID, nil, map[string]any{"user_id": userID})
	}
	return nil
}

// GetUserRoles returns all roles for a user.
func (s *Service) GetUserRoles(ctx context.Context, userID, tenantID string) ([]RoleResponse, *apperrors.AppError) {
	roles, err := s.assignRepo.GetUserRoles(ctx, userID, tenantID)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to get user roles", err)
	}
	result := make([]RoleResponse, len(roles))
	for i, r := range roles {
		result[i] = toRoleResponse(r)
	}
	return result, nil
}

// GetUserPermissions returns flattened permissions for a user.
func (s *Service) GetUserPermissions(ctx context.Context, userID, tenantID string) ([]string, *apperrors.AppError) {
	roles, err := s.assignRepo.GetUserRoles(ctx, userID, tenantID)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternal, "failed to get user roles", err)
	}
	return domainrbac.FlattenPermissions(roles), nil
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
