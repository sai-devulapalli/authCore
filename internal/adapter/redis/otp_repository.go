package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/authplex/internal/domain/otp"
	apperrors "github.com/authplex/pkg/sdk/errors"
	goredis "github.com/redis/go-redis/v9"
)

const otpPrefix = "otp:"

// OTPRepository implements otp.Repository using Redis.
type OTPRepository struct {
	rdb *goredis.Client
}

// NewOTPRepository creates a new Redis-backed OTP repository.
func NewOTPRepository(rdb *goredis.Client) *OTPRepository {
	return &OTPRepository{rdb: rdb}
}

var _ otp.Repository = (*OTPRepository)(nil)

func otpKey(identifier, tenantID string) string {
	return otpPrefix + tenantID + ":" + identifier
}

func (r *OTPRepository) Store(ctx context.Context, o otp.OTP) error {
	data, err := json.Marshal(o)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to marshal OTP", err)
	}
	ttl := time.Until(o.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	return r.rdb.Set(ctx, otpKey(o.Identifier, o.TenantID), data, ttl).Err()
}

func (r *OTPRepository) Get(ctx context.Context, identifier, tenantID string) (otp.OTP, error) {
	data, err := r.rdb.Get(ctx, otpKey(identifier, tenantID)).Bytes()
	if err != nil {
		return otp.OTP{}, apperrors.New(apperrors.ErrNotFound, "OTP not found")
	}
	var o otp.OTP
	if err := json.Unmarshal(data, &o); err != nil {
		return otp.OTP{}, apperrors.Wrap(apperrors.ErrInternal, "failed to unmarshal OTP", err)
	}
	return o, nil
}

func (r *OTPRepository) IncrementAttempts(ctx context.Context, identifier, tenantID string) error {
	o, err := r.Get(ctx, identifier, tenantID)
	if err != nil {
		return err
	}
	o.Attempts++
	data, _ := json.Marshal(o)
	ttl := time.Until(o.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	return r.rdb.Set(ctx, otpKey(identifier, tenantID), data, ttl).Err()
}

func (r *OTPRepository) Delete(ctx context.Context, identifier, tenantID string) error {
	return r.rdb.Del(ctx, otpKey(identifier, tenantID)).Err()
}
