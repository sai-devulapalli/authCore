package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/authplex/internal/domain/token"
	apperrors "github.com/authplex/pkg/sdk/errors"
	goredis "github.com/redis/go-redis/v9"
)

const (
	devicePrefix   = "device:"
	userCodePrefix = "usercode:"
)

// DeviceCodeRepository implements token.DeviceCodeRepository using Redis.
type DeviceCodeRepository struct {
	rdb *goredis.Client
}

// NewDeviceCodeRepository creates a new Redis-backed device code repository.
func NewDeviceCodeRepository(rdb *goredis.Client) *DeviceCodeRepository {
	return &DeviceCodeRepository{rdb: rdb}
}

var _ token.DeviceCodeRepository = (*DeviceCodeRepository)(nil)

func (r *DeviceCodeRepository) Store(ctx context.Context, dc token.DeviceCode) error {
	data, err := json.Marshal(dc)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to marshal device code", err)
	}
	ttl := time.Until(dc.ExpiresAt)
	if ttl <= 0 {
		return nil
	}

	pipe := r.rdb.Pipeline()
	pipe.Set(ctx, devicePrefix+dc.DeviceCode, data, ttl)
	pipe.Set(ctx, userCodePrefix+dc.UserCode, dc.DeviceCode, ttl) // index: user_code → device_code
	_, err = pipe.Exec(ctx)
	return err
}

func (r *DeviceCodeRepository) GetByDeviceCode(ctx context.Context, deviceCode string) (token.DeviceCode, error) {
	data, err := r.rdb.Get(ctx, devicePrefix+deviceCode).Bytes()
	if err != nil {
		return token.DeviceCode{}, apperrors.New(apperrors.ErrNotFound, "device code not found")
	}
	var dc token.DeviceCode
	if err := json.Unmarshal(data, &dc); err != nil {
		return token.DeviceCode{}, apperrors.Wrap(apperrors.ErrInternal, "failed to unmarshal device code", err)
	}
	return dc, nil
}

func (r *DeviceCodeRepository) GetByUserCode(ctx context.Context, userCode string) (token.DeviceCode, error) {
	deviceCode, err := r.rdb.Get(ctx, userCodePrefix+userCode).Result()
	if err != nil {
		return token.DeviceCode{}, apperrors.New(apperrors.ErrNotFound, "device code not found")
	}
	return r.GetByDeviceCode(ctx, deviceCode)
}

func (r *DeviceCodeRepository) Authorize(ctx context.Context, userCode string, subject string) error {
	dc, err := r.GetByUserCode(ctx, userCode)
	if err != nil {
		return err
	}
	dc.Subject = subject
	dc.Authorized = true

	data, _ := json.Marshal(dc)
	ttl := time.Until(dc.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	return r.rdb.Set(ctx, devicePrefix+dc.DeviceCode, data, ttl).Err()
}

func (r *DeviceCodeRepository) Deny(ctx context.Context, userCode string) error {
	dc, err := r.GetByUserCode(ctx, userCode)
	if err != nil {
		return err
	}
	dc.Denied = true

	data, _ := json.Marshal(dc)
	ttl := time.Until(dc.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	return r.rdb.Set(ctx, devicePrefix+dc.DeviceCode, data, ttl).Err()
}
