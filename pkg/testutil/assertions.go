package testutil

import (
	"testing"

	sdkerrors "github.com/authplex/pkg/sdk/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AssertResultOk asserts that a Result is successful and returns the value.
func AssertResultOk[T any](t *testing.T, r sdkerrors.Result[T]) T {
	t.Helper()
	require.True(t, r.IsOk(), "expected Result to be Ok, got error: %v", r.Error())
	return r.Value()
}

// AssertResultErr asserts that a Result is an error and returns the AppError.
func AssertResultErr[T any](t *testing.T, r sdkerrors.Result[T]) *sdkerrors.AppError {
	t.Helper()
	require.True(t, r.IsErr(), "expected Result to be Err, got value: %v", r.Value())
	return r.Error()
}

// AssertResultErrCode asserts that a Result is an error with a specific code.
func AssertResultErrCode[T any](t *testing.T, r sdkerrors.Result[T], code sdkerrors.ErrorCode) {
	t.Helper()
	appErr := AssertResultErr(t, r)
	assert.Equal(t, code, appErr.Code, "expected error code %s, got %s", code, appErr.Code)
}
