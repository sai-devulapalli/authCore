package testutil

import (
	"testing"

	sdkerrors "github.com/authplex/pkg/sdk/errors"
)

func TestAssertResultOk(t *testing.T) {
	r := sdkerrors.Ok(42)
	val := AssertResultOk(t, r)
	if val != 42 {
		t.Errorf("expected 42, got %d", val)
	}
}

func TestAssertResultErr(t *testing.T) {
	r := sdkerrors.Err[int](sdkerrors.New(sdkerrors.ErrNotFound, "not found"))
	appErr := AssertResultErr(t, r)
	if appErr.Code != sdkerrors.ErrNotFound {
		t.Errorf("expected NOT_FOUND, got %s", appErr.Code)
	}
}

func TestAssertResultErrCode(t *testing.T) {
	r := sdkerrors.Err[string](sdkerrors.New(sdkerrors.ErrBadRequest, "invalid"))
	AssertResultErrCode(t, r, sdkerrors.ErrBadRequest)
}
