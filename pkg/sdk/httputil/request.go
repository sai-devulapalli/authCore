package httputil

import (
	"encoding/json"
	"net/http"

	sdkerrors "github.com/authplex/pkg/sdk/errors"
)

// DecodeJSON reads and decodes the request body as JSON into the provided target.
// Returns an AppError on failure, never panics.
func DecodeJSON(r *http.Request, target any) *sdkerrors.AppError {
	if r.Body == nil {
		return sdkerrors.New(sdkerrors.ErrBadRequest, "request body is empty")
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return sdkerrors.Wrap(sdkerrors.ErrBadRequest, "invalid JSON in request body", err)
	}

	return nil
}

// QueryParam returns a query parameter value, or the default if not present.
func QueryParam(r *http.Request, key string, defaultValue string) string {
	val := r.URL.Query().Get(key)
	if val == "" {
		return defaultValue
	}
	return val
}

// RequiredQueryParam returns a query parameter value, or an AppError if missing.
func RequiredQueryParam(r *http.Request, key string) (string, *sdkerrors.AppError) {
	val := r.URL.Query().Get(key)
	if val == "" {
		return "", sdkerrors.New(sdkerrors.ErrBadRequest, "missing required query parameter: "+key)
	}
	return val, nil
}
