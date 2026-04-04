package httputil

import (
	"encoding/json"
	"net/http"

	sdkerrors "github.com/authplex/pkg/sdk/errors"
)

// JSONResponse is the standard envelope for API responses.
type JSONResponse struct {
	Data  any    `json:"data,omitempty"`
	Error *Error `json:"error,omitempty"`
}

// Error is the standard error shape returned in API responses.
type Error struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// WriteJSON writes a JSON response with the given status code and data.
// Returns an error if marshaling fails, but never panics.
func WriteJSON(w http.ResponseWriter, status int, data any) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(JSONResponse{Data: data})
}

// WriteError maps an AppError to an HTTP response with the appropriate status code.
// Returns an error if marshaling fails, but never panics.
func WriteError(w http.ResponseWriter, appErr *sdkerrors.AppError) error {
	status := appErr.Code.HTTPStatus()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(JSONResponse{
		Error: &Error{
			Code:    string(appErr.Code),
			Message: appErr.Message,
			Details: appErr.Details,
		},
	})
}

// WriteRaw writes a raw JSON payload without the standard envelope.
// Used for OIDC spec-compliant responses that must match an exact schema.
func WriteRaw(w http.ResponseWriter, status int, data any) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

// MethodNotAllowed returns an AppError for unsupported HTTP methods.
func MethodNotAllowed(method string) *sdkerrors.AppError {
	return sdkerrors.New(sdkerrors.ErrBadRequest, "method not allowed: "+method)
}
