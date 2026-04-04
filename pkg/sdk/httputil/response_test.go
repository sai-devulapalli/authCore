package httputil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	sdkerrors "github.com/authplex/pkg/sdk/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]string{"key": "value"}

	err := WriteJSON(w, http.StatusOK, data)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

	var resp JSONResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotNil(t, resp.Data)
	assert.Nil(t, resp.Error)
}

func TestWriteError(t *testing.T) {
	tests := []struct {
		name       string
		appErr     *sdkerrors.AppError
		wantStatus int
		wantCode   string
	}{
		{
			name:       "not found",
			appErr:     sdkerrors.New(sdkerrors.ErrNotFound, "user not found"),
			wantStatus: 404,
			wantCode:   "NOT_FOUND",
		},
		{
			name:       "bad request with details",
			appErr:     sdkerrors.New(sdkerrors.ErrBadRequest, "validation failed").WithDetails(map[string]any{"field": "email"}),
			wantStatus: 400,
			wantCode:   "BAD_REQUEST",
		},
		{
			name:       "internal error",
			appErr:     sdkerrors.New(sdkerrors.ErrInternal, "unexpected"),
			wantStatus: 500,
			wantCode:   "INTERNAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			err := WriteError(w, tt.appErr)

			require.NoError(t, err)
			assert.Equal(t, tt.wantStatus, w.Code)

			var resp JSONResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Nil(t, resp.Data)
			require.NotNil(t, resp.Error)
			assert.Equal(t, tt.wantCode, resp.Error.Code)
		})
	}
}

func TestWriteRaw(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]string{"issuer": "https://auth.example.com"}

	err := WriteRaw(w, http.StatusOK, data)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Code)

	var raw map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	assert.Equal(t, "https://auth.example.com", raw["issuer"])
}

func TestMethodNotAllowed(t *testing.T) {
	appErr := MethodNotAllowed("POST")

	assert.Equal(t, sdkerrors.ErrBadRequest, appErr.Code)
	assert.Contains(t, appErr.Message, "POST")
}
