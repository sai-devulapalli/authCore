package httputil

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdkerrors "github.com/authplex/pkg/sdk/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeJSON(t *testing.T) {
	t.Run("valid JSON", func(t *testing.T) {
		body := strings.NewReader(`{"name":"Alice","age":30}`)
		r := httptest.NewRequest(http.MethodPost, "/", body)

		var target struct {
			Name string `json:"name"`
			Age  int    `json:"age"`
		}

		err := DecodeJSON(r, &target)
		assert.Nil(t, err)
		assert.Equal(t, "Alice", target.Name)
		assert.Equal(t, 30, target.Age)
	})

	t.Run("nil body", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.Body = nil

		var target struct{}
		err := DecodeJSON(r, &target)

		require.NotNil(t, err)
		assert.Equal(t, sdkerrors.ErrBadRequest, err.Code)
		assert.Contains(t, err.Message, "empty")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		body := strings.NewReader(`{invalid}`)
		r := httptest.NewRequest(http.MethodPost, "/", body)

		var target struct{}
		err := DecodeJSON(r, &target)

		require.NotNil(t, err)
		assert.Equal(t, sdkerrors.ErrBadRequest, err.Code)
	})

	t.Run("unknown fields rejected", func(t *testing.T) {
		body := strings.NewReader(`{"name":"Alice","unknown":"field"}`)
		r := httptest.NewRequest(http.MethodPost, "/", body)

		var target struct {
			Name string `json:"name"`
		}
		err := DecodeJSON(r, &target)

		require.NotNil(t, err)
		assert.Equal(t, sdkerrors.ErrBadRequest, err.Code)
	})
}

func TestQueryParam(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/?key=value", nil)
		assert.Equal(t, "value", QueryParam(r, "key", "default"))
	})

	t.Run("missing returns default", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		assert.Equal(t, "default", QueryParam(r, "key", "default"))
	})

	t.Run("empty returns default", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/?key=", nil)
		assert.Equal(t, "default", QueryParam(r, "key", "default"))
	})
}

func TestRequiredQueryParam(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/?code=abc123", nil)
		val, err := RequiredQueryParam(r, "code")

		assert.Nil(t, err)
		assert.Equal(t, "abc123", val)
	})

	t.Run("missing", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		val, err := RequiredQueryParam(r, "code")

		require.NotNil(t, err)
		assert.Equal(t, sdkerrors.ErrBadRequest, err.Code)
		assert.Empty(t, val)
	})
}
