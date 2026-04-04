package email

import (
	"context"
	"log/slog"

	"github.com/authplex/internal/domain/otp"
)

// ConsoleSender logs OTP to stdout (development mode).
type ConsoleSender struct {
	logger *slog.Logger
}

// NewConsoleSender creates a new console email sender.
func NewConsoleSender(logger *slog.Logger) *ConsoleSender {
	return &ConsoleSender{logger: logger}
}

var _ otp.EmailSender = (*ConsoleSender)(nil)

// SendOTP logs the OTP code to the console.
func (s *ConsoleSender) SendOTP(_ context.Context, to, code string) error {
	s.logger.Info("EMAIL OTP", "to", to, "code", code)
	return nil
}
