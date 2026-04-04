package sms

import (
	"context"
	"log/slog"

	"github.com/authplex/internal/domain/otp"
)

// ConsoleSender logs OTP to stdout (development mode).
type ConsoleSender struct {
	logger *slog.Logger
}

// NewConsoleSender creates a new console SMS sender.
func NewConsoleSender(logger *slog.Logger) *ConsoleSender {
	return &ConsoleSender{logger: logger}
}

var _ otp.SMSSender = (*ConsoleSender)(nil)

// SendOTP logs the OTP code to the console.
func (s *ConsoleSender) SendOTP(_ context.Context, phone, code string) error {
	s.logger.Info("SMS OTP", "phone", phone, "code", code)
	return nil
}
