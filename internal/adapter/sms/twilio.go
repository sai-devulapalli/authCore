package sms

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/authplex/internal/domain/otp"
)

// TwilioSender sends OTP via Twilio SMS API.
type TwilioSender struct {
	accountSID string
	authToken  string
	fromNumber string
	httpClient *http.Client
}

// NewTwilioSender creates a new Twilio SMS sender.
func NewTwilioSender(accountSID, authToken, fromNumber string) *TwilioSender {
	return &TwilioSender{
		accountSID: accountSID,
		authToken:  authToken,
		fromNumber: fromNumber,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

var _ otp.SMSSender = (*TwilioSender)(nil)

// SendOTP sends the OTP code via Twilio SMS.
func (s *TwilioSender) SendOTP(ctx context.Context, phone, code string) error {
	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", s.accountSID)

	body := fmt.Sprintf("Your verification code is: %s", code)

	form := url.Values{
		"To":   {phone},
		"From": {s.fromNumber},
		"Body": {body},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create Twilio request: %w", err)
	}
	req.SetBasicAuth(s.accountSID, s.authToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Twilio request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Twilio error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}
