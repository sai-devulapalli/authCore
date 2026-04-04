package email

import (
	"context"
	"fmt"
	"net/smtp"

	"github.com/authplex/internal/domain/otp"
)

// SMTPSender sends OTP via SMTP.
type SMTPSender struct {
	host     string
	port     int
	username string
	password string
	from     string
}

// NewSMTPSender creates a new SMTP email sender.
func NewSMTPSender(host string, port int, username, password, from string) *SMTPSender {
	return &SMTPSender{
		host:     host,
		port:     port,
		username: username,
		password: password,
		from:     from,
	}
}

var _ otp.EmailSender = (*SMTPSender)(nil)

// SendOTP sends the OTP code via SMTP email.
func (s *SMTPSender) SendOTP(_ context.Context, to, code string) error {
	subject := "Your verification code"
	body := fmt.Sprintf("Your verification code is: %s\n\nThis code expires in 5 minutes.", code)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", s.from, to, subject, body)

	addr := fmt.Sprintf("%s:%d", s.host, s.port)

	var auth smtp.Auth
	if s.username != "" {
		auth = smtp.PlainAuth("", s.username, s.password, s.host)
	}

	return smtp.SendMail(addr, auth, s.from, []string{to}, []byte(msg))
}
