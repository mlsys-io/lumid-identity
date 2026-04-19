package common

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/smtp"

	"lumid_identity/internal/config"
)

// Email sender for lumid-identity. Two public helpers:
//
//	SendVerificationCode — 6-digit OTP during registration
//	SendPasswordReset    — tokenized reset link for /auth/reset-password
//
// Falls back to stdout when no SMTP host is configured so dev
// environments don't need real creds. Same SMTPS-on-465 transport
// LQA's pkg/email uses, lifted into this service so lum.id owns the
// sender identity (yao@lum.id by default).

func emailConfigured() bool {
	return config.G != nil &&
		config.G.Email.SMTPHost != "" &&
		config.G.Email.SMTPUser != "" &&
		config.G.Email.FromAddress != ""
}

// SendVerificationCode sends a 6-digit OTP as a branded HTML email.
// On SMTP failure it returns the error so the caller can bubble a
// 500 to the client — but the OTP is already written to Redis, so
// retries work.
func SendVerificationCode(to, code string) error {
	if !emailConfigured() {
		log.Printf("[email/dev] verification code for %s: %s", to, code)
		return nil
	}
	subject := "Your lum.id verification code"
	body := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
 body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#1f2937;background:#f8fafc;margin:0;padding:24px;}
 .card{max-width:480px;margin:0 auto;background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.06);overflow:hidden;}
 .header{background:linear-gradient(135deg,#6366f1,#9333ea);color:#fff;padding:24px;text-align:center;}
 .header h1{margin:0;font-size:20px;font-weight:600;letter-spacing:.3px;}
 .body{padding:28px 24px;line-height:1.6;}
 .code{font-size:32px;font-weight:700;color:#4338ca;letter-spacing:8px;text-align:center;background:#eef2ff;border-radius:8px;padding:16px 0;margin:20px 0;font-family:Menlo,Consolas,monospace;}
 .muted{color:#6b7280;font-size:12px;text-align:center;margin-top:16px;}
</style></head><body>
<div class="card">
  <div class="header"><h1>lum.id</h1></div>
  <div class="body">
    <p>Your verification code for completing registration on lum.id:</p>
    <div class="code">%s</div>
    <p>The code is valid for 10 minutes. If you did not request this, you can safely ignore the email.</p>
    <p class="muted">— lum.id identity · Lumid ecosystem</p>
  </div>
</div>
</body></html>`, code)
	return sendHTML(to, subject, body)
}

// SendPasswordReset emails a tokenized reset link. The token has
// already been persisted server-side — we just deliver the URL.
func SendPasswordReset(to, token string) error {
	base := config.G.Email.ResetBaseURL
	if base == "" {
		base = "https://lum.id/auth/reset-password"
	}
	link := base + "?token=" + token
	if !emailConfigured() {
		log.Printf("[email/dev] password reset for %s: %s", to, link)
		return nil
	}
	subject := "Reset your lum.id password"
	body := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
 body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#1f2937;background:#f8fafc;margin:0;padding:24px;}
 .card{max-width:520px;margin:0 auto;background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.06);overflow:hidden;}
 .header{background:linear-gradient(135deg,#6366f1,#9333ea);color:#fff;padding:24px;text-align:center;}
 .header h1{margin:0;font-size:20px;font-weight:600;letter-spacing:.3px;}
 .body{padding:28px 24px;line-height:1.6;}
 .btn{display:inline-block;background:#4338ca;color:#fff !important;text-decoration:none;padding:12px 22px;border-radius:8px;font-weight:600;margin:16px 0;}
 .link{word-break:break-all;color:#6366f1;font-size:12px;}
 .muted{color:#6b7280;font-size:12px;text-align:center;margin-top:16px;}
</style></head><body>
<div class="card">
  <div class="header"><h1>lum.id</h1></div>
  <div class="body">
    <p>Someone — hopefully you — asked to reset the password on this lum.id account.</p>
    <p style="text-align:center;"><a class="btn" href="%s">Reset password</a></p>
    <p>If the button doesn't work, paste this into your browser:</p>
    <p class="link">%s</p>
    <p>The link expires in 30 minutes. If you didn't request a reset, ignore this email — your password is unchanged.</p>
    <p class="muted">— lum.id identity · Lumid ecosystem</p>
  </div>
</div>
</body></html>`, link, link)
	return sendHTML(to, subject, body)
}

// sendHTML dials SMTPS (implicit TLS on :465) the same way LQA does.
// Gmail blocks STARTTLS with app passwords; implicit TLS just works.
func sendHTML(to, subject, htmlBody string) error {
	cfg := config.G.Email
	port := cfg.SMTPPort
	if port == 0 {
		port = 465
	}
	fromName := cfg.FromName
	if fromName == "" {
		fromName = "lum.id"
	}
	from := fmt.Sprintf("%s <%s>", fromName, cfg.FromAddress)

	msg := "From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n\r\n" +
		htmlBody

	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPassword, cfg.SMTPHost)
	tlsCfg := &tls.Config{ServerName: cfg.SMTPHost}
	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, port)

	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()

	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := client.Mail(cfg.FromAddress); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}
