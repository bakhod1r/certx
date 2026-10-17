// Package notify delivers alerts through webhooks (Slack-compatible),
// Telegram and email. Secrets are never included in returned errors.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"strings"
	"time"
)

// Level is the severity of a message.
type Level string

const (
	Info    Level = "info"
	Warning Level = "warning"
	Error   Level = "error"
)

// Message is a notification.
type Message struct {
	Level Level
	Title string
	Lines []string
}

// Text renders the message as plain text.
func (m Message) Text() string {
	icon := map[Level]string{Info: "✅", Warning: "⚠️", Error: "❌"}[m.Level]
	host, _ := os.Hostname()
	var b strings.Builder
	fmt.Fprintf(&b, "%s CertX on %s: %s", icon, host, m.Title)
	for _, l := range m.Lines {
		b.WriteString("\n• " + l)
	}
	return b.String()
}

// Notifier sends messages to one channel.
type Notifier interface {
	Name() string
	Send(ctx context.Context, m Message) error
}

// FromEnv builds notifiers from CERTX_* environment variables.
func FromEnv() []Notifier {
	var ns []Notifier
	if u := os.Getenv("CERTX_WEBHOOK_URL"); u != "" {
		ns = append(ns, &Webhook{URL: u})
	}
	if t, c := os.Getenv("CERTX_TELEGRAM_TOKEN"), os.Getenv("CERTX_TELEGRAM_CHAT_ID"); t != "" && c != "" {
		ns = append(ns, &Telegram{Token: t, ChatID: c})
	}
	if a, to := os.Getenv("CERTX_SMTP_ADDR"), os.Getenv("CERTX_EMAIL_TO"); a != "" && to != "" {
		ns = append(ns, &Email{
			Addr: a, User: os.Getenv("CERTX_SMTP_USER"), Password: os.Getenv("CERTX_SMTP_PASSWORD"),
			From: os.Getenv("CERTX_EMAIL_FROM"), To: strings.Split(to, ","),
		})
	}
	return ns
}

// SendAll delivers m through every notifier and joins the errors.
func SendAll(ctx context.Context, ns []Notifier, m Message) error {
	var errs []error
	for _, n := range ns {
		if err := n.Send(ctx, m); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n.Name(), err))
		}
	}
	return errors.Join(errs...)
}

var client = &http.Client{Timeout: 15 * time.Second}

// Webhook POSTs a JSON payload. The "text" field makes it work with Slack
// and Mattermost incoming webhooks as-is.
type Webhook struct{ URL string }

func (w *Webhook) Name() string { return "webhook" }

func (w *Webhook) Send(ctx context.Context, m Message) error {
	host, _ := os.Hostname()
	body, _ := json.Marshal(map[string]any{
		"text": m.Text(), "level": m.Level, "title": m.Title, "lines": m.Lines,
		"host": host, "time": time.Now().UTC(),
	})
	return post(ctx, w.URL, "application/json", body, w.URL)
}

// Telegram sends through the Bot API.
type Telegram struct {
	Token   string
	ChatID  string
	BaseURL string // defaults to https://api.telegram.org
}

func (t *Telegram) Name() string { return "telegram" }

func (t *Telegram) Send(ctx context.Context, m Message) error {
	base := t.BaseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	form := url.Values{"chat_id": {t.ChatID}, "text": {m.Text()}, "disable_web_page_preview": {"true"}}
	return post(ctx, base+"/bot"+t.Token+"/sendMessage", "application/x-www-form-urlencoded", []byte(form.Encode()), t.Token)
}

// Email sends through SMTP (STARTTLS when the server offers it).
type Email struct {
	Addr     string // host:port
	User     string
	Password string
	From     string
	To       []string
}

func (e *Email) Name() string { return "email" }

func (e *Email) Send(_ context.Context, m Message) error {
	from := e.From
	if from == "" {
		host, _ := os.Hostname()
		from = "certx@" + host
	}
	var auth smtp.Auth
	if e.User != "" {
		host, _, _ := strings.Cut(e.Addr, ":")
		auth = smtp.PlainAuth("", e.User, e.Password, host)
	}
	msg := "From: " + from + "\r\nTo: " + strings.Join(e.To, ", ") +
		"\r\nSubject: [CertX] " + m.Title +
		"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + strings.ReplaceAll(m.Text(), "\n", "\r\n") + "\r\n"
	if err := smtp.SendMail(e.Addr, auth, from, e.To, []byte(msg)); err != nil {
		return redact(err, e.Password)
	}
	return nil
}

func post(ctx context.Context, u, contentType string, body []byte, secret string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return redact(err, secret)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		return redact(err, secret)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// redact removes secret (tokens embedded in URLs, passwords) from err.
func redact(err error, secret string) error {
	if secret == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), secret, "***"))
}
