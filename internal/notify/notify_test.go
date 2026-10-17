package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebhookAndTelegram(t *testing.T) {
	var gotJSON map[string]any
	var gotForm string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/hook":
			_ = json.Unmarshal(body, &gotJSON)
		case "/botSECRET/sendMessage":
			gotForm = string(body)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	m := Message{Level: Error, Title: "1 renewal failed", Lines: []string{"a.example: boom"}}
	err := SendAll(context.Background(), []Notifier{
		&Webhook{URL: srv.URL + "/hook"},
		&Telegram{Token: "SECRET", ChatID: "42", BaseURL: srv.URL},
	}, m)
	if err != nil {
		t.Fatal(err)
	}
	if gotJSON["level"] != "error" || !strings.Contains(gotJSON["text"].(string), "a.example: boom") {
		t.Errorf("webhook payload: %v", gotJSON)
	}
	if !strings.Contains(gotForm, "chat_id=42") {
		t.Errorf("telegram form: %s", gotForm)
	}

	// Errors must never leak the bot token.
	err = (&Telegram{Token: "SECRET", ChatID: "42", BaseURL: "http://127.0.0.1:1"}).Send(context.Background(), m)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("err = %v", err)
	}
	err = (&Webhook{URL: srv.URL + "/missing"}).Send(context.Background(), m)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("err = %v", err)
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("CERTX_WEBHOOK_URL", "https://hooks.example/x")
	t.Setenv("CERTX_TELEGRAM_TOKEN", "t")
	t.Setenv("CERTX_TELEGRAM_CHAT_ID", "")
	t.Setenv("CERTX_SMTP_ADDR", "smtp.example:587")
	t.Setenv("CERTX_EMAIL_TO", "a@example,b@example")
	var names []string
	for _, n := range FromEnv() {
		names = append(names, n.Name())
	}
	if strings.Join(names, ",") != "webhook,email" {
		t.Errorf("notifiers = %v", names)
	}
}
