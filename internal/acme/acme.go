// Package acme obtains certificates from an ACME CA (Let's Encrypt by
// default) through the lego library.
package acme

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	stdlog "log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/providers/http/webroot"
	"github.com/go-acme/lego/v4/registration"

	"github.com/bakhod1r/certx/internal/deployment"
)

const (
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
)

// SetLogOutput redirects lego's progress log (stderr by default).
func SetLogOutput(w io.Writer) {
	legolog.Logger = stdlog.New(w, "lego: ", stdlog.LstdFlags)
}

// DirectoryURL resolves "staging", "production" or a custom URL.
func DirectoryURL(s string) (string, error) {
	switch strings.ToLower(s) {
	case "", "staging":
		return LetsEncryptStaging, nil
	case "production", "prod":
		return LetsEncryptProduction, nil
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("invalid ACME directory %q (want staging, production or an https URL)", s)
	}
	return s, nil
}

// Request describes a certificate order.
type Request struct {
	Storage   string
	Directory string
	Email     string
	Domains   []string
	Webroot   string // HTTP-01 files are written to <Webroot>/.well-known/acme-challenge/
}

// Bundle holds PEM-encoded certificate material.
type Bundle struct {
	Leaf       []byte
	Chain      []byte
	FullChain  []byte
	PrivateKey []byte
}

// Obtain registers (or reuses) the ACME account and orders a certificate.
func Obtain(req Request) (*Bundle, error) {
	user, err := loadAccount(req.Storage, req.Directory, req.Email)
	if err != nil {
		return nil, fmt.Errorf("account: %w", err)
	}
	client, err := newClient(user, req)
	if err != nil {
		return nil, err
	}
	if user.Registration == nil {
		if err := register(client, user); err != nil {
			return nil, err
		}
	}
	res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: req.Domains, Bundle: true})
	if err != nil && strings.Contains(err.Error(), "accountDoesNotExist") {
		// The CA no longer knows the stored account (deactivated, or the
		// storage was moved between CAs). The client signs with the old
		// account URL, so build a fresh one, register again and retry once.
		user.Registration = nil
		if client, err = newClient(user, req); err != nil {
			return nil, err
		}
		if err := register(client, user); err != nil {
			return nil, err
		}
		res, err = client.Certificate.Obtain(certificate.ObtainRequest{Domains: req.Domains, Bundle: true})
	}
	if err != nil {
		return nil, explain(err)
	}
	leaf, chain := splitBundle(res.Certificate)
	if len(chain) == 0 {
		chain = res.IssuerCertificate
	}
	return &Bundle{Leaf: leaf, Chain: chain, FullChain: res.Certificate, PrivateKey: res.PrivateKey}, nil
}

func newClient(user *account, req Request) (*lego.Client, error) {
	cfg := lego.NewConfig(user)
	cfg.CADirURL = req.Directory
	cfg.Certificate.KeyType = certcrypto.EC256
	cfg.UserAgent = "certx"
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, explain(err)
	}
	provider, err := webroot.NewHTTPProvider(req.Webroot)
	if err != nil {
		return nil, err
	}
	if err := client.Challenge.SetHTTP01Provider(provider); err != nil {
		return nil, err
	}
	return client, nil
}

func register(client *lego.Client, user *account) error {
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return explain(fmt.Errorf("register account: %w", err))
	}
	user.Registration = reg
	return user.save()
}

func splitBundle(full []byte) (leaf, chain []byte) {
	block, rest := pem.Decode(full)
	if block == nil {
		return full, nil
	}
	return pem.EncodeToMemory(block), bytes.TrimLeft(rest, "\n")
}

var rateLimitRe = regexp.MustCompile(`(?i)rateLimited|too many (certificates|failed authorizations|new orders)`)

// explain turns common ACME failures into actionable messages.
func explain(err error) error {
	msg := err.Error()
	switch {
	case rateLimitRe.MatchString(msg):
		return fmt.Errorf("%w\nhint: Let's Encrypt rate limit reached; test with --acme staging and retry later", err)
	case strings.Contains(msg, "urn:ietf:params:acme:error:unauthorized") || strings.Contains(msg, "Invalid response"):
		return fmt.Errorf("%w\nhint: the CA could not fetch the HTTP-01 challenge; check that the domain resolves to this server and port 80 is reachable", err)
	case strings.Contains(msg, "urn:ietf:params:acme:error:dns"):
		return fmt.Errorf("%w\nhint: the domain does not resolve publicly", err)
	case strings.Contains(msg, "urn:ietf:params:acme:error:caa"):
		return fmt.Errorf("%w\nhint: a CAA DNS record forbids this CA from issuing for the domain", err)
	case strings.Contains(msg, "urn:ietf:params:acme:error:connection"):
		return fmt.Errorf("%w\nhint: the CA could not connect to port 80; check firewall and DNS", err)
	}
	return err
}

// account implements registration.User and is persisted under
// <storage>/accounts/<ca-host>/<email>/.
type account struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey
	dir          string
}

func (a *account) GetEmail() string                        { return a.Email }
func (a *account) GetRegistration() *registration.Resource { return a.Registration }
func (a *account) GetPrivateKey() crypto.PrivateKey        { return a.key }

func loadAccount(storage, directory, email string) (*account, error) {
	u, err := url.Parse(directory)
	if err != nil {
		return nil, err
	}
	id := email
	if id == "" {
		id = "default"
	}
	if strings.ContainsAny(id, `/\`) || strings.HasPrefix(id, ".") {
		return nil, fmt.Errorf("invalid email %q", email)
	}
	a := &account{Email: email, dir: filepath.Join(storage, "accounts", u.Host, id)}

	keyPEM, err := os.ReadFile(filepath.Join(a.dir, "key.pem"))
	switch {
	case err == nil:
		block, _ := pem.Decode(keyPEM)
		if block == nil {
			return nil, errors.New("account key: invalid PEM")
		}
		if a.key, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("account key: %w", err)
		}
	case errors.Is(err, fs.ErrNotExist):
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		a.key = k
		if err := a.save(); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	if data, err := os.ReadFile(filepath.Join(a.dir, "account.json")); err == nil {
		var stored account
		if err := json.Unmarshal(data, &stored); err != nil {
			return nil, err
		}
		a.Registration = stored.Registration
	}
	return a, nil
}

func (a *account) save() error {
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(a.key.(*ecdsa.PrivateKey))
	if err != nil {
		return err
	}
	if err := deployment.AtomicWrite(filepath.Join(a.dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return err
	}
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return deployment.AtomicWrite(filepath.Join(a.dir, "account.json"), append(data, '\n'), 0o600)
}
