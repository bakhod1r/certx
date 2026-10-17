// Package certificate inspects X.509 certificates from local files and live
// TLS endpoints. Private-key material is never returned or logged.
package certificate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Info describes a certificate (leaf plus chain).
type Info struct {
	Source            string    `json:"source"`
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	DNSNames          []string  `json:"dns_names"`
	Serial            string    `json:"serial"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	DaysLeft          int       `json:"days_left"`
	SelfSigned        bool      `json:"self_signed"`
	ChainLength       int       `json:"chain_length"`
	ChainError        string    `json:"chain_error,omitempty"`
	KeyMatch          *bool     `json:"key_match,omitempty"`
	KeyError          string    `json:"key_error,omitempty"`
	KeyPermissive     bool      `json:"key_permissive,omitempty"`
	TLSVersion        string    `json:"tls_version,omitempty"`

	leaf *x509.Certificate
}

// Covers reports whether the certificate is valid for the host name.
func (i *Info) Covers(name string) bool {
	return i.leaf != nil && i.leaf.VerifyHostname(name) == nil
}

// Inspect reads a PEM certificate file and, when keyPath is set, checks that
// the private key matches it.
func Inspect(certPath, keyPath string, now time.Time) (*Info, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	certs, err := parsePEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", certPath, err)
	}
	info := describe(certs, "", now)
	info.Source = certPath

	if keyPath != "" {
		checkKey(info, data, keyPath)
	}
	return info, nil
}

func checkKey(info *Info, certPEM []byte, keyPath string) {
	fi, err := os.Stat(keyPath)
	if err != nil {
		info.KeyError = err.Error()
		return
	}
	info.KeyPermissive = fi.Mode().Perm()&0o077 != 0
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		info.KeyError = err.Error()
		return
	}
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	match := err == nil
	switch {
	case err == nil:
	case strings.Contains(err.Error(), "does not match"):
	default:
		// Never include key contents; the tls error text does not either.
		info.KeyError = "unable to parse private key"
		return
	}
	info.KeyMatch = &match
}

// InspectPEM describes PEM-encoded certificate data.
func InspectPEM(data []byte, now time.Time) (*Info, error) {
	certs, err := parsePEM(data)
	if err != nil {
		return nil, err
	}
	return describe(certs, "", now), nil
}

// Remote connects to host:port with the given SNI name and describes the
// certificate chain that is actually served.
func Remote(ctx context.Context, host string, port int, sni string, now time.Time) (*Info, error) {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		// Verification is performed explicitly below so that broken chains
		// can still be reported instead of failing the handshake.
		Config: &tls.Config{ServerName: sni, InsecureSkipVerify: true}, //nolint:gosec
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("server presented no certificate")
	}
	info := describe(state.PeerCertificates, sni, now)
	info.Source = "tls://" + net.JoinHostPort(host, strconv.Itoa(port))
	info.TLSVersion = tls.VersionName(state.Version)
	return info, nil
}

func parsePEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no PEM certificate found")
	}
	return certs, nil
}

func describe(certs []*x509.Certificate, dnsName string, now time.Time) *Info {
	leaf := certs[0]
	sum := sha256.Sum256(leaf.Raw)
	info := &Info{
		Subject:           name(leaf.Subject.CommonName, leaf.Subject.String()),
		Issuer:            name(leaf.Issuer.CommonName, leaf.Issuer.String()),
		DNSNames:          append([]string(nil), leaf.DNSNames...),
		Serial:            fmt.Sprintf("%X", leaf.SerialNumber),
		FingerprintSHA256: colonHex(sum[:]),
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
		DaysLeft:          int(math.Floor(leaf.NotAfter.Sub(now).Hours() / 24)),
		ChainLength:       len(certs),
		leaf:              leaf,
	}
	for _, ip := range leaf.IPAddresses {
		info.DNSNames = append(info.DNSNames, ip.String())
	}
	// CheckSignatureFrom would reject self-signed leaves without the CA flag.
	info.SelfSigned = bytes.Equal(leaf.RawIssuer, leaf.RawSubject) &&
		leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil

	if !info.SelfSigned {
		pool := x509.NewCertPool()
		for _, c := range certs[1:] {
			pool.AddCert(c)
		}
		opts := x509.VerifyOptions{Intermediates: pool, CurrentTime: now, DNSName: dnsName}
		if now.After(leaf.NotAfter) {
			opts.CurrentTime = leaf.NotAfter.Add(-time.Minute) // report chain problems separately from expiry
		}
		if _, err := leaf.Verify(opts); err != nil {
			info.ChainError = err.Error()
		}
	}
	return info
}

func name(cn, full string) string {
	if cn != "" {
		return cn
	}
	return full
}

func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}
