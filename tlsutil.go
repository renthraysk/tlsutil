package tlsutil

import (
	"crypto/tls"
	"os"

	"github.com/pkg/errors"

	"golang.org/x/crypto/acme/autocert"
)

type Option func(*tls.Config) error

// Wrap wraps multiple Options into one.
func Wrap(opts ...Option) Option {
	return func(cfg *tls.Config) error {
		for _, opt := range opts {
			if err := opt(cfg); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithKeyPair load a certificate from a certFile, keyFile pair, and append to tls.Config's Certificates
func WithKeyPair(certFile, keyFile string) Option {
	return func(cfg *tls.Config) error {
		cer, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return errors.Wrap(err, "failed to load keypair")
		}
		cfg.Certificates = append(cfg.Certificates, cer)
		return nil
	}
}

type ACMEOption func(*autocert.Manager) error

// AMCEWrap wraps multiple ACMEOptions into one.
func ACMEWrap(opts ...ACMEOption) ACMEOption {
	return func(mgr *autocert.Manager) error {
		for _, opt := range opts {
			if err := opt(mgr); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithACME configures TLS to use ACME, configure by a ACMEOptions.
func WithACME(opts ...ACMEOption) Option {
	return func(cfg *tls.Config) error {
		mgr := &autocert.Manager{
			Prompt: autocert.AcceptTOS,
		}
		for _, opt := range opts {
			if err := opt(mgr); err != nil {
				return err
			}
		}
		cfg.GetCertificate = mgr.GetCertificate
		return nil
	}
}

// WithACMEHosts adds hosts to the ACME host policy.
func WithACMEHosts(hosts []string) ACMEOption {
	return func(mgr *autocert.Manager) error {
		if len(hosts) > 0 {
			mgr.HostPolicy = autocert.HostWhitelist(hosts...)
		}
		return nil
	}
}

// WithACMEDirCache configures a cache directory for ACME certificates.
func WithACMEDirCache(dir string) ACMEOption {
	return func(mgr *autocert.Manager) error {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		mgr.Cache = autocert.DirCache(dir)
		return nil
	}
}

// WithTLS12 configures a tls.Config to the intersection of Mozilla's modern compatibility, and go's capability.
// https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
// https://blog.gopheracademy.com/advent-2016/exposing-go-on-the-internet/
func WithTLS12() Option {
	return func(cfg *tls.Config) error {
		cfg.MinVersion = tls.VersionTLS12
		cfg.PreferServerCipherSuites = true
		cfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
		cfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		}
		return nil
	}
}

// NewTLSConfig returns a new tls.Config with all options applied.
func NewTLSConfig(opts ...Option) (*tls.Config, error) {
	cfg := &tls.Config{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}
