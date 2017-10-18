package tlsutil

import (
	"crypto/rand"
	"crypto/tls"
	"io"
	"time"

	"github.com/renthraysk/group"
)

type KeyRotator struct {
	cfg      *tls.Config
	duration time.Duration
	keys     [][32]byte
	stop     chan chan struct{}
}

func (r *KeyRotator) read(key []byte) (int, error) {
	if r.cfg.Rand != nil {
		return io.ReadFull(r.cfg.Rand, key)
	}
	return rand.Read(key)
}

func (r *KeyRotator) rotate() error {
	var key [32]byte

	if len(r.keys) < cap(r.keys) {
		r.keys = r.keys[:len(r.keys)+1]
	}
	copy(r.keys[1:], r.keys[:])

	_, err := r.read(key[:])
	if err == nil {
		r.keys[0] = key
	}
	r.cfg.SetSessionTicketKeys(r.keys)
	return err
}

func (r *KeyRotator) Start() error {
	timer := time.NewTicker(r.duration)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			r.rotate()

		case q := <-r.stop:
			close(q)
			return nil
		}
	}
}

func (r *KeyRotator) Stop(err error) {
	q := make(chan struct{})
	r.stop <- q
	<-q
}

// WithSessionTicketKeyRotation
func WithSessionTicketKeyRotation(g *group.Group, n int, d time.Duration) Option {
	return func(cfg *tls.Config) error {
		r := &KeyRotator{
			cfg:      cfg,
			duration: d,
			keys:     make([][32]byte, 0, n),
			stop:     make(chan chan struct{}),
		}
		if err := r.rotate(); err != nil {
			cfg.SessionTicketsDisabled = true
			return nil
		}
		g.Add(r)
		return nil
	}
}
