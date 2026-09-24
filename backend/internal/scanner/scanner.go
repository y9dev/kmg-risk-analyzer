package scanner

import (
	"context"
	"crypto/x509"

	"certificate-radar/internal/domain"
)

type Scanner interface {
	Scan(ctx context.Context, target domain.Target) (*Result, error)
}

type Result struct {
	Target domain.Target

	Certificates []*x509.Certificate

	TLSVersion  uint16
	CipherSuite uint16
}
