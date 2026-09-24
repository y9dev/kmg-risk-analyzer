package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"certificate-radar/internal/domain"
)

type TLSScanner struct {
	timeout time.Duration
}

func NewTLSScanner(timeout time.Duration) *TLSScanner {
	return &TLSScanner{
		timeout: timeout,
	}
}

func (s *TLSScanner) Scan(
	ctx context.Context,
	target domain.Target,
) (*Result, error) {
	address := net.JoinHostPort(
		target.Address,
		fmt.Sprintf("%d", target.Port),
	)

	dialer := &net.Dialer{
		Timeout: s.timeout,
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf(
			"TCP connection to %s: %w",
			address,
			err,
		)
	}

	defer rawConn.Close()

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec
	}

	if target.ServerName != "" {
		tlsConfig.ServerName = target.ServerName
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf(
			"TLS handshake with %s: %w",
			address,
			err,
		)
	}

	state := tlsConn.ConnectionState()

	return &Result{
		Target:       target,
		Certificates: state.PeerCertificates,
		TLSVersion:   state.Version,
		CipherSuite:  state.CipherSuite,
	}, nil
}
