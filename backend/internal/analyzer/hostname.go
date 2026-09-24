package analyzer

import (
	"crypto/x509"

	"certificate-radar/internal/domain"
)

func validateHostname(
	target domain.Target,
	cert *x509.Certificate,
) domain.HostnameResult {
	serverName := target.ServerName

	if serverName == "" {
		serverName = target.Address
	}

	if err := cert.VerifyHostname(serverName); err != nil {
		return domain.HostnameResult{
			Status: domain.HostnameMismatch,
			Error:  err.Error(),
		}
	}

	return domain.HostnameResult{
		Status: domain.HostnameMatch,
	}
}
