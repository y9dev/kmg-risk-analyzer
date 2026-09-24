package analyzer

import (
	"crypto/x509"

	"certificate-radar/internal/domain"
	"certificate-radar/internal/scanner"
)

func validateChain(
	result *scanner.Result,
	cert *x509.Certificate,
) domain.ChainResult {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return domain.ChainResult{
			Status: domain.ChainUnknown,
			Error:  err.Error(),
		}
	}

	intermediates := x509.NewCertPool()

	for _, chainCert := range result.Certificates[1:] {
		intermediates.AddCert(chainCert)
	}

	options := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	if result.Target.ServerName != "" {
		options.DNSName = result.Target.ServerName
	} else {
		options.DNSName = result.Target.Address
	}

	if _, err := cert.Verify(options); err != nil {
		return domain.ChainResult{
			Status: domain.ChainInvalid,
			Error:  err.Error(),
		}
	}

	return domain.ChainResult{
		Status: domain.ChainValid,
	}
}
