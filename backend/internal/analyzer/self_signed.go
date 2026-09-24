package analyzer

import "crypto/x509"

func isSelfSigned(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}

	return cert.CheckSignatureFrom(cert) == nil
}
