package analyzer

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"

	"certificate-radar/internal/domain"
)

func buildCryptoFindings(cert *x509.Certificate) []domain.Finding {
	if cert == nil {
		return nil
	}

	findings := make([]domain.Finding, 0)

	if isWeakPublicKey(cert) {
		findings = append(findings, domain.Finding{
			Type:     domain.FindingWeakKey,
			Severity: domain.SeverityWarning,
			Message:  weakKeyMessage(cert),
		})
	}

	if isWeakSignature(cert) {
		findings = append(findings, domain.Finding{
			Type:     domain.FindingWeakSignature,
			Severity: domain.SeverityWarning,
			Message:  weakSignatureMessage(cert),
		})
	}

	return findings
}

func isWeakPublicKey(cert *x509.Certificate) bool {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return key.Size()*8 < 2048

	case *ecdsa.PublicKey:
		return key.Params().BitSize < 224

	default:
		return false
	}
}

func isWeakSignature(cert *x509.Certificate) bool {
	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA,
		x509.MD5WithRSA,
		x509.SHA1WithRSA,
		x509.DSAWithSHA1,
		x509.ECDSAWithSHA1:
		return true

	default:
		return false
	}
}

func weakKeyMessage(cert *x509.Certificate) string {
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA public key is smaller than 2048 bits"

	case *ecdsa.PublicKey:
		return "ECDSA curve is weaker than 224 bits"

	default:
		return "public key parameters are weak"
	}
}

func weakSignatureMessage(cert *x509.Certificate) string {
	return "certificate uses a weak signature algorithm: " +
		cert.SignatureAlgorithm.String()
}
