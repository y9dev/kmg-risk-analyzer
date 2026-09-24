package analyzer

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"

	"crypto/x509"

	"certificate-radar/internal/domain"
)

func certificateFromX509(cert *x509.Certificate) *domain.Certificate {
	hash := sha256.Sum256(cert.Raw)

	return &domain.Certificate{
		FingerprintSHA256: hex.EncodeToString(hash[:]),
		SerialNumber:      cert.SerialNumber.String(),

		Subject:     cert.Subject.String(),
		CommonName:  cert.Subject.CommonName,
		DNSNames:    append([]string(nil), cert.DNSNames...),
		IPAddresses: ipAddresses(cert),
		Issuer:      cert.Issuer.String(),

		ValidFrom: cert.NotBefore,
		ValidTo:   cert.NotAfter,

		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		PublicKeySize:      publicKeySize(cert),
	}
}

func ipAddresses(cert *x509.Certificate) []string {
	result := make([]string, 0, len(cert.IPAddresses))

	for _, ip := range cert.IPAddresses {
		result = append(result, ip.String())
	}

	return result
}

func publicKeySize(cert *x509.Certificate) int {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return key.Size() * 8

	case *ecdsa.PublicKey:
		return key.Params().BitSize

	case ed25519.PublicKey:
		return len(key) * 8

	default:
		return 0
	}
}
