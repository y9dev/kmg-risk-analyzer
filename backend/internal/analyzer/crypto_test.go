package analyzer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"certificate-radar/internal/domain"
)

func TestBuildCryptoFindings_WeakRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	cert := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKey:          &key.PublicKey,
		Subject:            pkix.Name{CommonName: "example.com"},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(24 * time.Hour),
	}

	findings := buildCryptoFindings(cert)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Type != domain.FindingWeakKey {
		t.Fatalf(
			"expected %s, got %s",
			domain.FindingWeakKey,
			findings[0].Type,
		)
	}
}

func TestBuildCryptoFindings_StrongRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	cert := &x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKey:          &key.PublicKey,
	}

	findings := buildCryptoFindings(cert)

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestBuildCryptoFindings_SHA1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	cert := &x509.Certificate{
		SignatureAlgorithm: x509.SHA1WithRSA,
		PublicKey:          &key.PublicKey,
	}

	findings := buildCryptoFindings(cert)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Type != domain.FindingWeakSignature {
		t.Fatalf(
			"expected %s, got %s",
			domain.FindingWeakSignature,
			findings[0].Type,
		)
	}
}

func TestBuildCryptoFindings_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	cert := &x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKey:          &key.PublicKey,
	}

	findings := buildCryptoFindings(cert)

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestBuildCryptoFindings_MD5(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	cert := &x509.Certificate{
		SignatureAlgorithm: x509.MD5WithRSA,
		PublicKey:          &key.PublicKey,
	}

	findings := buildCryptoFindings(cert)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Type != domain.FindingWeakSignature {
		t.Fatalf(
			"expected %s, got %s",
			domain.FindingWeakSignature,
			findings[0].Type,
		)
	}
}

func TestBuildCryptoFindings_NilCertificate(t *testing.T) {
	findings := buildCryptoFindings(nil)

	if findings != nil {
		t.Fatalf("expected nil findings, got %v", findings)
	}
}
