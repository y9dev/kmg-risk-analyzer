package domain

import "time"

type Certificate struct {
	FingerprintSHA256 string
	SerialNumber      string

	Subject     string
	CommonName  string
	DNSNames    []string
	IPAddresses []string
	Issuer      string

	ValidFrom time.Time
	ValidTo   time.Time

	SignatureAlgorithm string
	PublicKeyAlgorithm string
	PublicKeySize      int
}
