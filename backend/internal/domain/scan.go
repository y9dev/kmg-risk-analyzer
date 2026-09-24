package domain

import "time"

type ScanResult struct {
	TargetID  string
	ScannedAt time.Time

	Certificate *Certificate

	DaysLeft int

	Chain      ChainResult
	Hostname   HostnameResult
	Status     CertificateStatus
	SelfSigned bool

	Findings []Finding

	TLSVersion  uint16
	CipherSuite uint16

	Owner       string
	Criticality ServiceCriticality
}

type HostnameStatus string

const (
	HostnameMatch    HostnameStatus = "MATCH"
	HostnameMismatch HostnameStatus = "MISMATCH"
	HostnameUnknown  HostnameStatus = "UNKNOWN"
)

type HostnameResult struct {
	Status HostnameStatus
	Error  string
}
