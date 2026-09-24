package domain

type FindingType string

const (
	FindingSelfSigned       FindingType = "SELF_SIGNED"
	FindingChainInvalid     FindingType = "CHAIN_INVALID"
	FindingHostnameMismatch FindingType = "HOSTNAME_MISMATCH"
	FindingExpired          FindingType = "EXPIRED"
	FindingWeakKey          FindingType = "WEAK_KEY"
	FindingWeakSignature    FindingType = "WEAK_SIGNATURE"
)

type FindingSeverity string

const (
	SeverityInfo     FindingSeverity = "INFO"
	SeverityWarning  FindingSeverity = "WARNING"
	SeverityCritical FindingSeverity = "CRITICAL"
)

type Finding struct {
	Type     FindingType
	Severity FindingSeverity
	Message  string
}
