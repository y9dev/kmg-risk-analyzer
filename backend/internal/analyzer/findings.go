package analyzer

import (
	"fmt"

	"certificate-radar/internal/domain"
)

func buildFindings(
	result *domain.ScanResult,
) []domain.Finding {
	findings := make([]domain.Finding, 0)

	if result.SelfSigned {
		findings = append(findings, domain.Finding{
			Type:     domain.FindingSelfSigned,
			Severity: domain.SeverityCritical,
			Message:  "certificate is self-signed",
		})
	}

	if result.Chain.Status == domain.ChainInvalid {
		message := "certificate chain validation failed"

		if result.Chain.Error != "" {
			message = fmt.Sprintf(
				"certificate chain validation failed: %s",
				result.Chain.Error,
			)
		}

		findings = append(findings, domain.Finding{
			Type:     domain.FindingChainInvalid,
			Severity: domain.SeverityCritical,
			Message:  message,
		})
	}

	if result.Hostname.Status == domain.HostnameMismatch {
		message := "certificate hostname does not match target"

		if result.Hostname.Error != "" {
			message = fmt.Sprintf(
				"certificate hostname mismatch: %s",
				result.Hostname.Error,
			)
		}

		findings = append(findings, domain.Finding{
			Type:     domain.FindingHostnameMismatch,
			Severity: domain.SeverityCritical,
			Message:  message,
		})
	}

	if result.Status == domain.StatusExpired {
		findings = append(findings, domain.Finding{
			Type:     domain.FindingExpired,
			Severity: domain.SeverityCritical,
			Message:  "certificate has expired",
		})
	}

	return findings
}
