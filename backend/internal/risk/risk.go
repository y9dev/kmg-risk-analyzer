package risk

import (
	"certificate-radar/internal/domain"
)

type Engine struct {
}

func New() *Engine {
	return &Engine{}
}

func (e *Engine) Calculate(
	result *domain.ScanResult,
) domain.RiskResult {
	score := 0

	score += expirationScore(result.DaysLeft)
	score += findingScore(result.Findings)
	score += criticalityScore(result.Criticality)

	return domain.RiskResult{
		Score: score,
		Level: levelFromScore(score),
	}
}

func expirationScore(daysLeft int) int {
	switch {
	case daysLeft < 0:
		return 50
	case daysLeft <= 1:
		return 40
	case daysLeft <= 7:
		return 30
	case daysLeft <= 14:
		return 20
	case daysLeft <= 30:
		return 10
	default:
		return 0
	}
}

func findingScore(findings []domain.Finding) int {
	score := 0

	for _, finding := range findings {
		switch finding.Type {
		case domain.FindingChainInvalid:
			score += 30

		case domain.FindingHostnameMismatch:
			score += 30

		case domain.FindingSelfSigned:
			score += 20

		case domain.FindingWeakKey:
			score += 15

		case domain.FindingWeakSignature:
			score += 15

		case domain.FindingExpired:
			// Expiration is already accounted for by DaysLeft.
		}
	}

	return score
}

func levelFromScore(score int) domain.RiskLevel {
	switch {
	case score >= 70:
		return domain.RiskCritical
	case score >= 40:
		return domain.RiskHigh
	case score >= 20:
		return domain.RiskMedium
	default:
		return domain.RiskLow
	}
}

func criticalityScore(
	criticality domain.ServiceCriticality,
) int {
	switch criticality {
	case domain.CriticalityCritical:
		return 20

	case domain.CriticalityHigh:
		return 10

	case domain.CriticalityMedium:
		return 5

	case domain.CriticalityLow:
		return 0

	default:
		return 0
	}
}
