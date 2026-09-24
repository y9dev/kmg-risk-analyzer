package risk

import (
	"testing"

	"certificate-radar/internal/domain"
)

func TestExpirationScore(t *testing.T) {
	tests := []struct {
		name     string
		daysLeft int
		expected int
	}{
		{
			name:     "expired",
			daysLeft: -1,
			expected: 50,
		},
		{
			name:     "one day",
			daysLeft: 1,
			expected: 40,
		},
		{
			name:     "seven days",
			daysLeft: 7,
			expected: 30,
		},
		{
			name:     "fourteen days",
			daysLeft: 14,
			expected: 20,
		},
		{
			name:     "thirty days",
			daysLeft: 30,
			expected: 10,
		},
		{
			name:     "more than thirty days",
			daysLeft: 31,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expirationScore(tt.daysLeft)

			if got != tt.expected {
				t.Fatalf(
					"expected %d, got %d",
					tt.expected,
					got,
				)
			}
		})
	}
}

func TestFindingScore(t *testing.T) {
	tests := []struct {
		name     string
		findings []domain.Finding
		expected int
	}{
		{
			name: "chain invalid",
			findings: []domain.Finding{
				{
					Type: domain.FindingChainInvalid,
				},
			},
			expected: 30,
		},
		{
			name: "hostname mismatch",
			findings: []domain.Finding{
				{
					Type: domain.FindingHostnameMismatch,
				},
			},
			expected: 30,
		},
		{
			name: "self signed",
			findings: []domain.Finding{
				{
					Type: domain.FindingSelfSigned,
				},
			},
			expected: 20,
		},
		{
			name: "weak key and weak signature",
			findings: []domain.Finding{
				{
					Type: domain.FindingWeakKey,
				},
				{
					Type: domain.FindingWeakSignature,
				},
			},
			expected: 30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findingScore(tt.findings)

			if got != tt.expected {
				t.Fatalf(
					"expected %d, got %d",
					tt.expected,
					got,
				)
			}
		})
	}
}

func TestLevelFromScore(t *testing.T) {
	tests := []struct {
		score    int
		expected domain.RiskLevel
	}{
		{score: 0, expected: domain.RiskLow},
		{score: 19, expected: domain.RiskLow},
		{score: 20, expected: domain.RiskMedium},
		{score: 39, expected: domain.RiskMedium},
		{score: 40, expected: domain.RiskHigh},
		{score: 69, expected: domain.RiskHigh},
		{score: 70, expected: domain.RiskCritical},
	}

	for _, tt := range tests {
		t.Run(
			string(tt.expected),
			func(t *testing.T) {
				got := levelFromScore(tt.score)

				if got != tt.expected {
					t.Fatalf(
						"expected %s, got %s",
						tt.expected,
						got,
					)
				}
			},
		)
	}
}

func TestEngineCalculate(t *testing.T) {
	engine := New()

	result := &domain.ScanResult{
		DaysLeft: 7,
		Findings: []domain.Finding{
			{
				Type: domain.FindingChainInvalid,
			},
			{
				Type: domain.FindingWeakKey,
			},
		},
		Criticality: domain.CriticalityHigh,
	}

	risk := engine.Calculate(result)

	// 30 expiration + 30 chain + 15 weak key + 10 criticality = 85.
	if risk.Score != 85 {
		t.Fatalf(
			"expected score 85, got %d",
			risk.Score,
		)
	}

	if risk.Level != domain.RiskCritical {
		t.Fatalf(
			"expected risk level %s, got %s",
			domain.RiskCritical,
			risk.Level,
		)
	}
}

func TestCriticalityScore(t *testing.T) {
	tests := []struct {
		name        string
		criticality domain.ServiceCriticality
		expected    int
	}{
		{
			name:        "low",
			criticality: domain.CriticalityLow,
			expected:    0,
		},
		{
			name:        "medium",
			criticality: domain.CriticalityMedium,
			expected:    5,
		},
		{
			name:        "high",
			criticality: domain.CriticalityHigh,
			expected:    10,
		},
		{
			name:        "critical",
			criticality: domain.CriticalityCritical,
			expected:    20,
		},
		{
			name:        "unknown",
			criticality: "",
			expected:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := criticalityScore(tt.criticality)

			if got != tt.expected {
				t.Fatalf(
					"expected %d, got %d",
					tt.expected,
					got,
				)
			}
		})
	}
}
