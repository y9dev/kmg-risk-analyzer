package analyzer

import (
	"context"
	"time"

	"certificate-radar/internal/domain"
	"certificate-radar/internal/scanner"
)

type Analyzer struct {
	thresholds StatusThresholds
	now        func() time.Time
}

func New() *Analyzer {
	return &Analyzer{
		thresholds: DefaultStatusThresholds(),
		now:        time.Now,
	}
}

func daysLeft(validTo, now time.Time) int {
	return int(validTo.Sub(now).Hours() / 24)
}

func (a *Analyzer) Analyze(
	ctx context.Context,
	result *scanner.Result,
) (*domain.ScanResult, error) {
	if len(result.Certificates) == 0 {
		return nil, ErrNoCertificate
	}

	cert := result.Certificates[0]
	now := a.now()

	analysis := &domain.ScanResult{
		ScannedAt: now,

		Certificate: certificateFromX509(cert),

		DaysLeft: daysLeft(
			cert.NotAfter,
			now,
		),

		Chain: validateChain(
			result,
			cert,
		),

		Hostname: validateHostname(
			result.Target,
			cert,
		),

		Status: calculateStatus(
			cert.NotAfter,
			now,
			a.thresholds,
		),

		SelfSigned: isSelfSigned(cert),

		TLSVersion:  result.TLSVersion,
		CipherSuite: result.CipherSuite,

		TargetID:    result.Target.ID,
		Owner:       result.Target.Owner,
		Criticality: result.Target.Criticality,
	}

	analysis.Findings = buildFindings(
		analysis,
	)

	analysis.Findings = append(
		analysis.Findings,
		buildCryptoFindings(cert)...,
	)

	return analysis, nil
}
