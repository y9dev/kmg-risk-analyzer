package analyzer

import (
	"time"

	"certificate-radar/internal/domain"
)

type StatusThresholds struct {
	InformationDays int
	WarningDays     int
	CriticalDays    int
}

func DefaultStatusThresholds() StatusThresholds {
	return StatusThresholds{
		InformationDays: 60,
		WarningDays:     30,
		CriticalDays:    14,
	}
}

func calculateStatus(
	validTo time.Time,
	now time.Time,
	thresholds StatusThresholds,
) domain.CertificateStatus {
	daysLeft := daysLeft(validTo, now)

	switch {
	case daysLeft < 0:
		return domain.StatusExpired

	case daysLeft <= thresholds.CriticalDays:
		return domain.StatusCritical

	case daysLeft <= thresholds.WarningDays:
		return domain.StatusWarning

	case daysLeft <= thresholds.InformationDays:
		return domain.StatusInformation

	default:
		return domain.StatusOK
	}
}
