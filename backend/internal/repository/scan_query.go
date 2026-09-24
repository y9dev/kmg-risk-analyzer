package repository

import "certificate-radar/internal/domain"

type ScanListQuery struct {
	Limit  int
	Offset int

	Status      *domain.CertificateStatus
	RiskLevel   *domain.RiskLevel
	Owner       *string
	Criticality *domain.ServiceCriticality

	DaysLeftMin *int
	DaysLeftMax *int

	SortBy   string
	SortDesc bool

	Issuer *string
}
