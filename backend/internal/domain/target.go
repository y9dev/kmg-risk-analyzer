package domain

type ServiceCriticality string

const (
	CriticalityLow      ServiceCriticality = "LOW"
	CriticalityMedium   ServiceCriticality = "MEDIUM"
	CriticalityHigh     ServiceCriticality = "HIGH"
	CriticalityCritical ServiceCriticality = "CRITICAL"
)

type Target struct {
	ID         string
	Address    string
	Port       int
	ServerName string
	Enabled    bool

	Owner       string
	Criticality ServiceCriticality
}
