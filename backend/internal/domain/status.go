package domain

type CertificateStatus string

const (
	StatusOK          CertificateStatus = "OK"
	StatusInformation CertificateStatus = "INFORMATION"
	StatusWarning     CertificateStatus = "WARNING"
	StatusCritical    CertificateStatus = "CRITICAL"
	StatusExpired     CertificateStatus = "EXPIRED"
)
