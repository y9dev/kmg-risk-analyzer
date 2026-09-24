package api

import (
	"certificate-radar/internal/domain"
	"certificate-radar/internal/repository"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type ScanService interface {
	ScanTarget(
		ctx context.Context,
		targetID string,
	) (*domain.ScanRecord, error)
}

type ScanHandler struct {
	scanService ScanService
	scans       ScanReader
}

func NewScanHandler(
	scanService ScanService,
	scans ScanReader,
) *ScanHandler {
	return &ScanHandler{
		scanService: scanService,
		scans:       scans,
	}
}

type ScanReader interface {
	GetLatestByTarget(
		ctx context.Context,
		targetID string,
	) (*domain.ScanRecord, error)

	ListRecent(
		ctx context.Context,
		query repository.ScanListQuery,
	) ([]domain.ScanRecord, error)
}

func (h *ScanHandler) Scan(c *gin.Context) {
	targetID := strings.TrimSpace(c.Param("targetID"))

	record, err := h.scanService.ScanTarget(
		c.Request.Context(),
		targetID,
	)
	if err != nil {
		if errors.Is(err, repository.ErrTargetNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "target not found",
			})
			return
		}

		c.JSON(http.StatusBadGateway, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, toScanResponse(record))
}

func (h *ScanHandler) GetLatest(c *gin.Context) {
	targetID := strings.TrimSpace(c.Param("targetID"))

	record, err := h.scans.GetLatestByTarget(
		c.Request.Context(),
		targetID,
	)
	if err != nil {
		if errors.Is(err, repository.ErrScanNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "scan not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, toScanResponse(record))
}

const (
	defaultScanLimit = 50
	maxScanLimit     = 100
)

func (h *ScanHandler) ListRecent(c *gin.Context) {
	query, err := parseScanListQuery(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	records, err := h.scans.ListRecent(
		c.Request.Context(),
		repository.ScanListQuery{
			Limit:       query.Limit + 1,
			Offset:      query.Offset,
			Status:      query.Status,
			RiskLevel:   query.RiskLevel,
			Owner:       query.Owner,
			Criticality: query.Criticality,
			Issuer:      query.Issuer,
			DaysLeftMin: query.DaysLeftMin,
			DaysLeftMax: query.DaysLeftMax,
			SortBy:      query.SortBy,
			SortDesc:    query.SortDesc,
		},
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	hasMore := len(records) > query.Limit

	if hasMore {
		records = records[:query.Limit]
	}

	items := make([]scanResponse, 0, len(records))

	for _, record := range records {
		items = append(
			items,
			toScanResponse(&record),
		)
	}

	c.JSON(http.StatusOK, scanListResponse{
		Items:   items,
		Limit:   query.Limit,
		Offset:  query.Offset,
		HasMore: hasMore,
	})
}

type scanResponse struct {
	TargetID    string               `json:"target_id"`
	ScannedAt   string               `json:"scanned_at"`
	DaysLeft    int                  `json:"days_left"`
	Status      string               `json:"status"`
	Hostname    hostnameResponse     `json:"hostname"`
	Chain       chainResponse        `json:"chain"`
	SelfSigned  bool                 `json:"self_signed"`
	TLSVersion  uint16               `json:"tls_version"`
	CipherSuite uint16               `json:"cipher_suite"`
	Owner       string               `json:"owner"`
	Criticality string               `json:"criticality"`
	Certificate *certificateResponse `json:"certificate,omitempty"`
	Findings    []findingResponse    `json:"findings"`
	Risk        riskResponse         `json:"risk"`
}

type scanListResponse struct {
	Items   []scanResponse `json:"items"`
	Limit   int            `json:"limit"`
	Offset  int            `json:"offset"`
	HasMore bool           `json:"has_more"`
}

type hostnameResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type chainResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type certificateResponse struct {
	FingerprintSHA256  string   `json:"fingerprint_sha256"`
	SerialNumber       string   `json:"serial_number"`
	Subject            string   `json:"subject"`
	CommonName         string   `json:"common_name"`
	DNSNames           []string `json:"dns_names"`
	IPAddresses        []string `json:"ip_addresses"`
	Issuer             string   `json:"issuer"`
	ValidFrom          string   `json:"valid_from"`
	ValidTo            string   `json:"valid_to"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm"`
	PublicKeySize      int      `json:"public_key_size"`
}

type findingResponse struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type riskResponse struct {
	Score int    `json:"score"`
	Level string `json:"level"`
}

func toScanResponse(record *domain.ScanRecord) scanResponse {
	scan := record.Scan

	response := scanResponse{
		TargetID:  scan.TargetID,
		ScannedAt: scan.ScannedAt.Format(time.RFC3339),
		DaysLeft:  scan.DaysLeft,
		Status:    string(scan.Status),
		Hostname: hostnameResponse{
			Status: string(scan.Hostname.Status),
			Error:  scan.Hostname.Error,
		},
		Chain: chainResponse{
			Status: string(scan.Chain.Status),
			Error:  scan.Chain.Error,
		},
		SelfSigned:  scan.SelfSigned,
		TLSVersion:  scan.TLSVersion,
		CipherSuite: scan.CipherSuite,
		Owner:       scan.Owner,
		Criticality: string(scan.Criticality),
		Risk: riskResponse{
			Score: record.Risk.Score,
			Level: string(record.Risk.Level),
		},
		Findings: make([]findingResponse, 0, len(scan.Findings)),
	}

	if scan.Certificate != nil {
		response.Certificate = &certificateResponse{
			FingerprintSHA256:  scan.Certificate.FingerprintSHA256,
			SerialNumber:       scan.Certificate.SerialNumber,
			Subject:            scan.Certificate.Subject,
			CommonName:         scan.Certificate.CommonName,
			DNSNames:           append([]string(nil), scan.Certificate.DNSNames...),
			IPAddresses:        append([]string(nil), scan.Certificate.IPAddresses...),
			Issuer:             scan.Certificate.Issuer,
			ValidFrom:          scan.Certificate.ValidFrom.Format(time.RFC3339),
			ValidTo:            scan.Certificate.ValidTo.Format(time.RFC3339),
			SignatureAlgorithm: scan.Certificate.SignatureAlgorithm,
			PublicKeyAlgorithm: scan.Certificate.PublicKeyAlgorithm,
			PublicKeySize:      scan.Certificate.PublicKeySize,
		}
	}

	for _, finding := range scan.Findings {
		response.Findings = append(
			response.Findings,
			findingResponse{
				Type:     string(finding.Type),
				Severity: string(finding.Severity),
				Message:  finding.Message,
			},
		)
	}

	return response
}

func parseScanListQuery(c *gin.Context) (
	repository.ScanListQuery,
	error,
) {
	const (
		defaultLimit = 50
		maxLimit     = 100
	)

	query := repository.ScanListQuery{
		Limit:  defaultLimit,
		Offset: 0,
	}

	if value := c.Query("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || limit <= 0 {
			return query, fmt.Errorf(
				"limit must be a positive integer",
			)
		}

		if limit > maxLimit {
			return query, fmt.Errorf(
				"limit must be <= %d",
				maxLimit,
			)
		}

		query.Limit = limit
	}

	if value := c.Query("offset"); value != "" {
		offset, err := strconv.Atoi(value)
		if err != nil || offset < 0 {
			return query, fmt.Errorf(
				"offset must be a non-negative integer",
			)
		}

		query.Offset = offset
	}

	if value := c.Query("status"); value != "" {
		status := domain.CertificateStatus(
			strings.ToUpper(strings.TrimSpace(value)),
		)

		switch status {
		case domain.StatusOK,
			domain.StatusInformation,
			domain.StatusWarning,
			domain.StatusCritical,
			domain.StatusExpired:
			query.Status = &status

		default:
			return query, fmt.Errorf(
				"invalid status %q",
				value,
			)
		}
	}

	if value := c.Query("risk_level"); value != "" {
		level := domain.RiskLevel(
			strings.ToUpper(strings.TrimSpace(value)),
		)

		switch level {
		case domain.RiskLow,
			domain.RiskMedium,
			domain.RiskHigh,
			domain.RiskCritical:
			query.RiskLevel = &level

		default:
			return query, fmt.Errorf(
				"invalid risk_level %q",
				value,
			)
		}
	}

	if value := c.Query("owner"); value != "" {
		owner := strings.TrimSpace(value)

		if owner != "" {
			query.Owner = &owner
		}
	}

	if value := c.Query("issuer"); value != "" {
		issuer := strings.TrimSpace(value)

		if issuer != "" {
			query.Issuer = &issuer
		}
	}

	if value := c.Query("criticality"); value != "" {
		criticality := domain.ServiceCriticality(
			strings.ToUpper(strings.TrimSpace(value)),
		)

		switch criticality {
		case domain.CriticalityLow,
			domain.CriticalityMedium,
			domain.CriticalityHigh,
			domain.CriticalityCritical:
			query.Criticality = &criticality

		default:
			return query, fmt.Errorf(
				"invalid criticality %q",
				value,
			)
		}
	}

	if value := c.Query("days_left_min"); value != "" {
		days, err := strconv.Atoi(value)
		if err != nil {
			return query, fmt.Errorf(
				"days_left_min must be an integer",
			)
		}

		query.DaysLeftMin = &days
	}

	if value := c.Query("days_left_max"); value != "" {
		days, err := strconv.Atoi(value)
		if err != nil {
			return query, fmt.Errorf(
				"days_left_max must be an integer",
			)
		}

		query.DaysLeftMax = &days
	}

	if query.DaysLeftMin != nil &&
		query.DaysLeftMax != nil &&
		*query.DaysLeftMin > *query.DaysLeftMax {
		return query, fmt.Errorf(
			"days_left_min must be <= days_left_max",
		)
	}

	query.SortBy = "scanned_at"

	if value := c.Query("sort"); value != "" {
		switch value {
		case "days_left",
			"status",
			"risk_score",
			"owner",
			"criticality",
			"scanned_at":
			query.SortBy = value

		default:
			return query, fmt.Errorf(
				"invalid sort %q",
				value,
			)
		}
	}

	query.SortDesc = true

	if value := c.Query("order"); value != "" {
		switch strings.ToLower(value) {
		case "asc":
			query.SortDesc = false
		case "desc":
			query.SortDesc = true
		default:
			return query, fmt.Errorf(
				"order must be asc or desc",
			)
		}
	}

	return query, nil
}
