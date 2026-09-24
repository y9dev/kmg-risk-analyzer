package api

import (
	"certificate-radar/internal/domain"
	"certificate-radar/internal/repository"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

type fakeScanService struct {
	record   *domain.ScanRecord
	err      error
	targetID string
}

func (s *fakeScanService) ScanTarget(
	_ context.Context,
	targetID string,
) (*domain.ScanRecord, error) {
	s.targetID = targetID
	return s.record, s.err
}

type fakeScanReader struct {
	records []domain.ScanRecord
	err     error

	gotQuery repository.ScanListQuery

	latest    *domain.ScanRecord
	latestErr error
}

func (f *fakeScanReader) ListRecent(
	_ context.Context,
	query repository.ScanListQuery,
) ([]domain.ScanRecord, error) {
	f.gotQuery = query

	if f.err != nil {
		return nil, f.err
	}

	return f.records, nil
}

func (f *fakeScanReader) GetLatestByTarget(
	_ context.Context,
	_ string,
) (*domain.ScanRecord, error) {
	return f.latest, f.latestErr
}

func TestScanHandler_Scan(t *testing.T) {
	record := &domain.ScanRecord{
		Scan: domain.ScanResult{
			TargetID: "target-1",
			DaysLeft: 42,
			Status:   domain.StatusInformation,
		},
		Risk: domain.RiskResult{
			Score: 10,
			Level: domain.RiskLow,
		},
	}

	scanService := &fakeScanService{
		record: record,
	}

	handler := NewScanHandler(
		scanService,
		&fakeScanReader{},
	)

	router := gin.New()
	router.POST("/api/scans/:targetID", handler.Scan)

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/scans/target-1",
		nil,
	)

	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d: %s",
			http.StatusOK,
			rec.Code,
			rec.Body.String(),
		)
	}

	if scanService.targetID != "target-1" {
		t.Fatalf(
			"expected target-1, got %s",
			scanService.targetID,
		)
	}

	body := rec.Body.String()

	if !strings.Contains(body, `"days_left":42`) {
		t.Fatalf("days_left missing: %s", body)
	}

	if !strings.Contains(body, `"level":"LOW"`) {
		t.Fatalf("risk missing: %s", body)
	}
}
