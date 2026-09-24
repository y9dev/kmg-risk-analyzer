package service

import (
	"context"
	"fmt"

	"certificate-radar/internal/domain"
	"certificate-radar/internal/scanner"
)

type ScanRepository interface {
	Save(
		ctx context.Context,
		scan domain.ScanResult,
		risk domain.RiskResult,
	) error
}

type Analyzer interface {
	Analyze(
		ctx context.Context,
		result *scanner.Result,
	) (*domain.ScanResult, error)
}

type Scanner interface {
	Scan(
		ctx context.Context,
		target domain.Target,
	) (*scanner.Result, error)
}

type RiskEngine interface {
	Calculate(
		result *domain.ScanResult,
	) domain.RiskResult
}

type ScanService struct {
	targets  TargetRepository
	scanner  Scanner
	analyzer Analyzer
	risk     RiskEngine
	scans    ScanRepository
}

func NewScanService(
	targets TargetRepository,
	scanner Scanner,
	analyzer Analyzer,
	riskEngine RiskEngine,
	scans ScanRepository,
) *ScanService {
	return &ScanService{
		targets:  targets,
		scanner:  scanner,
		analyzer: analyzer,
		risk:     riskEngine,
		scans:    scans,
	}
}

func (s *ScanService) ScanTarget(
	ctx context.Context,
	targetID string,
) (*domain.ScanRecord, error) {
	target, err := s.targets.Get(ctx, targetID)
	if err != nil {
		return nil, fmt.Errorf(
			"get target %q: %w",
			targetID,
			err,
		)
	}

	if !target.Enabled {
		return nil, fmt.Errorf(
			"target %q is disabled",
			targetID,
		)
	}

	scanResult, err := s.scanner.Scan(ctx, target)
	if err != nil {
		return nil, fmt.Errorf(
			"scan target %q: %w",
			targetID,
			err,
		)
	}

	analysis, err := s.analyzer.Analyze(
		ctx,
		scanResult,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"analyze target %q: %w",
			targetID,
			err,
		)
	}

	riskResult := s.risk.Calculate(analysis)

	if err := s.scans.Save(
		ctx,
		*analysis,
		riskResult,
	); err != nil {
		return nil, fmt.Errorf(
			"save scan %q: %w",
			targetID,
			err,
		)
	}

	return &domain.ScanRecord{
		Scan: *analysis,
		Risk: riskResult,
	}, nil
}
