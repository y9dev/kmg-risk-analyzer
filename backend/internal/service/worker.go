package service

import (
	"context"
	"fmt"

	"certificate-radar/internal/domain"
)

type TargetScanner interface {
	ScanTarget(
		ctx context.Context,
		targetID string,
	) (*domain.ScanRecord, error)
}

type Worker struct {
	targets TargetRepository
	scans   TargetScanner
}

func NewWorker(
	targets TargetRepository,
	scans TargetScanner,
) *Worker {
	return &Worker{
		targets: targets,
		scans:   scans,
	}
}

type WorkerResult struct {
	TargetID string
	Record   *domain.ScanRecord
	Err      error
}

func (w *Worker) Run(ctx context.Context) []WorkerResult {
	targets, err := w.targets.List(ctx)
	if err != nil {
		return []WorkerResult{
			{
				Err: fmt.Errorf("list targets: %w", err),
			},
		}
	}

	results := make([]WorkerResult, 0, len(targets))

	for _, target := range targets {
		if !target.Enabled {
			continue
		}

		record, err := w.scans.ScanTarget(ctx, target.ID)

		results = append(results, WorkerResult{
			TargetID: target.ID,
			Record:   record,
			Err:      err,
		})
	}

	return results
}
