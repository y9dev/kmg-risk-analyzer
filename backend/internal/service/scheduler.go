package service

import (
	"context"
	"fmt"
	"time"
)

type WorkerRunner interface {
	Run(ctx context.Context) []WorkerResult
}

type ScanBatchHandler func(results []WorkerResult)

type Scheduler struct {
	worker   WorkerRunner
	interval time.Duration
	handler  ScanBatchHandler
}

func NewScheduler(
	worker WorkerRunner,
	interval time.Duration,
	handler ScanBatchHandler,
) (*Scheduler, error) {
	if worker == nil {
		return nil, fmt.Errorf("worker is nil")
	}

	if interval <= 0 {
		return nil, fmt.Errorf("scheduler interval must be positive")
	}

	return &Scheduler{
		worker:   worker,
		interval: interval,
		handler:  handler,
	}, nil
}

func (s *Scheduler) Run(ctx context.Context) {
	s.runOnce(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

func (s *Scheduler) runOnce(ctx context.Context) {
	results := s.worker.Run(ctx)

	if s.handler != nil {
		s.handler(results)
	}
}
