package repository

import (
	"context"

	"certificate-radar/internal/domain"
)

type TargetRepository interface {
	Create(ctx context.Context, target domain.Target) error
	Get(ctx context.Context, id string) (domain.Target, error)
	List(ctx context.Context) ([]domain.Target, error)
	Update(ctx context.Context, target domain.Target) error
	Delete(ctx context.Context, id string) error
}

type ScanRepository interface {
	Save(
		ctx context.Context,
		scan domain.ScanResult,
		risk domain.RiskResult,
	) error

	GetLatestByTarget(
		ctx context.Context,
		targetID string,
	) (*domain.ScanRecord, error)

	ListRecent(
		ctx context.Context,
		query ScanListQuery,
	) ([]domain.ScanRecord, error)
}
