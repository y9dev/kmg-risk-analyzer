package service

import (
	"certificate-radar/internal/domain"
	"context"
)

type TargetRepository interface {
	Create(
		ctx context.Context,
		target domain.Target,
	) error

	Get(
		ctx context.Context,
		id string,
	) (domain.Target, error)

	List(
		ctx context.Context,
	) ([]domain.Target, error)

	Update(
		ctx context.Context,
		target domain.Target,
	) error

	Delete(ctx context.Context, id string) error
}
