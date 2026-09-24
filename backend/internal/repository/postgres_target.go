package repository

import (
	"context"
	"errors"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"certificate-radar/internal/domain"
)

var ErrTargetNotFound = errors.New("target not found")

type PostgresTargetRepository struct {
	db *pgxpool.Pool
}

func NewPostgresTargetRepository(
	db *pgxpool.Pool,
) *PostgresTargetRepository {
	return &PostgresTargetRepository{
		db: db,
	}
}

func (r *PostgresTargetRepository) Create(
	ctx context.Context,
	target domain.Target,
) error {
	query, args, err := sq.
		Insert("targets").
		Columns(
			"id",
			"address",
			"port",
			"server_name",
			"enabled",
			"owner",
			"criticality",
		).
		Values(
			target.ID,
			target.Address,
			target.Port,
			target.ServerName,
			target.Enabled,
			target.Owner,
			target.Criticality,
		).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return fmt.Errorf("build create target query: %w", err)
	}

	_, err = r.db.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("create target: %w", err)
	}

	return nil
}

func (r *PostgresTargetRepository) Delete(
	ctx context.Context,
	id string,
) error {
	query, args, err := sq.
		Delete("targets").
		Where(sq.Eq{"id": id}).
		PlaceholderFormat(sq.Dollar).
		ToSql()

	if err != nil {
		return fmt.Errorf("build delete target query: %w", err)
	}

	tag, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("delete target: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return ErrTargetNotFound
	}

	return nil
}

func (r *PostgresTargetRepository) Get(
	ctx context.Context,
	id string,
) (domain.Target, error) {
	query, args, err := sq.
		Select(
			"id",
			"address",
			"port",
			"server_name",
			"enabled",
			"owner",
			"criticality",
		).
		From("targets").
		Where(sq.Eq{"id": id}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return domain.Target{}, fmt.Errorf(
			"build get target query: %w",
			err,
		)
	}

	var target domain.Target

	err = r.db.QueryRow(ctx, query, args...).Scan(
		&target.ID,
		&target.Address,
		&target.Port,
		&target.ServerName,
		&target.Enabled,
		&target.Owner,
		&target.Criticality,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Target{}, ErrTargetNotFound
		}

		return domain.Target{}, fmt.Errorf(
			"get target: %w",
			err,
		)
	}

	return target, nil
}

func (r *PostgresTargetRepository) List(
	ctx context.Context,
) ([]domain.Target, error) {
	query, args, err := sq.
		Select(
			"id",
			"address",
			"port",
			"server_name",
			"enabled",
			"owner",
			"criticality",
		).
		From("targets").
		OrderBy("id").
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf(
			"build list targets query: %w",
			err,
		)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	defer rows.Close()

	targets := make([]domain.Target, 0)

	for rows.Next() {
		var target domain.Target

		if err := rows.Scan(
			&target.ID,
			&target.Address,
			&target.Port,
			&target.ServerName,
			&target.Enabled,
			&target.Owner,
			&target.Criticality,
		); err != nil {
			return nil, fmt.Errorf(
				"scan target row: %w",
				err,
			)
		}

		targets = append(targets, target)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate target rows: %w",
			err,
		)
	}

	return targets, nil
}

func (r *PostgresTargetRepository) Update(
	ctx context.Context,
	target domain.Target,
) error {
	query, args, err := sq.
		Update("targets").
		Set("address", target.Address).
		Set("port", target.Port).
		Set("server_name", target.ServerName).
		Set("enabled", target.Enabled).
		Set("owner", target.Owner).
		Set("criticality", target.Criticality).
		Where(sq.Eq{"id": target.ID}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return fmt.Errorf(
			"build update target query: %w",
			err,
		)
	}

	tag, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update target: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return ErrTargetNotFound
	}

	return nil
}
