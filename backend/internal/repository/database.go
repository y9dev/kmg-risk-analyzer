package repository

import (
	"certificate-radar/internal/config"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DatabaseConfig struct {
	URL string

	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

type MigrationConfig struct {
	MigrationsPath string
	Direction      string
	Steps          int
}

func NewPool(
	ctx context.Context,
	cfg DatabaseConfig,
) (*pgxpool.Pool, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("database URL is empty")
	}

	poolConfig, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf(
			"parse database config: %w",
			err,
		)
	}

	if cfg.MaxConns > 0 {
		poolConfig.MaxConns = cfg.MaxConns
	}

	if cfg.MinConns > 0 {
		poolConfig.MinConns = cfg.MinConns
	}

	if cfg.MaxConnLifetime > 0 {
		poolConfig.MaxConnLifetime = cfg.MaxConnLifetime
	}

	if cfg.MaxConnIdleTime > 0 {
		poolConfig.MaxConnIdleTime = cfg.MaxConnIdleTime
	}

	pool, err := pgxpool.NewWithConfig(
		ctx,
		poolConfig,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create postgres pool: %w",
			err,
		)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()

		return nil, fmt.Errorf(
			"ping postgres: %w",
			err,
		)
	}

	return pool, nil
}

func RunMigrations(ctx context.Context, migrationConfig *MigrationConfig, pool *pgxpool.Pool) error {
	if err := pool.Ping(ctx); err != nil {
		return err
	}

	absPath, err := filepath.Abs(migrationConfig.MigrationsPath)
	if err != nil {
		return fmt.Errorf("invalid migrations path: %w", err)
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return fmt.Errorf("migrations directory does not exist: %s", absPath)
	}

	db, err := sql.Open("postgres", config.DatabaseURL())
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("could not create migration driver: %w", err)
	}

	migrationSource := "file://" + filepath.ToSlash(absPath)

	m, err := migrate.NewWithDatabaseInstance(
		migrationSource,
		"postgres",
		driver,
	)
	if err != nil {
		return fmt.Errorf("migration initialization failed: %w", err)
	}

	version, dirty, verErr := m.Version()
	if verErr != nil && verErr != migrate.ErrNilVersion {
		return fmt.Errorf("failed to get migration version: %w", verErr)
	}

	if dirty {
		slog.Warn("Detected dirty migration: forcing pointer and running down script")

		if err := m.Force(int(version)); err != nil {
			return fmt.Errorf("failed to force migration version: %w", err)
		}

		if err := m.Steps(-1); err != nil && err != migrate.ErrNoChange {
			return fmt.Errorf("failed to run down migration: %w", err)
		}

		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			return fmt.Errorf("failed to re-apply migrations: %w", err)
		}

		slog.Info("Down + re-Up completed successfully")
		return nil
	}

	var migErr error
	switch migrationConfig.Direction {
	case "up":
		if migrationConfig.Steps > 0 {
			migErr = m.Steps(migrationConfig.Steps)
		} else {
			migErr = m.Up()
		}
	case "down":
		if migrationConfig.Steps > 0 {
			migErr = m.Steps(-migrationConfig.Steps)
		} else {
			migErr = m.Down()
		}
	case "force":
		if migrationConfig.Steps < 0 {
			return errors.New("version cannot be negative for force command")
		}
		migErr = m.Force(migrationConfig.Steps)
	default:
		v, d, dbErr := m.Version()
		if dbErr != nil && dbErr != migrate.ErrNilVersion {
			return fmt.Errorf("failed to get migration version: %w", dbErr)
		}
		slog.Info("Current migration version", "version", v, "dirty", d)
		return nil
	}

	if migErr != nil && migErr != migrate.ErrNoChange {
		return fmt.Errorf("migration failed: %w", migErr)
	}
	if errors.Is(migErr, migrate.ErrNoChange) {
		slog.Info("No migrations to apply")
	} else {
		slog.Info("Migrations completed successfully")
	}
	return nil
}

func GetMigrationVersion(migrationsPath string) (uint, bool, error) {
	db, err := sql.Open("postgres", config.DatabaseURL())
	if err != nil {
		return 0, false, fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return 0, false, fmt.Errorf("could not create migration driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", migrationsPath),
		"postgres", driver)
	if err != nil {
		return 0, false, fmt.Errorf("migration initialization failed: %w", err)
	}

	version, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return 0, false, fmt.Errorf("failed to get migration version: %w", err)
	}

	if err == migrate.ErrNilVersion {
		return 0, false, nil
	}

	return version, dirty, nil
}
