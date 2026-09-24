package main

import (
	"certificate-radar/internal/analyzer"
	"certificate-radar/internal/api"
	"certificate-radar/internal/config"
	"certificate-radar/internal/repository"
	"certificate-radar/internal/risk"
	"certificate-radar/internal/scanner"
	"certificate-radar/internal/service"
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	httpAddr    = ":8080"
	httpTimeout = 10 * time.Second
)

func main() {
	slog.Info("App starting")

	config.Init()

	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
		os.Interrupt,
	)
	defer stop()

	pgx, err := initDatabase(ctx, config.DatabaseURL())
	if err != nil {
		log.Fatalf("failed to start app: %s", err)
	}
	defer pgx.Close()

	if err := repository.RunMigrations(ctx, &repository.MigrationConfig{
		MigrationsPath: "./migrations",
		Steps:          0,
		Direction:      "up",
	}, pgx); err != nil {
		log.Fatalf("failed to start app: %s", err)
	}

	router := buildRouter(pgx)

	server := &http.Server{
		Addr:              httpAddr,
		Handler:           router,
		ReadHeaderTimeout: httpTimeout,
		ReadTimeout:       httpTimeout,
		WriteTimeout:      httpTimeout,
		IdleTimeout:       httpTimeout,
	}

	serverErr := make(chan error, 1)

	go func() {
		slog.Info("HTTP server starting", "addr", httpAddr)

		if err := server.ListenAndServe(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	slog.Info("App started")

	select {
	case <-ctx.Done():
		slog.Info("Shutdown signal received")

	case err := <-serverErr:
		log.Fatalf("HTTP server failed: %s", err)
	}

	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error(
			"HTTP server shutdown failed",
			"error",
			err,
		)
	}

	slog.Info("App stopped")
}

func buildRouter(
	pgx *pgxpool.Pool,
) *gin.Engine {
	targetRepository := repository.NewPostgresTargetRepository(pgx)
	scanRepository := repository.NewPostgresScanRepository(pgx)

	targetService := service.NewTargetService(
		targetRepository,
	)

	tlsScanner := scanner.NewTLSScanner(
		5 * time.Second,
	)

	certificateAnalyzer := analyzer.New()
	riskEngine := risk.New()

	scanService := service.NewScanService(
		targetRepository,
		tlsScanner,
		certificateAnalyzer,
		riskEngine,
		scanRepository,
	)

	targetHandler := api.NewTargetHandler(
		targetService,
	)

	scanHandler := api.NewScanHandler(
		scanService,
		scanRepository,
	)

	return api.NewRouter(
		targetHandler,
		scanHandler,
	)
}

func initDatabase(
	ctx context.Context,
	conn string,
) (*pgxpool.Pool, error) {
	pgxConfig, err := pgxpool.ParseConfig(conn)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to init database config: %w",
			err,
		)
	}

	pgxConfig.MaxConns = 20
	pgxConfig.MinConns = 5
	pgxConfig.PingTimeout = 5 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, pgxConfig)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create database pool: %w",
			err,
		)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()

		return nil, fmt.Errorf(
			"failed to ping database: %w",
			err,
		)
	}

	return pool, nil
}
