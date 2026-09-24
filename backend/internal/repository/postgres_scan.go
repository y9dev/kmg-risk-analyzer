package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"certificate-radar/internal/domain"
)

var ErrScanNotFound = errors.New("scan not found")

type PostgresScanRepository struct {
	db *pgxpool.Pool
}

func NewPostgresScanRepository(
	db *pgxpool.Pool,
) *PostgresScanRepository {
	return &PostgresScanRepository{
		db: db,
	}
}

func (r *PostgresScanRepository) Save(
	ctx context.Context,
	scan domain.ScanResult,
	risk domain.RiskResult,
) error {
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin scan transaction: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	scanID, err := insertScan(ctx, tx, scan, risk)
	if err != nil {
		return err
	}

	if scan.Certificate != nil {
		if err := insertCertificate(
			ctx,
			tx,
			scanID,
			scan.Certificate,
		); err != nil {
			return err
		}
	}

	if err := insertFindings(
		ctx,
		tx,
		scanID,
		scan.Findings,
	); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit scan transaction: %w", err)
	}

	return nil
}

type tx interface {
	Exec(
		ctx context.Context,
		sql string,
		arguments ...any,
	) (pgconn.CommandTag, error)

	QueryRow(
		ctx context.Context,
		sql string,
		args ...any,
	) pgx.Row
}

func insertScan(
	ctx context.Context,
	tx tx,
	scan domain.ScanResult,
	risk domain.RiskResult,
) (int64, error) {
	query, args, err := sq.
		Insert("scans").
		Columns(
			"target_id",
			"scanned_at",
			"days_left",
			"status",
			"hostname_status",
			"hostname_error",
			"chain_status",
			"chain_error",
			"self_signed",
			"tls_version",
			"cipher_suite",
			"risk_score",
			"risk_level",
		).
		Values(
			scan.TargetID,
			scan.ScannedAt,
			scan.DaysLeft,
			scan.Status,
			scan.Hostname.Status,
			scan.Hostname.Error,
			scan.Chain.Status,
			scan.Chain.Error,
			scan.SelfSigned,
			scan.TLSVersion,
			scan.CipherSuite,
			risk.Score,
			risk.Level,
		).
		Suffix("RETURNING id").
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return 0, fmt.Errorf(
			"build insert scan query: %w",
			err,
		)
	}

	var scanID int64

	if err := tx.QueryRow(
		ctx,
		query,
		args...,
	).Scan(&scanID); err != nil {
		return 0, fmt.Errorf(
			"insert scan: %w",
			err,
		)
	}

	return scanID, nil
}

func insertCertificate(
	ctx context.Context,
	tx tx,
	scanID int64,
	cert *domain.Certificate,
) error {
	dnsNames, err := json.Marshal(cert.DNSNames)
	if err != nil {
		return fmt.Errorf(
			"marshal certificate DNS names: %w",
			err,
		)
	}

	ipAddresses, err := json.Marshal(cert.IPAddresses)
	if err != nil {
		return fmt.Errorf(
			"marshal certificate IP addresses: %w",
			err,
		)
	}

	query, args, err := sq.
		Insert("certificates").
		Columns(
			"scan_id",
			"fingerprint_sha256",
			"serial_number",
			"subject",
			"common_name",
			"issuer",
			"valid_from",
			"valid_to",
			"signature_algorithm",
			"public_key_algorithm",
			"public_key_size",
			"dns_names",
			"ip_addresses",
		).
		Values(
			scanID,
			cert.FingerprintSHA256,
			cert.SerialNumber,
			cert.Subject,
			cert.CommonName,
			cert.Issuer,
			cert.ValidFrom,
			cert.ValidTo,
			cert.SignatureAlgorithm,
			cert.PublicKeyAlgorithm,
			cert.PublicKeySize,
			dnsNames,
			ipAddresses,
		).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return fmt.Errorf(
			"build insert certificate query: %w",
			err,
		)
	}

	if _, err := tx.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf(
			"insert certificate: %w",
			err,
		)
	}

	return nil
}

func insertFindings(
	ctx context.Context,
	tx tx,
	scanID int64,
	findings []domain.Finding,
) error {
	if len(findings) == 0 {
		return nil
	}

	builder := sq.
		Insert("findings").
		Columns(
			"scan_id",
			"type",
			"severity",
			"message",
		)

	for _, finding := range findings {
		builder = builder.Values(
			scanID,
			finding.Type,
			finding.Severity,
			finding.Message,
		)
	}

	query, args, err := builder.
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return fmt.Errorf(
			"build insert findings query: %w",
			err,
		)
	}

	if _, err := tx.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf(
			"insert findings: %w",
			err,
		)
	}

	return nil
}
