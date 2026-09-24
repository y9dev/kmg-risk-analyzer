package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"certificate-radar/internal/domain"
)

type scanRow struct {
	ID        int64
	TargetID  string
	ScannedAt time.Time

	Owner       string
	Criticality string

	DaysLeft int
	Status   string

	HostnameStatus string
	HostnameError  string

	ChainStatus string
	ChainError  string

	SelfSigned bool

	TLSVersion  uint16
	CipherSuite uint16

	RiskScore int
	RiskLevel string
}

func (r *PostgresScanRepository) GetLatestByTarget(
	ctx context.Context,
	targetID string,
) (*domain.ScanRecord, error) {
	query, args, err := scanSelect().
		Where(sq.Eq{
			"s.target_id": targetID,
		}).
		OrderBy("s.scanned_at DESC", "s.id DESC").
		Limit(1).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf(
			"build latest scan query: %w",
			err,
		)
	}

	var row scanRow

	err = r.db.QueryRow(
		ctx,
		query,
		args...,
	).Scan(scanRowDest(&row)...)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrScanNotFound
		}

		return nil, fmt.Errorf(
			"get latest scan: %w",
			err,
		)
	}

	return r.loadScanRecord(ctx, row)
}

func (r *PostgresScanRepository) ListRecent(
	ctx context.Context,
	query ScanListQuery,
) ([]domain.ScanRecord, error) {
	if query.Limit <= 0 {
		return []domain.ScanRecord{}, nil
	}

	if query.Offset < 0 {
		query.Offset = 0
	}

	builder := scanSelect()

	if query.Status != nil {
		builder = builder.Where(
			"s.status = ?",
			string(*query.Status),
		)
	}

	if query.RiskLevel != nil {
		builder = builder.Where(
			"s.risk_level = ?",
			string(*query.RiskLevel),
		)
	}

	if query.Owner != nil {
		builder = builder.Where(
			"t.owner = ?",
			*query.Owner,
		)
	}

	if query.Criticality != nil {
		builder = builder.Where(
			"t.criticality = ?",
			string(*query.Criticality),
		)
	}

	if query.DaysLeftMin != nil {
		builder = builder.Where(
			"s.days_left >= ?",
			*query.DaysLeftMin,
		)
	}

	if query.DaysLeftMax != nil {
		builder = builder.Where(
			"s.days_left <= ?",
			*query.DaysLeftMax,
		)
	}

	if query.Issuer != nil {
		builder = builder.Where(
			`EXISTS (
			SELECT 1
			FROM certificates c
			WHERE c.scan_id = s.id
			  AND c.issuer = ?
		)`,
			*query.Issuer,
		)
	}

	orderBy := scanOrderBy(query)
	orderDirection := scanOrderDirection(query)

	builder = builder.OrderBy(
		orderBy+" "+orderDirection,
		"s.id DESC",
	)

	sqlQuery, args, err := builder.
		Limit(uint64(query.Limit)).
		Offset(uint64(query.Offset)).
		PlaceholderFormat(sq.Dollar).
		ToSql()

	if err != nil {
		return nil, fmt.Errorf(
			"build list recent scans query: %w",
			err,
		)
	}

	rows, err := r.db.Query(ctx, sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf(
			"list recent scans: %w",
			err,
		)
	}
	defer rows.Close()

	results := make([]domain.ScanRecord, 0, query.Limit)

	for rows.Next() {
		var row scanRow

		if err := rows.Scan(scanRowDest(&row)...); err != nil {
			return nil, fmt.Errorf(
				"scan recent scan row: %w",
				err,
			)
		}

		record, err := r.loadScanRecord(ctx, row)
		if err != nil {
			return nil, err
		}

		results = append(results, *record)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate recent scans: %w",
			err,
		)
	}

	return results, nil
}

func (r *PostgresScanRepository) loadScanRecord(
	ctx context.Context,
	row scanRow,
) (*domain.ScanRecord, error) {
	certificate, err := r.getCertificate(
		ctx,
		row.ID,
	)
	if err != nil {
		return nil, err
	}

	findings, err := r.getFindings(
		ctx,
		row.ID,
	)
	if err != nil {
		return nil, err
	}

	return &domain.ScanRecord{
		Scan: domain.ScanResult{
			TargetID:  row.TargetID,
			ScannedAt: row.ScannedAt,

			Owner:       row.Owner,
			Criticality: domain.ServiceCriticality(row.Criticality),

			Certificate: certificate,

			DaysLeft: row.DaysLeft,

			Hostname: domain.HostnameResult{
				Status: domain.HostnameStatus(row.HostnameStatus),
				Error:  row.HostnameError,
			},

			Chain: domain.ChainResult{
				Status: domain.ChainStatus(row.ChainStatus),
				Error:  row.ChainError,
			},

			Status:     domain.CertificateStatus(row.Status),
			SelfSigned: row.SelfSigned,

			Findings: findings,

			TLSVersion:  row.TLSVersion,
			CipherSuite: row.CipherSuite,
		},

		Risk: domain.RiskResult{
			Score: row.RiskScore,
			Level: domain.RiskLevel(row.RiskLevel),
		},
	}, nil
}

func (r *PostgresScanRepository) getCertificate(
	ctx context.Context,
	scanID int64,
) (*domain.Certificate, error) {
	query, args, err := sq.
		Select(
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
		From("certificates").
		Where(sq.Eq{
			"scan_id": scanID,
		}).
		Limit(1).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf(
			"build certificate query: %w",
			err,
		)
	}

	var cert domain.Certificate
	var dnsNames []byte
	var ipAddresses []byte

	err = r.db.QueryRow(
		ctx,
		query,
		args...,
	).Scan(
		&cert.FingerprintSHA256,
		&cert.SerialNumber,
		&cert.Subject,
		&cert.CommonName,
		&cert.Issuer,
		&cert.ValidFrom,
		&cert.ValidTo,
		&cert.SignatureAlgorithm,
		&cert.PublicKeyAlgorithm,
		&cert.PublicKeySize,
		&dnsNames,
		&ipAddresses,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf(
			"get certificate: %w",
			err,
		)
	}

	if err := json.Unmarshal(dnsNames, &cert.DNSNames); err != nil {
		return nil, fmt.Errorf(
			"unmarshal DNS names: %w",
			err,
		)
	}

	if err := json.Unmarshal(
		ipAddresses,
		&cert.IPAddresses,
	); err != nil {
		return nil, fmt.Errorf(
			"unmarshal IP addresses: %w",
			err,
		)
	}

	return &cert, nil
}

func scanOrderBy(query ScanListQuery) string {
	switch query.SortBy {
	case "days_left":
		return "s.days_left"
	case "status":
		return "s.status"
	case "risk_score":
		return "s.risk_score"
	case "owner":
		return "t.owner"
	case "criticality":
		return "t.criticality"
	case "scanned_at":
		return "s.scanned_at"
	default:
		return "s.scanned_at"
	}
}

func scanOrderDirection(query ScanListQuery) string {
	if query.SortDesc {
		return "DESC"
	}

	return "ASC"
}

func (r *PostgresScanRepository) getFindings(
	ctx context.Context,
	scanID int64,
) ([]domain.Finding, error) {
	query, args, err := sq.
		Select(
			"type",
			"severity",
			"message",
		).
		From("findings").
		Where(sq.Eq{
			"scan_id": scanID,
		}).
		OrderBy("id").
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf(
			"build findings query: %w",
			err,
		)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf(
			"get findings: %w",
			err,
		)
	}
	defer rows.Close()

	findings := make([]domain.Finding, 0)

	for rows.Next() {
		var finding domain.Finding

		if err := rows.Scan(
			&finding.Type,
			&finding.Severity,
			&finding.Message,
		); err != nil {
			return nil, fmt.Errorf(
				"scan finding: %w",
				err,
			)
		}

		findings = append(findings, finding)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate findings: %w",
			err,
		)
	}

	return findings, nil
}

func scanSelect() sq.SelectBuilder {
	return sq.
		Select(
			"s.id",
			"s.target_id",
			"s.scanned_at",

			"t.owner",
			"t.criticality",

			"s.days_left",
			"s.status",

			"s.hostname_status",
			"s.hostname_error",

			"s.chain_status",
			"s.chain_error",

			"s.self_signed",

			"s.tls_version",
			"s.cipher_suite",

			"s.risk_score",
			"s.risk_level",
		).
		From("scans s").
		Join("targets t ON t.id = s.target_id")
}

func scanRowDest(row *scanRow) []any {
	return []any{
		&row.ID,
		&row.TargetID,
		&row.ScannedAt,

		&row.Owner,
		&row.Criticality,

		&row.DaysLeft,
		&row.Status,

		&row.HostnameStatus,
		&row.HostnameError,

		&row.ChainStatus,
		&row.ChainError,

		&row.SelfSigned,

		&row.TLSVersion,
		&row.CipherSuite,

		&row.RiskScore,
		&row.RiskLevel,
	}
}
