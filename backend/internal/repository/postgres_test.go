package repository

import (
	"context"
	"os"
	"testing"
	"time"

	"certificate-radar/internal/domain"
)

func TestPostgresTargetRepository(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")

	if databaseURL == "" {
		t.Skip(
			"DATABASE_URL is not set; skipping PostgreSQL integration test",
		)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	pool, err := NewPool(ctx, DatabaseConfig{
		URL: databaseURL,
	})
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	defer pool.Close()

	repo := NewPostgresTargetRepository(pool)

	target := domain.Target{
		ID:          "test-target-001",
		Address:     "example.com",
		Port:        443,
		ServerName:  "example.com",
		Enabled:     true,
		Owner:       "platform",
		Criticality: domain.CriticalityHigh,
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			"DELETE FROM targets WHERE id = $1",
			target.ID,
		)
	})

	t.Run("create", func(t *testing.T) {
		err := repo.Create(ctx, target)
		if err != nil {
			t.Fatalf("create target: %v", err)
		}
	})

	t.Run("get", func(t *testing.T) {
		got, err := repo.Get(ctx, target.ID)
		if err != nil {
			t.Fatalf("get target: %v", err)
		}

		if got.ID != target.ID {
			t.Errorf(
				"ID = %q, want %q",
				got.ID,
				target.ID,
			)
		}

		if got.Address != target.Address {
			t.Errorf(
				"Address = %q, want %q",
				got.Address,
				target.Address,
			)
		}

		if got.Port != target.Port {
			t.Errorf(
				"Port = %d, want %d",
				got.Port,
				target.Port,
			)
		}

		if got.ServerName != target.ServerName {
			t.Errorf(
				"ServerName = %q, want %q",
				got.ServerName,
				target.ServerName,
			)
		}

		if got.Owner != target.Owner {
			t.Errorf(
				"Owner = %q, want %q",
				got.Owner,
				target.Owner,
			)
		}

		if got.Criticality != target.Criticality {
			t.Errorf(
				"Criticality = %q, want %q",
				got.Criticality,
				target.Criticality,
			)
		}
	})

	t.Run("update", func(t *testing.T) {
		target.Owner = "security"
		target.Criticality = domain.CriticalityCritical
		target.Enabled = false

		if err := repo.Update(ctx, target); err != nil {
			t.Fatalf("update target: %v", err)
		}

		got, err := repo.Get(ctx, target.ID)
		if err != nil {
			t.Fatalf("get updated target: %v", err)
		}

		if got.Owner != "security" {
			t.Errorf(
				"Owner = %q, want %q",
				got.Owner,
				"security",
			)
		}

		if got.Criticality != domain.CriticalityCritical {
			t.Errorf(
				"Criticality = %q, want %q",
				got.Criticality,
				domain.CriticalityCritical,
			)
		}

		if got.Enabled {
			t.Error("Enabled = true, want false")
		}
	})

	t.Run("list", func(t *testing.T) {
		targets, err := repo.List(ctx)
		if err != nil {
			t.Fatalf("list targets: %v", err)
		}

		found := false

		for _, item := range targets {
			if item.ID == target.ID {
				found = true
				break
			}
		}

		if !found {
			t.Errorf(
				"target %q not found in list",
				target.ID,
			)
		}
	})
}

func TestPostgresTargetRepository_GetNotFound(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")

	if databaseURL == "" {
		t.Skip(
			"DATABASE_URL is not set; skipping PostgreSQL integration test",
		)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	pool, err := NewPool(ctx, DatabaseConfig{
		URL: databaseURL,
	})
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	defer pool.Close()

	repo := NewPostgresTargetRepository(pool)

	_, err = repo.Get(ctx, "does-not-exist")

	if err != ErrTargetNotFound {
		t.Fatalf(
			"error = %v, want %v",
			err,
			ErrTargetNotFound,
		)
	}
}

func TestPostgresScanRepository(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")

	if databaseURL == "" {
		t.Skip(
			"DATABASE_URL is not set; skipping PostgreSQL integration test",
		)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	pool, err := NewPool(ctx, DatabaseConfig{
		URL: databaseURL,
	})
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	defer pool.Close()

	targetRepo := NewPostgresTargetRepository(pool)
	scanRepo := NewPostgresScanRepository(pool)

	target := domain.Target{
		ID:          "scan-test-target",
		Address:     "example.com",
		Port:        443,
		ServerName:  "example.com",
		Enabled:     true,
		Owner:       "platform",
		Criticality: domain.CriticalityHigh,
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			"DELETE FROM targets WHERE id = $1",
			target.ID,
		)
	})

	if err := targetRepo.Create(ctx, target); err != nil {
		t.Fatalf("create target: %v", err)
	}

	scan := domain.ScanResult{
		TargetID:  target.ID,
		ScannedAt: time.Now(),

		Certificate: &domain.Certificate{
			FingerprintSHA256: "abcdef123456",
			SerialNumber:      "123456",

			Subject:    "CN=example.com",
			CommonName: "example.com",
			DNSNames: []string{
				"example.com",
				"www.example.com",
			},
			IPAddresses: []string{
				"192.0.2.10",
			},
			Issuer: "CN=Example CA",

			ValidFrom: time.Now().Add(-24 * time.Hour),
			ValidTo:   time.Now().Add(30 * 24 * time.Hour),

			SignatureAlgorithm: "SHA256-RSA",
			PublicKeyAlgorithm: "RSA",
			PublicKeySize:      2048,
		},

		DaysLeft: 30,

		Chain: domain.ChainResult{
			Status: domain.ChainValid,
		},

		Hostname: domain.HostnameResult{
			Status: domain.HostnameMatch,
		},

		Status:     domain.StatusWarning,
		SelfSigned: false,

		Findings: []domain.Finding{
			{
				Type:     domain.FindingWeakSignature,
				Severity: domain.SeverityWarning,
				Message:  "test finding",
			},
		},

		TLSVersion:  0x0304,
		CipherSuite: 0x1301,

		Owner:       target.Owner,
		Criticality: target.Criticality,
	}

	risk := domain.RiskResult{
		Score: 45,
		Level: domain.RiskHigh,
	}

	if err := scanRepo.Save(ctx, scan, risk); err != nil {
		t.Fatalf("save scan: %v", err)
	}

	t.Run("get latest", func(t *testing.T) {
		record, err := scanRepo.GetLatestByTarget(
			ctx,
			target.ID,
		)
		if err != nil {
			t.Fatalf("get latest scan: %v", err)
		}

		if record.Scan.TargetID != target.ID {
			t.Errorf(
				"TargetID = %q, want %q",
				record.Scan.TargetID,
				target.ID,
			)
		}

		if record.Scan.Owner != "platform" {
			t.Errorf(
				"Owner = %q, want %q",
				record.Scan.Owner,
				"platform",
			)
		}

		if record.Scan.Criticality != domain.CriticalityHigh {
			t.Errorf(
				"Criticality = %q, want %q",
				record.Scan.Criticality,
				domain.CriticalityHigh,
			)
		}

		if record.Scan.Certificate == nil {
			t.Fatal("Certificate = nil")
		}

		if record.Scan.Certificate.CommonName != "example.com" {
			t.Errorf(
				"CommonName = %q, want %q",
				record.Scan.Certificate.CommonName,
				"example.com",
			)
		}

		if len(record.Scan.Certificate.DNSNames) != 2 {
			t.Fatalf(
				"DNSNames length = %d, want 2",
				len(record.Scan.Certificate.DNSNames),
			)
		}

		if len(record.Scan.Findings) != 1 {
			t.Fatalf(
				"Findings length = %d, want 1",
				len(record.Scan.Findings),
			)
		}

		if record.Risk.Score != 45 {
			t.Errorf(
				"Risk.Score = %d, want 45",
				record.Risk.Score,
			)
		}

		if record.Risk.Level != domain.RiskHigh {
			t.Errorf(
				"Risk.Level = %q, want %q",
				record.Risk.Level,
				domain.RiskHigh,
			)
		}
	})

	t.Run("list recent", func(t *testing.T) {
		records, err := scanRepo.ListRecent(ctx, ScanListQuery{})
		if err != nil {
			t.Fatalf("list recent scans: %v", err)
		}

		found := false

		for _, record := range records {
			if record.Scan.TargetID == target.ID {
				found = true
				break
			}
		}

		if !found {
			t.Fatalf(
				"target %q not found in recent scans",
				target.ID,
			)
		}
	})
}

func TestPostgresScanRepository_GetLatestNotFound(
	t *testing.T,
) {
	databaseURL := os.Getenv("DATABASE_URL")

	if databaseURL == "" {
		t.Skip(
			"DATABASE_URL is not set; skipping PostgreSQL integration test",
		)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	pool, err := NewPool(ctx, DatabaseConfig{
		URL: databaseURL,
	})
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	defer pool.Close()

	repo := NewPostgresScanRepository(pool)

	_, err = repo.GetLatestByTarget(
		ctx,
		"target-without-scans",
	)

	if err != ErrScanNotFound {
		t.Fatalf(
			"error = %v, want %v",
			err,
			ErrScanNotFound,
		)
	}
}
