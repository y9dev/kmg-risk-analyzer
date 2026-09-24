package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"certificate-radar/internal/analyzer"
	"certificate-radar/internal/config"
	"certificate-radar/internal/domain"
	"certificate-radar/internal/repository"
	"certificate-radar/internal/risk"
	"certificate-radar/internal/scanner"
	"certificate-radar/internal/service"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	commandTimeout = 15 * time.Second
	scanTimeout    = 5 * time.Second
)

func main() {
	config.Init()

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "target":
		runTargetCommand(os.Args[2:])
	case "scan":
		runScanCommand(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func runTargetCommand(args []string) {
	if len(args) == 0 {
		targetUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "add":
		runTargetAdd(args[1:])
	case "list":
		runTargetList(args[1:])
	default:
		targetUsage()
		os.Exit(1)
	}
}

func runTargetAdd(args []string) {
	fs := flag.NewFlagSet("target add", flag.ExitOnError)

	owner := fs.String("owner", "", "service owner")
	criticality := fs.String(
		"criticality",
		string(domain.CriticalityLow),
		"service criticality: LOW, MEDIUM, HIGH, CRITICAL",
	)

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: radar-cli target add <target> [flags]")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		commandTimeout,
	)
	defer cancel()

	pool := openDB(ctx)
	defer pool.Close()

	repo := repository.NewPostgresTargetRepository(pool)
	targetService := service.NewTargetService(repo)

	t, err := targetService.Create(
		ctx,
		fs.Arg(0),
		*owner,
		domain.ServiceCriticality(
			strings.ToUpper(strings.TrimSpace(*criticality)),
		),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Target created\n")
	fmt.Printf("ID:           %s\n", t.ID)
	fmt.Printf("Address:      %s\n", t.Address)
	fmt.Printf("Port:         %d\n", t.Port)
	fmt.Printf("Server Name:  %s\n", t.ServerName)
	fmt.Printf("Owner:        %s\n", t.Owner)
	fmt.Printf("Criticality:  %s\n", t.Criticality)
	fmt.Printf("Enabled:      %t\n", t.Enabled)
}

func runTargetList(args []string) {
	fs := flag.NewFlagSet("target list", flag.ExitOnError)

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: radar-cli target list")
	}

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		commandTimeout,
	)
	defer cancel()

	pool := openDB(ctx)
	defer pool.Close()

	repo := repository.NewPostgresTargetRepository(pool)
	targetService := service.NewTargetService(repo)

	targets, err := targetService.List(ctx)
	if err != nil {
		log.Fatal(err)
	}

	if len(targets) == 0 {
		fmt.Println("No targets found")
		return
	}

	fmt.Printf(
		"%-34s %-25s %-6s %-25s %-12s %-10s\n",
		"ID",
		"ADDRESS",
		"PORT",
		"OWNER",
		"CRITICALITY",
		"ENABLED",
	)

	for _, t := range targets {
		fmt.Printf(
			"%-34s %-25s %-6d %-25s %-12s %-10t\n",
			t.ID,
			t.Address,
			t.Port,
			t.Owner,
			t.Criticality,
			t.Enabled,
		)
	}
}

func runScanCommand(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: radar-cli scan <target-id>")
	}

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		commandTimeout,
	)
	defer cancel()

	pool := openDB(ctx)
	defer pool.Close()

	targetRepo := repository.NewPostgresTargetRepository(pool)
	scanRepo := repository.NewPostgresScanRepository(pool)

	tlsScanner := scanner.NewTLSScanner(scanTimeout)
	certificateAnalyzer := analyzer.New()
	riskEngine := risk.New()

	scanService := service.NewScanService(
		targetRepo,
		tlsScanner,
		certificateAnalyzer,
		riskEngine,
		scanRepo,
	)

	record, err := scanService.ScanTarget(ctx, fs.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	printScanRecord(record)
}

func openDB(ctx context.Context) *pgxpool.Pool {
	databaseURL := config.DatabaseURL()
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}

	pool, err := repository.NewPool(ctx, repository.DatabaseConfig{
		URL: databaseURL,
	})
	if err != nil {
		log.Fatal(err)
	}

	return pool
}

func printScanRecord(record *domain.ScanRecord) {
	scan := record.Scan

	fmt.Println("Scan completed")
	fmt.Println()

	fmt.Printf("Target ID:     %s\n", scan.TargetID)
	fmt.Printf("Scanned At:    %s\n", scan.ScannedAt.Format(time.RFC3339))
	fmt.Printf("Status:        %s\n", scan.Status)
	fmt.Printf("Days Left:     %d\n", scan.DaysLeft)
	fmt.Printf("Owner:         %s\n", scan.Owner)
	fmt.Printf("Criticality:   %s\n", scan.Criticality)
	fmt.Printf("Risk:          %d (%s)\n", record.Risk.Score, record.Risk.Level)

	fmt.Println()
	fmt.Println("TLS")
	fmt.Printf("Version:       %s\n", tlsVersionName(scan.TLSVersion))
	fmt.Printf("Cipher:        %s\n", tls.CipherSuiteName(scan.CipherSuite))

	fmt.Println()
	fmt.Println("Certificate")

	if scan.Certificate == nil {
		fmt.Println("Certificate:   none")
	} else {
		fmt.Printf(
			"Fingerprint:   %s\n",
			scan.Certificate.FingerprintSHA256,
		)
		fmt.Printf(
			"Serial:        %s\n",
			scan.Certificate.SerialNumber,
		)
		fmt.Printf(
			"Subject:       %s\n",
			scan.Certificate.Subject,
		)
		fmt.Printf(
			"Common Name:   %s\n",
			scan.Certificate.CommonName,
		)
		fmt.Printf(
			"Issuer:        %s\n",
			scan.Certificate.Issuer,
		)
		fmt.Printf(
			"Valid From:    %s\n",
			scan.Certificate.ValidFrom.Format(time.RFC3339),
		)
		fmt.Printf(
			"Valid To:      %s\n",
			scan.Certificate.ValidTo.Format(time.RFC3339),
		)
		fmt.Printf(
			"Signature:     %s\n",
			scan.Certificate.SignatureAlgorithm,
		)
		fmt.Printf(
			"Public Key:    %s %d bit\n",
			scan.Certificate.PublicKeyAlgorithm,
			scan.Certificate.PublicKeySize,
		)
	}

	fmt.Println()
	fmt.Println("Validation")
	fmt.Printf("Hostname:       %s\n", scan.Hostname.Status)
	if scan.Hostname.Error != "" {
		fmt.Printf("Hostname Error: %s\n", scan.Hostname.Error)
	}

	fmt.Printf("Chain:          %s\n", scan.Chain.Status)
	if scan.Chain.Error != "" {
		fmt.Printf("Chain Error:    %s\n", scan.Chain.Error)
	}

	fmt.Printf("Self-Signed:    %t\n", scan.SelfSigned)

	fmt.Println()
	fmt.Println("Findings")

	if len(scan.Findings) == 0 {
		fmt.Println("None")
		return
	}

	for _, finding := range scan.Findings {
		fmt.Printf(
			"- [%s] %s: %s\n",
			finding.Severity,
			finding.Type,
			finding.Message,
		)
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  radar-cli target add <target> [--owner <owner>] [--criticality <level>]
  radar-cli target list
  radar-cli scan <target-id>`)
}

func targetUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  radar-cli target add <target> [--owner <owner>] [--criticality <level>]
  radar-cli target list`)
}
