// Command vaultd serves the vault-share API and, optionally, the built web client.
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sHyanorn/vault-share/server/internal/api"
	"github.com/sHyanorn/vault-share/server/internal/audit"
	"github.com/sHyanorn/vault-share/server/internal/blob"
	"github.com/sHyanorn/vault-share/server/internal/cleanup"
	"github.com/sHyanorn/vault-share/server/internal/config"
	"github.com/sHyanorn/vault-share/server/internal/health"
	"github.com/sHyanorn/vault-share/server/internal/keyfile"
	"github.com/sHyanorn/vault-share/server/internal/store"
)

const (
	cleanupInterval = time.Minute
	accountKeyFile  = "account.key"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "vaultd:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("data dir: %w", err)
	}
	blobs, err := openBlobs(ctx, cfg)
	if err != nil {
		return fmt.Errorf("blob store: %w", err)
	}
	dbPath := filepath.Join(cfg.DataDir, "vault.db")
	st, err := openDatabase(ctx, dbPath, blobs)
	if err != nil {
		return err
	}
	defer st.Close()
	storage := []any{"kind", cfg.Storage}
	if cfg.Storage == "s3" {
		// Where the files go, never the credentials.
		storage = append(storage, "bucket", cfg.S3.Bucket, "endpoint", cfg.S3.Endpoint, "region", cfg.S3.Region)
	}
	logger.Info("storage", storage...)
	auditor, err := audit.New(cfg.DataDir, st, logger, time.Now)
	if err != nil {
		return fmt.Errorf("audit key: %w", err)
	}
	accountKey, err := loadAccountKey(ctx, cfg.DataDir, st)
	if err != nil {
		return err
	}
	job := cleanup.New(st, blobs, auditor, logger, time.Now)
	go job.Loop(ctx, cleanupInterval)

	checker := health.New(st, blobs, cfg.DataDir, health.MinFreeBytes, logger, time.Now)
	handler, err := api.NewRouter(api.Options{
		Logger:         logger,
		Store:          st,
		Blobs:          blobs,
		Audit:          auditor,
		TrustedProxies: cfg.TrustedProxies,
		Host:           cfg.Host,
		MaxFileBytes:   cfg.MaxFileBytes,
		MaxTotalBytes:  cfg.MaxTotalBytes,
		Now:            time.Now,
		WebDir:         cfg.WebDir,
		AccountKey:     accountKey,
		SignupClosed:   cfg.SignupClosed,
		MaxAccounts:    cfg.MaxAccounts,
		Health:         checker.Check,
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: handler,
		// Streaming handlers extend these per request through
		// http.ResponseController; every other request must finish quickly.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	errc := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.ListenAddr)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	stop() // a second signal now terminates the process
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("shutdown incomplete, closing active connections", "err", err)
	}
	return nil
}

// openDatabase opens the database at dbPath, creating it on a first start.
// The guard comes before the open, so a refusal leaves no new database
// behind that would let the next start pass.
func openDatabase(ctx context.Context, dbPath string, blobs blob.Store) (*store.Store, error) {
	if err := refuseNewDatabaseOverContent(ctx, dbPath, blobs); err != nil {
		return nil, err
	}
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	return st, nil
}

// refuseNewDatabaseOverContent fails when the database at dbPath does not
// exist yet while the storage already holds content. A new database has no
// record of that content, so cleanup would delete all of it as orphaned:
// the database was lost, or the storage belongs to another instance.
func refuseNewDatabaseOverContent(ctx context.Context, dbPath string, blobs blob.Store) error {
	info, err := os.Stat(dbPath)
	switch {
	case err == nil && info.Size() > 0:
		return nil
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("database: %w", err)
	}
	for id, err := range blobs.IDs(ctx) {
		if err != nil {
			return fmt.Errorf("list stored content: %w", err)
		}
		return fmt.Errorf("%s is missing or empty, but the storage already holds content (for example %s). "+
			"A new database has no record of it, and cleanup would delete it. "+
			"Restore the database from a backup, or empty the storage (the blobs directory or the bucket) to start over; "+
			"see docs/OPERATIONS.md", dbPath, id)
	}
	return nil
}

// loadAccountKey returns the key in account.key and creates it only while
// no account exists. Every account's sessions and two-factor secret depend
// on it, so a missing key beside existing accounts means it was lost or left
// out of a restore, and a new one would silently break them.
func loadAccountKey(ctx context.Context, dir string, st *store.Store) ([]byte, error) {
	key, err := keyfile.Read(dir, accountKeyFile)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("account key: %w", err)
	}
	accounts, err := st.HasUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	if accounts {
		return nil, fmt.Errorf("%s does not exist, but the database already holds accounts. "+
			"A new key would sign every browser out and leave two-factor accounts with their recovery codes only. "+
			"Restore %s from the same backup as the database, or create a new one on purpose; "+
			"see docs/OPERATIONS.md", filepath.Join(dir, accountKeyFile), accountKeyFile)
	}
	key, err = keyfile.Load(dir, accountKeyFile)
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	return key, nil
}

func openBlobs(ctx context.Context, cfg config.Config) (blob.Store, error) {
	if cfg.Storage != "s3" {
		return blob.NewDisk(filepath.Join(cfg.DataDir, "blobs"))
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return blob.NewS3(ctx, blob.S3Config{
		Endpoint:        cfg.S3.Endpoint,
		Region:          cfg.S3.Region,
		Bucket:          cfg.S3.Bucket,
		AccessKeyID:     cfg.S3.AccessKeyID,
		SecretAccessKey: cfg.S3.SecretAccessKey,
		PathStyle:       cfg.S3.PathStyle,
	})
}
