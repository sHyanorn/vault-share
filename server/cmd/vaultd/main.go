// Command vaultd serves the vault-share API and, optionally, the built web client.
package main

import (
	"context"
	"fmt"
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
	"github.com/sHyanorn/vault-share/server/internal/store"
)

const cleanupInterval = time.Minute

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
	st, err := store.Open(ctx, filepath.Join(cfg.DataDir, "vault.db"))
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()
	blobs, err := blob.NewDisk(filepath.Join(cfg.DataDir, "blobs"))
	if err != nil {
		return fmt.Errorf("blob dir: %w", err)
	}
	auditor, err := audit.New(cfg.DataDir, st, logger)
	if err != nil {
		return fmt.Errorf("audit key: %w", err)
	}
	job := &cleanup.Job{Store: st, Blobs: blobs, Audit: auditor, Log: logger}
	go job.Loop(ctx, cleanupInterval)

	handler, err := api.NewRouter(api.Options{
		Logger:         logger,
		Store:          st,
		Blobs:          blobs,
		Audit:          auditor,
		TrustedProxies: cfg.TrustedProxies,
		MaxFileBytes:   cfg.MaxFileBytes,
		MaxTotalBytes:  cfg.MaxTotalBytes,
		WebDir:         cfg.WebDir,
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
