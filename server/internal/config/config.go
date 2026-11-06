// Package config loads vaultd settings from VAULT_* environment variables.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const prefix = "VAULT_"

// Config holds every runtime setting of vaultd.
type Config struct {
	// ListenAddr is the host:port the HTTP server binds to (VAULT_LISTEN_ADDR).
	ListenAddr string
	// BaseURL is the public origin used to build share links, without a
	// trailing slash (VAULT_BASE_URL).
	BaseURL string
	// DataDir holds the database and ciphertext blobs (VAULT_DATA_DIR).
	DataDir string
	// MaxFileBytes caps the ciphertext size of a single upload (VAULT_MAX_FILE_BYTES).
	MaxFileBytes int64
	// WebDir, when set, is the built frontend served for non-API paths (VAULT_WEB_DIR).
	WebDir string
	// TrustedProxies are the sources whose X-Forwarded-For is believed
	// (VAULT_TRUSTED_PROXIES, comma-separated addresses or CIDRs). Empty
	// means the connecting address is the client.
	TrustedProxies []netip.Prefix
	// LogLevel is the minimum level written to the log (VAULT_LOG_LEVEL).
	LogLevel slog.Level
}

// Load reads settings through lookup, normally os.LookupEnv. Unset or empty
// variables take their defaults. Every invalid variable is reported.
func Load(lookup func(string) (string, bool)) (Config, error) {
	get := func(name, fallback string) string {
		if v, ok := lookup(prefix + name); ok && v != "" {
			return v
		}
		return fallback
	}

	cfg := Config{
		ListenAddr: get("LISTEN_ADDR", ":8080"),
		BaseURL:    get("BASE_URL", "https://localhost"),
		DataDir:    get("DATA_DIR", "data"),
		WebDir:     get("WEB_DIR", ""),
	}
	var errs []error
	fail := func(name string, err error) {
		errs = append(errs, fmt.Errorf("%s%s: %w", prefix, name, err))
	}

	if _, _, err := net.SplitHostPort(cfg.ListenAddr); err != nil {
		fail("LISTEN_ADDR", err)
	}

	if u, err := url.Parse(cfg.BaseURL); err != nil {
		fail("BASE_URL", err)
	} else if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || strings.ContainsAny(cfg.BaseURL, "?#") {
		fail("BASE_URL", errors.New("must be an http(s) origin with an optional path"))
	} else {
		cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	}

	if n, err := strconv.ParseInt(get("MAX_FILE_BYTES", "1073741824"), 10, 64); err != nil {
		fail("MAX_FILE_BYTES", err)
	} else if n <= 0 {
		fail("MAX_FILE_BYTES", errors.New("must be positive"))
	} else {
		cfg.MaxFileBytes = n
	}

	if err := cfg.LogLevel.UnmarshalText([]byte(get("LOG_LEVEL", "info"))); err != nil {
		fail("LOG_LEVEL", err)
	}

	for _, item := range strings.Split(get("TRUSTED_PROXIES", ""), ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		prefix, err := parseProxy(item)
		if err != nil {
			fail("TRUSTED_PROXIES", err)
			continue
		}
		cfg.TrustedProxies = append(cfg.TrustedProxies, prefix)
	}

	return cfg, errors.Join(errs...)
}

// parseProxy accepts an address or a CIDR in the form clients are matched
// in: IPv4-mapped entries become plain IPv4 and zones are dropped, because
// connecting addresses are unmapped and stripped of zones before matching.
func parseProxy(item string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(item)
	if err != nil {
		addr, addrErr := netip.ParseAddr(item)
		if addrErr != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not an address or CIDR", item)
		}
		addr = addr.WithZone("")
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("%q spans beyond the IPv4-mapped range", item)
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked(), nil
}
