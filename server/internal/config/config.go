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

	"github.com/sHyanorn/vault-share/server/internal/blob"
)

const prefix = "VAULT_"

// Config holds every runtime setting of vaultd.
type Config struct {
	// ListenAddr is the host:port the HTTP server binds to (VAULT_LISTEN_ADDR).
	ListenAddr string
	// BaseURL is the public origin used to build share links, without a
	// trailing slash (VAULT_BASE_URL).
	BaseURL string
	// Host is the host name of BaseURL, the only name the API answers for.
	Host string
	// DataDir holds the database and ciphertext blobs (VAULT_DATA_DIR).
	DataDir string
	// MaxFileBytes caps the ciphertext size of a single upload (VAULT_MAX_FILE_BYTES).
	MaxFileBytes int64
	// MaxTotalBytes caps the storage all files together may take, metadata
	// and per-file overhead included (VAULT_MAX_TOTAL_BYTES).
	MaxTotalBytes int64
	// WebDir, when set, is the built frontend served for non-API paths (VAULT_WEB_DIR).
	WebDir string
	// TrustedProxies are the sources whose X-Forwarded-For is believed
	// (VAULT_TRUSTED_PROXIES, comma-separated addresses or CIDRs). Empty
	// means the connecting address is the client.
	TrustedProxies []netip.Prefix
	// LogLevel is the minimum level written to the log (VAULT_LOG_LEVEL).
	LogLevel slog.Level
	// Storage is where ciphertext lives: "disk", under DataDir, or "s3"
	// (VAULT_STORAGE).
	Storage string
	// S3 names the bucket when Storage is "s3" (VAULT_S3_*).
	S3 S3
}

// S3 is an S3-compatible bucket that belongs to vaultd alone.
type S3 struct {
	// Endpoint is the service URL; empty means AWS (VAULT_S3_ENDPOINT).
	Endpoint string
	// Region defaults to us-east-1 (VAULT_S3_REGION).
	Region string
	// Bucket must exist (VAULT_S3_BUCKET).
	Bucket string
	// AccessKeyID and SecretAccessKey are static credentials
	// (VAULT_S3_ACCESS_KEY_ID, VAULT_S3_SECRET_ACCESS_KEY).
	AccessKeyID     string
	SecretAccessKey string
	// PathStyle puts the bucket in the path instead of the host name; on by
	// default with a custom endpoint (VAULT_S3_PATH_STYLE).
	PathStyle bool
}

// The size limits keep every sum the quota builds on them far from
// overflowing an int64 (F36).
const (
	maxFileBytes  = 1 << 40
	maxTotalBytes = 1 << 50
)

var s3Variables = []string{"S3_ENDPOINT", "S3_REGION", "S3_BUCKET", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY", "S3_PATH_STYLE"}

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

	// The database DSN would read these as the start of its options.
	if strings.ContainsAny(cfg.DataDir, "?#") {
		fail("DATA_DIR", errors.New("must not contain ? or #"))
	}

	if u, err := url.Parse(cfg.BaseURL); err != nil {
		fail("BASE_URL", err)
	} else if !bareHTTPURL(u, cfg.BaseURL) {
		fail("BASE_URL", errors.New("must be an http(s) origin with an optional path"))
	} else {
		cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
		cfg.Host = u.Hostname()
	}

	if n, err := strconv.ParseInt(get("MAX_FILE_BYTES", "1073741824"), 10, 64); err != nil {
		fail("MAX_FILE_BYTES", err)
	} else if n <= 0 || n > maxFileBytes {
		fail("MAX_FILE_BYTES", errors.New("must be positive and at most 1 TiB"))
	} else {
		cfg.MaxFileBytes = n
	}

	if n, err := strconv.ParseInt(get("MAX_TOTAL_BYTES", "21474836480"), 10, 64); err != nil {
		fail("MAX_TOTAL_BYTES", err)
	} else if n < cfg.MaxFileBytes+1<<20 {
		fail("MAX_TOTAL_BYTES", errors.New("must leave room for one file of VAULT_MAX_FILE_BYTES"))
	} else if n > maxTotalBytes {
		fail("MAX_TOTAL_BYTES", errors.New("must be at most 1 PiB"))
	} else {
		cfg.MaxTotalBytes = n
	}

	if err := cfg.LogLevel.UnmarshalText([]byte(get("LOG_LEVEL", "info"))); err != nil {
		fail("LOG_LEVEL", err)
	}

	for _, item := range strings.Split(get("TRUSTED_PROXIES", ""), ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		proxy, err := parseProxy(item)
		if err != nil {
			fail("TRUSTED_PROXIES", err)
			continue
		}
		cfg.TrustedProxies = append(cfg.TrustedProxies, proxy)
	}

	cfg.Storage = get("STORAGE", "disk")
	switch cfg.Storage {
	case "disk":
		// A bucket configured by mistake would leave the files on disk
		// while the operator believes they are in S3.
		for _, name := range s3Variables {
			if get(name, "") != "" {
				fail(name, errors.New("is set but VAULT_STORAGE is not s3"))
			}
		}
	case "s3":
		cfg.S3 = S3{
			Endpoint:        get("S3_ENDPOINT", ""),
			Region:          get("S3_REGION", "us-east-1"),
			Bucket:          get("S3_BUCKET", ""),
			AccessKeyID:     get("S3_ACCESS_KEY_ID", ""),
			SecretAccessKey: get("S3_SECRET_ACCESS_KEY", ""),
		}
		if cfg.S3.Endpoint != "" {
			if err := checkEndpoint(cfg.S3.Endpoint); err != nil {
				fail("S3_ENDPOINT", err)
			}
		}
		if b, err := strconv.ParseBool(get("S3_PATH_STYLE", strconv.FormatBool(cfg.S3.Endpoint != ""))); err != nil {
			fail("S3_PATH_STYLE", errors.New("must be true or false"))
		} else {
			cfg.S3.PathStyle = b
		}
		if cfg.MaxFileBytes > blob.MaxS3ObjectBytes {
			fail("MAX_FILE_BYTES", errors.New("must be at most 5 GiB with S3, the most it takes in one request"))
		}
		// Values are never echoed: one of them is a secret.
		for name, value := range map[string]string{
			"S3_BUCKET": cfg.S3.Bucket, "S3_ACCESS_KEY_ID": cfg.S3.AccessKeyID, "S3_SECRET_ACCESS_KEY": cfg.S3.SecretAccessKey,
		} {
			if value == "" {
				fail(name, errors.New("is required when VAULT_STORAGE is s3"))
			}
		}
	default:
		fail("STORAGE", errors.New(`must be "disk" or "s3"`))
	}

	return cfg, errors.Join(errs...)
}

// bareHTTPURL reports whether u, parsed from raw, is an http(s) URL with a
// host and no credentials, query or fragment. raw is searched for ? and # so
// that an empty query or fragment, as in "https://h?", is refused too.
func bareHTTPURL(u *url.URL, raw string) bool {
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil &&
		!strings.ContainsAny(raw, "?#")
}

// checkEndpoint accepts an http(s) URL with no credentials, query or
// fragment. Plain http must stay on this machine or reach a single-label
// name, such as a Compose service; anything further needs TLS.
func checkEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || !bareHTTPURL(u, endpoint) {
		return errors.New("must be an http(s) URL")
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		local := !strings.Contains(host, ".")
		if ip, err := netip.ParseAddr(host); err == nil {
			local = ip.IsLoopback()
		}
		if !local {
			return errors.New("must use https unless it is on this machine or a single-label host such as a Compose service")
		}
	}
	return nil
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
