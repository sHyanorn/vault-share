package config

import (
	"log/slog"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func lookupFrom(env map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		ListenAddr:   ":8080",
		BaseURL:      "https://localhost",
		DataDir:      "data",
		MaxFileBytes: 1 << 30,
		LogLevel:     slog.LevelInfo,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("got %+v, want %+v", cfg, want)
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := Load(lookupFrom(map[string]string{
		"VAULT_LISTEN_ADDR":     "127.0.0.1:9000",
		"VAULT_BASE_URL":        "https://share.example.com/vault/",
		"VAULT_DATA_DIR":        "/data",
		"VAULT_MAX_FILE_BYTES":  "1024",
		"VAULT_WEB_DIR":         "/srv/web",
		"VAULT_LOG_LEVEL":       "debug",
		"VAULT_TRUSTED_PROXIES": "10.0.0.0/8, 192.168.1.5",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		ListenAddr:     "127.0.0.1:9000",
		BaseURL:        "https://share.example.com/vault",
		DataDir:        "/data",
		MaxFileBytes:   1024,
		WebDir:         "/srv/web",
		LogLevel:       slog.LevelDebug,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.1.5/32")},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("got %+v, want %+v", cfg, want)
	}
}

func TestLoadEmptyMeansUnset(t *testing.T) {
	cfg, err := Load(lookupFrom(map[string]string{"VAULT_MAX_FILE_BYTES": "", "VAULT_WEB_DIR": ""}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxFileBytes != 1<<30 || cfg.WebDir != "" {
		t.Errorf("empty variables should fall back to defaults, got %+v", cfg)
	}
}

func TestLoadInvalid(t *testing.T) {
	cases := map[string]string{
		"VAULT_LISTEN_ADDR":     "8080",
		"VAULT_BASE_URL":        "ftp://x",
		"VAULT_MAX_FILE_BYTES":  "0",
		"VAULT_LOG_LEVEL":       "loud",
		"VAULT_TRUSTED_PROXIES": "10.0.0.0/8, proxy",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(lookupFrom(map[string]string{name: value}))
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("want error naming %s, got %v", name, err)
			}
		})
	}
	t.Run("base url variants", func(t *testing.T) {
		for _, bad := range []string{"localhost", "https://", "https://u:p@h", "https://h?x=1", "https://h#frag", "https://h?", "https://h/#", "https://h/%zz"} {
			if _, err := Load(lookupFrom(map[string]string{"VAULT_BASE_URL": bad})); err == nil {
				t.Errorf("%q: want error", bad)
			}
		}
	})
	t.Run("reports every error", func(t *testing.T) {
		_, err := Load(lookupFrom(cases))
		if err == nil {
			t.Fatal("want error")
		}
		for name := range cases {
			if !strings.Contains(err.Error(), name) {
				t.Errorf("error does not mention %s: %v", name, err)
			}
		}
	})
}

func TestTrustedProxiesMatchHowClientsAreSeen(t *testing.T) {
	cases := map[string]string{
		"::ffff:10.0.0.0/104": "10.0.0.0/8",
		"::ffff:10.0.0.1":     "10.0.0.1/32",
		"fe80::1%eth0":        "fe80::1/128",
		"10.1.2.3/8":          "10.0.0.0/8",
	}
	for in, want := range cases {
		cfg, err := Load(lookupFrom(map[string]string{"VAULT_TRUSTED_PROXIES": in}))
		if err != nil || len(cfg.TrustedProxies) != 1 || cfg.TrustedProxies[0].String() != want {
			t.Errorf("%q: got %v, err %v, want %s", in, cfg.TrustedProxies, err, want)
		}
	}
	if _, err := Load(lookupFrom(map[string]string{"VAULT_TRUSTED_PROXIES": "::ffff:0.0.0.0/90"})); err == nil {
		t.Error("a mapped prefix wider than the mapped range was accepted")
	}
}
