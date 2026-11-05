package config

import (
	"log/slog"
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
	if cfg != want {
		t.Errorf("got %+v, want %+v", cfg, want)
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := Load(lookupFrom(map[string]string{
		"VAULT_LISTEN_ADDR":    "127.0.0.1:9000",
		"VAULT_BASE_URL":       "https://share.example.com/vault/",
		"VAULT_DATA_DIR":       "/data",
		"VAULT_MAX_FILE_BYTES": "1024",
		"VAULT_WEB_DIR":        "/srv/web",
		"VAULT_LOG_LEVEL":      "debug",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		ListenAddr:   "127.0.0.1:9000",
		BaseURL:      "https://share.example.com/vault",
		DataDir:      "/data",
		MaxFileBytes: 1024,
		WebDir:       "/srv/web",
		LogLevel:     slog.LevelDebug,
	}
	if cfg != want {
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
		"VAULT_LISTEN_ADDR":    "8080",
		"VAULT_BASE_URL":       "ftp://x",
		"VAULT_MAX_FILE_BYTES": "0",
		"VAULT_LOG_LEVEL":      "loud",
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
		for _, bad := range []string{"localhost", "https://", "https://u:p@h", "https://h?x=1", "https://h#frag", "https://h/%zz"} {
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
