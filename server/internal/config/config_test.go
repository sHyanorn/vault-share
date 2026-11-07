package config

import (
	"log/slog"
	"maps"
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
		ListenAddr:    ":8080",
		BaseURL:       "https://localhost",
		Host:          "localhost",
		DataDir:       "data",
		Storage:       "disk",
		MaxFileBytes:  1 << 30,
		MaxTotalBytes: 20 << 30,
		LogLevel:      slog.LevelInfo,
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
		"VAULT_MAX_TOTAL_BYTES": "4194304",
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
		Host:           "share.example.com",
		DataDir:        "/data",
		Storage:        "disk",
		MaxFileBytes:   1024,
		MaxTotalBytes:  4 << 20,
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
		"VAULT_DATA_DIR":        "data?mode=ro",
		"VAULT_BASE_URL":        "ftp://x",
		"VAULT_MAX_FILE_BYTES":  "0",
		"VAULT_MAX_TOTAL_BYTES": "1000",
		"VAULT_LOG_LEVEL":       "loud",
		"VAULT_TRUSTED_PROXIES": "10.0.0.0/8, proxy",
		"VAULT_STORAGE":         "tape",
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

func TestLoadS3(t *testing.T) {
	env := map[string]string{
		"VAULT_STORAGE":              "s3",
		"VAULT_S3_ENDPOINT":          "https://s3.example.com",
		"VAULT_S3_BUCKET":            "vault",
		"VAULT_S3_ACCESS_KEY_ID":     "AKID",
		"VAULT_S3_SECRET_ACCESS_KEY": "the-secret-value",
	}
	cfg, err := Load(lookupFrom(env))
	if err != nil {
		t.Fatal(err)
	}
	want := S3{Endpoint: "https://s3.example.com", Region: "us-east-1", Bucket: "vault", AccessKeyID: "AKID", SecretAccessKey: "the-secret-value", PathStyle: true}
	if cfg.Storage != "s3" || cfg.S3 != want {
		t.Errorf("got %q %+v", cfg.Storage, cfg.S3)
	}
	for _, c := range []struct {
		endpoint, pathStyle string
		want                bool
	}{{"", "", false}, {"https://s3.example.com", "false", false}, {"", "true", true}} {
		changed := maps.Clone(env)
		changed["VAULT_S3_ENDPOINT"], changed["VAULT_S3_PATH_STYLE"] = c.endpoint, c.pathStyle
		if cfg, err := Load(lookupFrom(changed)); err != nil || cfg.S3.PathStyle != c.want {
			t.Errorf("endpoint %q, path style %q: %v %v", c.endpoint, c.pathStyle, cfg.S3.PathStyle, err)
		}
	}
	for _, local := range []string{"http://localhost:9000", "http://127.0.0.1:7070", "http://[::1]:7070", "http://s3:7070"} {
		changed := maps.Clone(env)
		changed["VAULT_S3_ENDPOINT"] = local
		if _, err := Load(lookupFrom(changed)); err != nil {
			t.Errorf("plain http to %s: %v", local, err)
		}
	}

	for _, missing := range []string{"VAULT_S3_BUCKET", "VAULT_S3_ACCESS_KEY_ID", "VAULT_S3_SECRET_ACCESS_KEY"} {
		partial := maps.Clone(env)
		delete(partial, missing)
		if _, err := Load(lookupFrom(partial)); err == nil || !strings.Contains(err.Error(), missing) {
			t.Errorf("without %s: %v", missing, err)
		}
	}
	for _, bad := range []string{"s3.example.com", "ftp://s3.example.com", "https://u:p@s3.example.com", "https://s3.example.com?x=1",
		"http://s3.example.com", "http://10.0.0.5:9000"} {
		broken := maps.Clone(env)
		broken["VAULT_S3_ENDPOINT"] = bad
		_, err := Load(lookupFrom(broken))
		if err == nil || !strings.Contains(err.Error(), "VAULT_S3_ENDPOINT") {
			t.Errorf("endpoint %q: %v", bad, err)
		}
		if err != nil && strings.Contains(err.Error(), "the-secret-value") {
			t.Errorf("the error shows the secret: %v", err)
		}
	}
	large := maps.Clone(env)
	large["VAULT_MAX_FILE_BYTES"] = "5368709121" // 5 GiB and one byte
	large["VAULT_MAX_TOTAL_BYTES"] = "10737418240"
	if _, err := Load(lookupFrom(large)); err == nil || !strings.Contains(err.Error(), "VAULT_MAX_FILE_BYTES") {
		t.Errorf("a file limit above one S3 request: %v", err)
	}
	pathStyle := maps.Clone(env)
	pathStyle["VAULT_S3_PATH_STYLE"] = "maybe"
	if _, err := Load(lookupFrom(pathStyle)); err == nil || !strings.Contains(err.Error(), "VAULT_S3_PATH_STYLE") {
		t.Errorf("path style %q: %v", "maybe", err)
	}
	// S3 settings without S3 storage are a mistake to report: the files
	// would stay on disk.
	env["VAULT_STORAGE"] = "disk"
	_, err = Load(lookupFrom(env))
	if err == nil || !strings.Contains(err.Error(), "VAULT_S3_BUCKET") || strings.Contains(err.Error(), "the-secret-value") {
		t.Errorf("disk storage with S3 settings: %v", err)
	}
}
