package api

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The Wycheproof HMAC-SHA256 vectors with a 256-bit key, the size of an auth
// key: a valid full tag must pass the server's check, and a modified tag or
// a valid one truncated to 128 bits must fail it.
func TestValidSignatureWycheproof(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/wycheproof/hmac_sha256_test.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		TestGroups []struct {
			KeySize int `json:"keySize"`
			TagSize int `json:"tagSize"`
			Tests   []struct {
				TcID    int    `json:"tcId"`
				Comment string `json:"comment"`
				Key     string `json:"key"`
				Msg     string `json:"msg"`
				Tag     string `json:"tag"`
				Result  string `json:"result"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	count := 0
	for _, g := range file.TestGroups {
		if g.KeySize != 256 {
			continue
		}
		for _, tc := range g.Tests {
			count++
			got := validSignature(unhex(tc.Key), unhex(tc.Msg), unhex(tc.Tag))
			if want := tc.Result == "valid" && g.TagSize == 256; got != want {
				t.Errorf("tcId %d (%s, %d-bit tag): valid = %v, want %v", tc.TcID, tc.Comment, g.TagSize, got, want)
			}
		}
	}
	if count != 162 {
		t.Fatalf("applied %d vectors, want 162", count)
	}
}
