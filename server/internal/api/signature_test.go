package api

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The Wycheproof HMAC-SHA256 vectors with a 256-bit key and a full 256-bit
// tag, the sizes of an auth key and a download signature: valid tags must
// pass the server's check and every modified one must fail it.
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
		if g.KeySize != 256 || g.TagSize != 256 {
			continue
		}
		for _, tc := range g.Tests {
			count++
			got := validSignature(unhex(tc.Key), unhex(tc.Msg), unhex(tc.Tag))
			if got != (tc.Result == "valid") {
				t.Errorf("tcId %d (%s): valid = %v, want %s", tc.TcID, tc.Comment, got, tc.Result)
			}
		}
	}
	if count != 81 {
		t.Fatalf("applied %d vectors, want 81", count)
	}
}
