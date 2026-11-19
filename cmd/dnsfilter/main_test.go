package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"dnsfilter"
	"dnsfilter/internal/config"
)

func TestEnsureConfigWritesTheExampleOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	created, err := ensureConfig(path)
	if err != nil || !created {
		t.Fatalf("first call: created=%v err=%v", created, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dnsfilter.ExampleConfig) {
		t.Fatal("written config differs from config.example.json")
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("written config does not load: %v", err)
	}

	if err := os.WriteFile(path, []byte("edited"), 0o644); err != nil {
		t.Fatal(err)
	}
	created, err = ensureConfig(path)
	if err != nil || created {
		t.Fatalf("second call: created=%v err=%v", created, err)
	}
	if got, _ := os.ReadFile(path); string(got) != "edited" {
		t.Fatalf("an existing config was overwritten: %q", got)
	}
}
