package config

import (
	"os"
	"strings"
	"testing"
)

func TestNewInstallationSecrets_generates_nondefault_credentials(t *testing.T) {
	// Given
	const defaultMasterKey = "sk-buggy-master"
	const defaultDatabasePassword = "buggy"

	// When
	secrets, err := NewInstallationSecrets()

	// Then
	if err != nil {
		t.Fatalf("NewInstallationSecrets() error = %v", err)
	}
	if secrets.LiteLLMMasterKey == defaultMasterKey {
		t.Fatal("LiteLLM master key must not use the public default")
	}
	if secrets.PostgresPassword == defaultDatabasePassword {
		t.Fatal("Postgres password must not use the public default")
	}
	if !strings.HasPrefix(secrets.LiteLLMMasterKey, "sk-") {
		t.Fatalf("LiteLLM master key = %q, want sk- prefix", secrets.LiteLLMMasterKey)
	}
	wantLengths := map[string]int{
		secrets.LiteLLMMasterKey: 67,
		secrets.LiteLLMSaltKey:   67,
		secrets.PostgresPassword: 48,
		secrets.Neo4jPassword:    64,
	}
	for value, want := range wantLengths {
		if len(value) != want {
			t.Fatalf("generated credential length = %d, want %d", len(value), want)
		}
	}
}

func TestNewInstallationSecrets_generates_independent_values(t *testing.T) {
	// Given
	const generatedSecretCount = 4

	// When
	secrets, err := NewInstallationSecrets()

	// Then
	if err != nil {
		t.Fatalf("NewInstallationSecrets() error = %v", err)
	}
	values := map[string]struct{}{
		secrets.LiteLLMMasterKey: {},
		secrets.LiteLLMSaltKey:   {},
		secrets.PostgresPassword: {},
		secrets.Neo4jPassword:    {},
	}
	if len(values) != generatedSecretCount {
		t.Fatalf("generated %d unique values, want %d", len(values), generatedSecretCount)
	}
}

func TestEnsureScopeSecrets_generates_missing_and_keeps_existing(t *testing.T) {
	// Given an .env that already holds one of the three scope secrets
	path := t.TempDir() + "/.env"
	if err := os.WriteFile(path, []byte("SANDBOX_TOKEN=keep-me\nOTHER=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"SANDBOX_TOKEN": "keep-me", "OTHER": "1"}

	// When the launcher ensures the scope secrets
	generated, err := EnsureScopeSecrets(path, env)

	// Then only the missing ones are generated, on disk and in memory
	if err != nil {
		t.Fatalf("EnsureScopeSecrets() error = %v", err)
	}
	if len(generated) != len(ScopeSecretKeys)-1 {
		t.Fatalf("generated = %v, want every missing key", generated)
	}
	onDisk, err := LoadEnv(path)
	if err != nil {
		t.Fatal(err)
	}
	if onDisk["SANDBOX_TOKEN"] != "keep-me" || env["SANDBOX_TOKEN"] != "keep-me" {
		t.Fatal("existing SANDBOX_TOKEN was rotated")
	}
	for _, key := range []string{"EGRESS_GUARD_TOKEN", "BUGGY_STACK_MCP_TOKEN", "BUGGY_AUDIT_HMAC_KEY"} {
		if len(onDisk[key]) != 64 || onDisk[key] != env[key] {
			t.Fatalf("%s = %q on disk, %q in memory; want one 64-hex value", key, onDisk[key], env[key])
		}
	}
	if onDisk["EGRESS_GUARD_TOKEN"] == onDisk["BUGGY_AUDIT_HMAC_KEY"] {
		t.Fatal("secrets must be independent")
	}

	// And a second call changes nothing
	again, err := EnsureScopeSecrets(path, env)
	if err != nil || len(again) != 0 {
		t.Fatalf("second call generated %v (err %v), want nothing", again, err)
	}
}
