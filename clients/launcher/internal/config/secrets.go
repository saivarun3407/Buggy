package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// InstallationSecrets contains the service credentials generated for a new
// launcher-managed installation.
type InstallationSecrets struct {
	LiteLLMMasterKey string
	LiteLLMSaltKey   string
	PostgresPassword string
	Neo4jPassword    string
	// SandboxToken authenticates callers of the sandbox daemon.
	SandboxToken string
	// EgressGuardToken authenticates the langgraph service to the egress
	// guard's control API. It is never given to the sandbox.
	EgressGuardToken string
	// AuditHMACKey binds every audit-ledger record.
	AuditHMACKey string
}

// NewInstallationSecrets generates independent credentials for every service
// that otherwise inherits a public development default from .env.example.
func NewInstallationSecrets() (InstallationSecrets, error) {
	masterKey, err := randomHex(32)
	if err != nil {
		return InstallationSecrets{}, fmt.Errorf("generate LiteLLM master key: %w", err)
	}
	saltKey, err := randomHex(32)
	if err != nil {
		return InstallationSecrets{}, fmt.Errorf("generate LiteLLM salt key: %w", err)
	}
	postgresPassword, err := randomHex(24)
	if err != nil {
		return InstallationSecrets{}, fmt.Errorf("generate Postgres password: %w", err)
	}
	neo4jPassword, err := randomHex(32)
	if err != nil {
		return InstallationSecrets{}, fmt.Errorf("generate Neo4j password: %w", err)
	}

	sandboxToken, err := randomHex(32)
	if err != nil {
		return InstallationSecrets{}, fmt.Errorf("generate sandbox token: %w", err)
	}
	egressGuardToken, err := randomHex(32)
	if err != nil {
		return InstallationSecrets{}, fmt.Errorf("generate egress guard token: %w", err)
	}
	auditHMACKey, err := randomHex(32)
	if err != nil {
		return InstallationSecrets{}, fmt.Errorf("generate audit HMAC key: %w", err)
	}

	return InstallationSecrets{
		LiteLLMMasterKey: "sk-" + masterKey,
		LiteLLMSaltKey:   "sk-" + saltKey,
		PostgresPassword: postgresPassword,
		Neo4jPassword:    neo4jPassword,
		SandboxToken:     sandboxToken,
		EgressGuardToken: egressGuardToken,
		AuditHMACKey:     auditHMACKey,
	}, nil
}

func randomHex(byteLength int) (string, error) {
	value := make([]byte, byteLength)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("read operating-system randomness: %w", err)
	}
	return hex.EncodeToString(value), nil
}

// ScopeSecretKeys are the .env keys the scope-enforcement services require.
// Unlike database passwords they are not bound to a persistent volume, so a
// missing one can be generated at any start.
var ScopeSecretKeys = []string{"SANDBOX_TOKEN", "EGRESS_GUARD_TOKEN", "BUGGY_STACK_MCP_TOKEN", "BUGGY_AUDIT_HMAC_KEY"}

// EnsureScopeSecrets generates any missing scope-enforcement secret, writes it
// to the .env at envPath, and mirrors it into env. It returns the keys it
// generated. Existing values are never changed.
func EnsureScopeSecrets(envPath string, env map[string]string) ([]string, error) {
	var generated []string
	for _, key := range ScopeSecretKeys {
		if strings.TrimSpace(env[key]) != "" {
			continue
		}
		value, err := randomHex(32)
		if err != nil {
			return generated, fmt.Errorf("generate %s: %w", key, err)
		}
		if err := SetEnvKey(envPath, key, value); err != nil {
			return generated, fmt.Errorf("write %s to %s: %w", key, envPath, err)
		}
		env[key] = value
		generated = append(generated, key)
	}
	return generated, nil
}
