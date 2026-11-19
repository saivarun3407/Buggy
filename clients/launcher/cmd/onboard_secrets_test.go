package cmd

import "testing"

func TestOnboardingInstallationSecretsPreservesExistingValues(t *testing.T) {
	existing := map[string]string{
		"LITELLM_MASTER_KEY": "existing-master",
		"LITELLM_SALT_KEY":   "existing-salt",
		"POSTGRES_PASSWORD":  "existing-postgres",
		"NEO4J_PASSWORD":     "existing-neo4j",
		"SANDBOX_TOKEN":      "existing-sandbox",
		"EGRESS_GUARD_TOKEN": "existing-guard",
	}

	// Given credentials already bound to persistent database volumes, when the
	// wizard is reset, then every installation credential remains unchanged.
	secrets, err := onboardingInstallationSecrets(existing)
	if err != nil {
		t.Fatalf("onboardingInstallationSecrets() error: %v", err)
	}
	if secrets.LiteLLMMasterKey != existing["LITELLM_MASTER_KEY"] ||
		secrets.LiteLLMSaltKey != existing["LITELLM_SALT_KEY"] ||
		secrets.PostgresPassword != existing["POSTGRES_PASSWORD"] ||
		secrets.Neo4jPassword != existing["NEO4J_PASSWORD"] ||
		secrets.SandboxToken != existing["SANDBOX_TOKEN"] ||
		secrets.EgressGuardToken != existing["EGRESS_GUARD_TOKEN"] {
		t.Fatalf("reset rotated credentials: %#v", secrets)
	}
}

func TestOnboardingInstallationSecretsFillsMissingValues(t *testing.T) {
	// Given a partial configuration, when installation secrets are resolved,
	// then the existing value is preserved and every missing value is generated.
	secrets, err := onboardingInstallationSecrets(map[string]string{
		"POSTGRES_PASSWORD": "existing-postgres",
	})
	if err != nil {
		t.Fatalf("onboardingInstallationSecrets() error: %v", err)
	}
	if secrets.PostgresPassword != "existing-postgres" {
		t.Fatalf("PostgresPassword = %q, want preserved value", secrets.PostgresPassword)
	}
	if secrets.LiteLLMMasterKey == "" || secrets.LiteLLMSaltKey == "" || secrets.Neo4jPassword == "" ||
		secrets.SandboxToken == "" || secrets.EgressGuardToken == "" || secrets.AuditHMACKey == "" {
		t.Fatal("missing installation credentials were not generated")
	}
}
