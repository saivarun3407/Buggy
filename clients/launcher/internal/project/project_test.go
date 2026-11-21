package project

import (
	"strings"
	"testing"
)

func TestRepoDefaultsToThisFork(t *testing.T) {
	t.Setenv(RepoEnv, "")
	if got := Repo(); got != "saivarun3407/Buggy" {
		t.Fatalf("Repo() = %q, want saivarun3407/Buggy", got)
	}
	if got := ImagePrefix(); got != "ghcr.io/saivarun3407/" {
		t.Fatalf("ImagePrefix() = %q", got)
	}
}

func TestRepoOverride(t *testing.T) {
	t.Setenv(RepoEnv, "Some-Org/Buggy")
	if got := Repo(); got != "Some-Org/Buggy" {
		t.Fatalf("Repo() = %q", got)
	}
	if got := Owner(); got != "Some-Org" {
		t.Fatalf("Owner() = %q", got)
	}
	// Registry paths are lower case even when the owner is not.
	if got := ImagePrefix(); got != "ghcr.io/some-org/" {
		t.Fatalf("ImagePrefix() = %q", got)
	}
}

func TestMalformedOverrideIsIgnored(t *testing.T) {
	for _, bad := range []string{"no-slash", "a/b/c", "../evil", "owner/name?x=1", "owner/ name", "/name"} {
		t.Setenv(RepoEnv, bad)
		if got := Repo(); got != DefaultRepo {
			t.Errorf("BUGGY_REPO=%q: Repo() = %q, want the default", bad, got)
		}
	}
}

func TestNoUpstreamOrganisation(t *testing.T) {
	if strings.Contains(strings.ToLower(DefaultRepo), "purpleailab") {
		t.Fatalf("DefaultRepo %q targets the upstream organisation", DefaultRepo)
	}
}
