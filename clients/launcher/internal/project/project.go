// Package project names the GitHub repository this launcher installs and
// updates from, and the container registry its images are published to.
//
// It is the one place the launcher learns its origin. Releases, config
// files, the star prompt and the registry prefix all derive from Repo(), so
// a fork changes one string (or sets BUGGY_REPO) instead of hunting for
// hard-coded organisations.
package project

import (
	"os"
	"regexp"
	"strings"
)

// DefaultRepo is the "owner/name" of the repository releases come from. It
// is a var so the release build can stamp the repository it was built in
// (GoReleaser: -X .../internal/project.DefaultRepo=<owner>/<name>).
var DefaultRepo = "saivarun3407/Buggy"

// RepoEnv overrides DefaultRepo at run time, e.g. to install from a fork.
const RepoEnv = "BUGGY_REPO"

// ImagePrefixEnv is the compose variable that prefixes every Buggy image
// name (`${BUGGY_IMAGE_PREFIX:-}buggy-<name>:<tag>`).
const ImagePrefixEnv = "BUGGY_IMAGE_PREFIX"

// Registry is the host Buggy images are published to.
const Registry = "ghcr.io"

// GitHub owner and repository names: letters, digits, '-', '_' and '.'.
var repoPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+$`)

// Repo returns the "owner/name" to install and update from: BUGGY_REPO when
// it is a well-formed slug, else DefaultRepo. A malformed override is
// ignored rather than spliced into download URLs.
func Repo() string {
	if v := strings.TrimSpace(os.Getenv(RepoEnv)); repoPattern.MatchString(v) {
		return v
	}
	return DefaultRepo
}

// Owner returns the owner half of Repo().
func Owner() string {
	owner, _, _ := strings.Cut(Repo(), "/")
	return owner
}

// ImagePrefix returns the registry prefix released images are published
// under, with its trailing slash: "ghcr.io/<owner, lower case>/". Registry
// paths must be lower case, while GitHub owners need not be.
func ImagePrefix() string {
	return Registry + "/" + strings.ToLower(Owner()) + "/"
}
