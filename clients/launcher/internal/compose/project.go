package compose

import (
	"os"
	"strings"
)

// StackName returns the value of BUGGY_STACK_NAME, sanitized to
// match the same `[a-z0-9-]{1,32}` shape we accept in compose object
// names. Empty when the user has not opted into a named stack.
func StackName() string {
	name := strings.TrimSpace(os.Getenv("BUGGY_STACK_NAME"))
	if name == "" {
		return ""
	}
	if len(name) > 32 {
		name = name[:32]
	}
	clean := strings.Builder{}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			r = '-'
		}
		clean.WriteRune(r)
	}
	return clean.String()
}

// ComposeProjectEnv is the explicit override env var. Setting it pins the
// launcher's compose project, e.g. to run inside an existing project.
const ComposeProjectEnv = "BUGGY_COMPOSE_PROJECT"

// ComposeProjectName returns the docker compose `-p PROJECT` value the
// launcher passes on every compose call.
//
// Resolution order:
//
//  1. BUGGY_COMPOSE_PROJECT env — explicit user override.
//  2. Stack-name fallback — "buggy[-${BUGGY_STACK_NAME}]".
//
// "container_name:" fields in docker-compose.yml are global to the docker
// daemon, so a stable project name keeps two callers from fighting over the
// same container names.
func ComposeProjectName() string {
	if v := strings.TrimSpace(os.Getenv(ComposeProjectEnv)); v != "" {
		return v
	}
	suffix := StackName()
	if suffix == "" {
		return "buggy"
	}
	return "buggy-" + suffix
}

// ComposeCommandEnv returns the environment every docker compose call runs
// with. A variable missing from the process environment is set to the empty
// string, so compose interpolates "" rather than a stale --env-file value
// into container names (BUGGY_STACK_NAME) and the project name
// (BUGGY_COMPOSE_PROJECT).
//
// COMPOSE_PROFILES is forced empty: compose unions it with explicit
// `--profile X` flags, so a stale `COMPOSE_PROFILES=...` line in
// $BUGGY_HOME/.env would otherwise bring up profiles the launcher did not
// ask for. Last-set-wins in the child env, so this overrides the parent.
func ComposeCommandEnv() []string {
	env := os.Environ()
	for _, key := range []string{
		"BUGGY_STACK_NAME",
		ComposeProjectEnv,
	} {
		if _, ok := os.LookupEnv(key); !ok {
			env = append(env, key+"=")
		}
	}
	env = append(env, "COMPOSE_PROFILES=")
	return env
}
