# Releasing from this repository

A release is cut by pushing a version tag. Everything it publishes lands in
**this** repository and its GitHub Container Registry namespace; no workflow,
script or launcher source names another organisation. The owner and name come
from the GitHub context (`github.repository`, `github.repository_owner`), so a
fork of this repository releases into its own namespace without edits.

## Before the first tag (one-time GitHub setup)

1. **Actions may write packages.** Settings → Actions → General → Workflow
   permissions: *Read and write permissions*. The release jobs request
   `packages: write`, `contents: write`, `id-token: write` (Cosign keyless
   signing) and `attestations: write`; an organisation policy that caps the
   token at read-only blocks the push.
2. **Native arm64 runners.** `docker-heavy` and `docker-web` run on
   `ubuntu-24.04-arm`. That label is free for public repositories; on a
   private repository it needs a plan that includes arm64 hosted runners.
3. **The `pypi-release` environment.** Every release job runs in it. GitHub
   creates it on first use; add required reviewers there if a person must
   approve each release.
4. **Make the packages public after the first release.** GHCR creates each
   `buggy-*` package as *private*. An install pulls anonymously, and
   `pin-digests.yml` inspects the images without logging in, so open each
   package (Profile → Packages → `buggy-…` → Package settings) and set
   *Change visibility → Public*. Do it once per image; later versions inherit
   it. Linking each package to this repository there also lets the release
   workflow keep pushing to it.
5. **PyPI stays off unless you own the names.** See below.

## Cutting a release

```bash
git tag v1.4.0          # final release:  vMAJOR.MINOR.PATCH
git tag v1.5.0-rc.1     # pre-release:    any suffix after a hyphen
git push origin v1.4.0
```

The tag must start with `v` (`on: push: tags: ["v*"]`); the version is the
tag without the `v`. A version with a hyphen is a pre-release: it is published
as such and never moves `:latest` or `:stable`.

Source-tree version fields stay at the `0.0.0` sentinel; the version is
stamped in at build time, so there is no bump commit.

## What a release publishes, and where

| Job | Publishes |
|-----|-----------|
| `launcher` | GoReleaser builds the `buggy` launcher for linux, darwin and windows on amd64 and arm64, plus `checksums.txt`, into a **draft** GitHub release in this repository. The binary is stamped with `github.repository`, so it updates from, and pulls images of, the repository that built it. The job also uploads `config-checksums.txt`, the SHA-256 manifest of the compose files, `config/litellm.yaml` and `.env.example`. |
| `docker` | `buggy-litellm`, `buggy-langgraph`, `buggy-cli`, `buggy-skillogy`, `buggy-egress-guard` and `buggy-browser`, multi-arch under QEMU. |
| `docker-heavy` + `docker-heavy-merge` | `buggy-sandbox` and `buggy-pipeline`, built per platform on native runners (too slow under QEMU) and merged into one manifest. |
| `docker-web` + `docker-web-merge` | `buggy-web`, the same way. |
| `publish-release` | Checks that every `:<version>` image exists, moves `:latest` (final releases only) and turns the draft release into a published one. |
| `publish-pypi` | Opt-in, see below. Nothing waits for it. |

Images go to `ghcr.io/<owner>/buggy-<name>:<version>`, where `<owner>` is the
repository owner in lower case (registry paths must be lower case). Each image
and manifest is signed with Cosign (keyless, GitHub OIDC), has a CycloneDX
SBOM attested to it, and has the SBOM attached to the workflow run.

After the release is published, `pin-digests.yml` uploads
`image-digests.txt` (each image's manifest digest). `promote-stable.yml` runs
daily and moves `:stable` to the newest final release older than the soak
window (7 days). `release-recover.yml` re-runs the verify, promote and
publish steps for a release whose images were all pushed but whose final job
failed; it never builds an image.

Every compose image is published. `tests/test_release_images.py` fails if an
image the compose files run is missing from a build job or from one of the
image lists.

To check a signature:

```bash
cosign verify ghcr.io/<owner>/buggy-pipeline:<version> \
  --certificate-identity-regexp 'https://github\.com/<owner>/<repo>/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Enabling PyPI

`publish-pypi` uploads the `buggy`, `buggy-core` and `buggy-sdk` wheels and
sdists. It runs only when the repository variable `PUBLISH_PYPI` is `true`
(Settings → Secrets and variables → Actions → Variables). Set it only if you
own those three names on PyPI, or have renamed the packages to ones you own.
Each project then needs a Trusted Publisher on pypi.org pointing at this
repository, workflow `release.yml`, environment `pypi-release`; no API token
is stored. The rest of the release does not depend on this job, so with the
variable unset it is skipped and the release still completes.

## What the installer then does

```bash
curl -fsSL https://raw.githubusercontent.com/saivarun3407/Buggy/main/scripts/install.sh | bash
```

`scripts/install.sh` installs from `saivarun3407/Buggy`; set
`BUGGY_REPO=<owner>/<name>` to install from another fork. It:

1. picks the version: `VERSION` if set, else the newest final release that
   has soaked for 7 days (`CHANNEL=stable`, the default) or the newest final
   (`CHANNEL=latest`);
2. downloads the compose files, `config/litellm.yaml` and `.env.example` at
   that tag and checks each against the release's `config-checksums.txt`;
3. downloads the launcher binary for this OS and CPU and checks it against
   `checksums.txt`;
4. writes `BUGGY_IMAGE_PREFIX=ghcr.io/<owner>/` into an existing `.env` (a
   value already there is kept), and pulls the images with that prefix.

On a fresh install there is no `.env` yet (`buggy onboard` creates it); the
release launcher adds the same `BUGGY_IMAGE_PREFIX` on its first
`buggy start`, and sets it for every compose call it makes until then.

The compose files name images as
`${BUGGY_IMAGE_PREFIX:-}buggy-<name>:${BUGGY_VERSION:-stable}`. With the
variable unset (a source checkout), the names are the bare `buggy-<name>`
tags that `make build-images` produces, exactly as before.
