# Buggy in CI: gate on verified findings, upload SARIF

A pipeline runs a hunt against a staging URL you are authorized to test, then
gates the job on what the hunt **proved** and uploads it to GitHub code
scanning. Three pieces do this:

| Piece | What it does |
|---|---|
| `buggy hunt ... --fail-on high` | Runs the hunt and writes `hunt-result.json` and the findings report JSON into the control directory (`~/.buggy/control/<engagement>/`). |
| `buggy-cli ci-gate` | Reads the report (and optionally `hunt-result.json`), prints one summary line and the gating findings, writes SARIF 2.1.0, exits with a gate code. |
| `.github/actions/buggy-scan` | Composite action: runs `buggy-cli ci-gate`, then `github/codeql-action/upload-sarif`. |

## What counts

Only **exploit-verified** findings count: the independent verifier re-sent
every request the claim cites and every assertion held on the fresh response.
These, and only these, become SARIF results and fail the gate. Source-verified
and inconclusive items, untested leads and discarded claims never become a
result and never fail the job; the SARIF run carries their counts in
`runs[0].properties.not_proven`.

A run that did not finish is not called clean: an incomplete run exits 3, not 0.

## `buggy-cli ci-gate`

```
buggy-cli ci-gate --report <report.json> [--hunt-result <hunt-result.json>]
                  [--fail-on high] [--fail-on-issues] [--sarif out.sarif]
```

| Exit | Meaning |
|---|---|
| 0 | Complete, and no exploit-verified finding is at or above `--fail-on`. |
| 10 | An exploit-verified finding is at or above `--fail-on` (with `--fail-on-issues`, also a known issue counted in `hunt-result.json`). This wins over an incomplete run: what was proven stays proven. |
| 3 | Nothing at or above the threshold, but the run is incomplete: the report's `summary.complete` or the hunt result's `complete` is false, or the SARIF file could not be written. |
| 2 | Bad input: a file is missing or not JSON, is not a report or a hunt result, or the two name different engagements. |

The codes are the ones `buggy-cli hunt` exits with. `--fail-on` defaults to
`high`. A verified finding whose severity is not one of the five meets every
threshold.

## SARIF

One run, `tool.driver.name` `Buggy`, one rule per vulnerability class
(`buggy/<class>`, with a `helpUri` to a representative CWE). Each result has:

- `level`: critical and high are `error`, medium is `warning`, low and info are `note`;
- `message.text`: title and endpoint, as plain text (finding text is
  untrusted: control characters are removed, `{` `}` doubled and `[` `]`
  escaped so no field becomes a placeholder or a link);
- `locations[0].physicalLocation.artifactLocation.uri`: the endpoint URL,
  rebuilt from validated parts (an endpoint that is not an `http(s)` URL is
  replaced by `buggy-finding/<id>`), with `properties.method` and
  `properties.parameter`;
- `partialFingerprints.findingId`: the finding id, so a re-run updates the
  same alert;
- `properties.security-severity`: critical 9.5, high 8.0, medium 5.5, low 3.0,
  info 0.0 (also set on the rule, which is where code scanning reads it).

The output is deterministic: results are ordered by severity then id, and the
only timestamp is the report's own `generated_at`.

## The GitHub Action

Inputs:

| Input | Default | |
|---|---|---|
| `report` | (required) | Path to the findings report JSON. |
| `hunt-result` | `""` | Path to `hunt-result.json`; makes an incomplete run exit 3. |
| `fail-on` | `high` | critical, high, medium, low or info. |
| `upload-sarif` | `true` | Upload to code scanning. **Needs `permissions: security-events: write`** on the job. |

Outputs: `exit-code` and `sarif-path`. The upload step runs even when the gate
fails, so the alerts are there to look at. Inputs reach the script only as
environment variables; the action prints no secret.

The action installs `buggy-cli` with `pip` unless it is already on `PATH`, so
run `actions/setup-python` first (system Python on recent runners refuses
`pip install`).

## Example workflow

`buggy hunt --lite` maps the target with the deterministic recon pipeline and
needs no model key; it runs no agent, so it proves no finding by itself. Drop
`--lite` (and provide a model key as a secret) for the agents to test and prove
findings. The hunt step is allowed to fail so that the gate and the upload
still run; the gate step decides the job's result from the files.

```yaml
name: Buggy staging scan

on:
  workflow_dispatch:
  schedule:
    - cron: "17 3 * * 1"

permissions:
  contents: read
  security-events: write   # required by upload-sarif

jobs:
  hunt:
    runs-on: ubuntu-latest
    timeout-minutes: 120
    env:
      STAGING_URL: ${{ vars.STAGING_URL }}
      ENGAGEMENT: staging
    steps:
      - uses: actions/checkout@v6

      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"

      - name: Install the buggy launcher
        run: curl -fsSL https://buggy.red/install | bash

      - name: Hunt the staging URL
        id: hunt
        continue-on-error: true
        run: |
          buggy hunt "$STAGING_URL" --lite --yes --non-interactive \
            --engagement-name "$ENGAGEMENT" --fail-on high

      - name: Collect the hunt's files
        if: always()
        run: |
          mkdir -p buggy-out
          cp -- "$HOME/.buggy/control/$ENGAGEMENT/report.json" buggy-out/ || true
          cp -- "$HOME/.buggy/control/$ENGAGEMENT/hunt-result.json" buggy-out/ || true

      - name: Gate and upload
        if: always()
        uses: ./.github/actions/buggy-scan
        with:
          report: buggy-out/report.json
          hunt-result: buggy-out/hunt-result.json
          fail-on: high
          upload-sarif: "true"
```

Outside this repository, use the action as
`PurpleAILAB/Buggy/.github/actions/buggy-scan@<commit sha>`. Pin third-party
actions to a commit SHA in your own workflows.

Run the gate by hand on the same files:

```
buggy-cli ci-gate --report ~/.buggy/control/staging/report.json \
  --hunt-result ~/.buggy/control/staging/hunt-result.json \
  --fail-on high --sarif buggy.sarif
```
