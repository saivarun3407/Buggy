# Benchmark results policy

A benchmark number is a claim. It may be published only when anyone can check
it from the files next to it.

## Rules

1. A benchmark number (solve count, rate, cost, time, tokens) may appear in the
   README or any other document only with a link to the run directory it comes
   from, and that directory must pass:

   ```bash
   uv run python -m benchmark.evidence verify benchmark/results/<run-id>
   ```

2. The number must be copied from that directory's `SCORECARD.md`, which is
   generated, never edited:

   ```bash
   uv run python -m benchmark.scorecard benchmark/results/<run-id> --write
   ```

   `--write` is refused when verification fails, and `verify` fails when
   `SCORECARD.md` differs from what the records render.

3. Failures are published with the wins. Every attempted target has a record
   and a transcript; every target of the suite without a record is listed as
   not attempted. A subset run is reported as a subset.

4. Numbers that predate this contract, or whose run directory does not pass
   `verify`, are labelled **historical** wherever they appear and are not
   compared with current results. `benchmark/results/README.md` is such a
   record: invalidated, kept for audit.

5. No run directory, no number. "Not run" is a valid entry; an estimate is not.

## Lab stage evaluations

A stage evaluation of a `buggy hunt` lab run (`benchmark/lab/results/<run-id>/`,
written by `python -m benchmark.lab evaluate`) follows the same rules with its
own check. Its numbers come from its `SCORECARD.md`, and the directory must pass:

```bash
uv run python -m benchmark.lab verify benchmark/lab/results/<run-id>
```

It holds `inputs.json` (what was read from the run, reduced), `evaluation.json`,
`manifest.json` (sha256 of every input file) and `SCORECARD.md`. `verify`
re-evaluates the inputs and re-renders the scorecard. It shows the numbers
follow from the inputs; like `benchmark.evidence verify`, it cannot show the
inputs came from a real run.

## What a run directory contains

| File | Content |
|---|---|
| `manifest.json` | run id, suite, every target of the suite with its level |
| `<target>.json` | one record per target: commitment, reveal, outcome, model, revision, inputs, tokens, cost |
| `transcripts/<target>.jsonl` | the raw solver output the outcome was decided on |
| `SCORECARD.md` | generated from the records |

The record is written twice. Before the attempt: the sha256 of that attempt's
random flag (`flag_commitment`). After it: the flag (`flag_revealed`), the
outcome and the transcript hash. A win cites the transcript line that contains
the flag. The contract is defined in `benchmark/evidence.py`.

## What `verify` shows, and what it does not

It shows the directory is internally consistent: each revealed flag matches its
commitment, each transcript is the one that was hashed, each win cites a line
that contains the flag, each failure has a reason, no target is duplicated or
missing its transcript, and the timestamps put the commitment first.

It does not show that the files were produced by a real run: timestamps are
self-reported, and a whole directory can be fabricated consistently. To make
the commitment binding, publish the commitment files (for example, push them)
before the solver starts. Reproducing a result still means re-running it at the
recorded revision with the recorded model.
