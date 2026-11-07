# Reproduce Fieldwork checks

## Toolchain

Use Python 3.12 and Node 26.7.0. The repository records these in `.python-version` and `.node-version`. Run commands from the repository root. PowerShell examples below use the Windows virtual-environment path. On Linux or macOS, use `.venv/bin/python`.

## Install the pinned dependencies

```powershell
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-api.lock
npm --prefix apps/web ci --ignore-scripts --no-audit --no-fund
```

The API lock includes the exact Python package versions needed for the review path. CPU training adds the separately pinned PyTorch wheel.

```powershell
.venv/Scripts/python -m pip install 'torch==2.14.1+cpu' --index-url https://download.pytorch.org/whl/cpu
.venv/Scripts/python -m pip check
```

## Run the focused review

```powershell
python verify.py
```

This checks installed Python dependencies, verifies metric denominators and the independent evaluator, checks synthetic manifest integrity, exercises the bundled helper imports, and builds the React interface. It requires no private dataset or database profile. The execution receipt and logs are written under `.local/review-checks/`.

## Run a small synthetic training experiment

With the pinned CPU wheel installed, generate an authored dataset and train for one epoch.

```powershell
.venv/Scripts/python -c "from fieldwork.data import generate; generate('.local/review-data')"
.venv/Scripts/python -m fieldwork.ml --data .local/review-data --out .local/review-training --epochs 1 --seed 42
```

Inspect `.local/review-training/result.json` and the `epoch-1` checkpoint. This demonstrates the training and checkpoint codec on generated images. The historical flower accuracy comes from a distinct real-image population, described in the result report.

## Database-backed application and replay

The application uses PostgreSQL, separate API and worker identities, database migrations, and private local profiles. See [the operator runbook](RUNBOOK.md) for the original deployment workflow. A new operator must provision their own accounts, rights registry, and model/decoder images. Private profiles and trained artifacts are excluded from the publication copy.

`tests/test_replay.py` contains the controlled process-loss and replay test. Its `isolated_store` fixture creates a throwaway database using an operator profile. The test restores checkpoint state, rejects stale writes, compares final model parameters and logits with a control, and checks the 1e-6 tolerance. The larger flower recovery measurement is documented in `real-host-crash-replay-20261103.md`.

The `tools/activate_*`, `tools/apply_*`, and `tools/r5_*` scripts include historical operator procedures tied to recorded deployment identities and source hashes. Their prerequisites are retained in their source and original documentation. The standalone review command exercises the portable subset.

## Data and distribution

The publication copy includes the authored synthetic dataset generator. The flower corpus, rights registry, trained checkpoints, and qualified releases require their own asset-level provenance and rights decisions. The recorded annotator/steward roles were simulated, as disclosed in the acceptance report.
