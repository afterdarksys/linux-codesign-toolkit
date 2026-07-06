# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Linux Code Signing Toolkit: a toolkit for code-signing Windows binaries (PE/CAB/MSI/APPX via osslsigncode), Java JARs (jarsigner/keytool), Adobe AIR files, and Apple packages (.pkg/.ipa/.app) on Linux/macOS. Two layers coexist:

1. **v1.x bash CLI** — `codesign-toolkit.sh` (copied to `codesign-toolkit` at build time), a wrapper around osslsigncode/jarsigner/xar/isign. Supports sign/unsign/resign/verify plus timestamping.
2. **v2.0 Python REST API** — FastAPI service in `src/codesign_api/` with API-key auth, SQLite-backed operation tracking, background signing jobs, and SOX/GLBA/PCI-DSS/GDPR compliance/audit features. Fully backward compatible with the CLI.

## Commands

```bash
# Bash CLI (Makefile)
make            # deps (clones+builds osslsigncode via cmake) + build codesign-toolkit
make install    # install to /usr/local (PREFIX overridable)
make test       # runs ./tests/run-tests.sh (CLI test suite)
make clean

# CLI usage
./codesign-toolkit sign -type windows -cert cert.pem -key key.pem -in app.exe -out app-signed.exe
./codesign-toolkit verify -in app-signed.exe

# Python API server (v2.0)
pip install -r requirements.txt
python scripts/create_admin_user.py     # bootstrap admin API key
python -m src.codesign_api.main         # start server on :8000 (docs at /docs)
python scripts/test_api.py YOUR_API_KEY # exercise API endpoints

# Docker
cd docker && docker-compose up -d

# Packaging (hatchling; console script `codesign-api`)
./publish-python-package.sh
```

Configuration for the API is via `.env` (copy `.env.example`). pytest is declared as an optional dep in `pyproject.toml`, but there is no Python unit-test suite — `tests/` contains only the CLI `run-tests.sh`, and `scripts/test_api.py` is a live-server smoke test.

## Architecture

`src/codesign_api/` is the whole Python service:

- `main.py` — FastAPI app entry point; wires routers from `routers/`.
- `signing.py` — the bridge to the actual signing work: it shells out to the same underlying tools the bash CLI uses (osslsigncode etc.), running operations in the background and tracking them in the DB.
- `auth.py` + `models.py` + `database.py` — API-key users with per-signing-type permissions, SQLAlchemy/aiosqlite persistence of users, operations, and files.
- `compliance.py` + `security.py` — audit logging, retention (SOX 7-year), AES-256 encryption at rest, GDPR export/erasure, threat monitoring.

The vendored `osslsigncode/` directory is the upstream GPL-3.0 C project (built via cmake by `make deps`); the wrapper and API are MIT.

## Docs Worth Reading

`README.md` (overview + full CLI/API usage), `API_README.md` (complete REST API reference), `COMPLIANCE_DOCUMENTATION.md`, `CHANGELOG.md`. Any change touching keys, certs, auth, or crypto falls under `~/development/ads-fable-utils/SECURITY-RULES.md`.
