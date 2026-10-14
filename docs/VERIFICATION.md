# Public snapshot verification

Verification date: **October 13, 2026**. Scope: this sanitized portfolio edition, not the private operational system or a production certification.

## Executed checks

- Built/installed the package with its demo/test extras into a separate initially empty Python **3.11.16** environment. Other project packages and production configuration were not present.
- Ran the full exported `unittest` suite with warnings treated as errors: **50 tests passed**.
- Ran `scripts/smoke_demo.py`: **36 checks passed** using the actual application in-process and synthetic local fixtures.
- Ran a known-vulnerability audit of the installed third-party package versions: **no known vulnerabilities reported at audit time**. This is a point-in-time advisory-database check, not proof that dependencies have no flaws.
- Ran Gitleaks 8.30.1 and a separate disclosure-oriented source review. No secrets were detected; deliberate malformed/private-IP rejection fixtures were manually distinguished from real infrastructure. Source-tree checks do not guarantee absence of every possible disclosure.

## Reproduce

After installing the extras described in the README:

```sh
PYTHONDONTWRITEBYTECODE=1 python -B -W error -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python -B scripts/smoke_demo.py
```

## Exercised dependency versions

- `fastapi==0.143.0`
- `starlette==1.8.0`
- `pydantic==2.14.1`
- `uvicorn==0.54.0`
- `httpx2==2.12.0`
- `httpcore2==2.12.0`

Direct versions are pinned in `pyproject.toml`; a complete hash-locked cross-platform environment is not supplied. Keep dependency monitoring enabled and repeat the checks after upgrades. The initial preparation environment exposed dependency/schema drift; the public snapshot upgrades the HTTP client libraries and aligns generated contracts with the exercised schema generator.

## What these results do not establish

All nine HTTP tools and local manifest export were exercised. The walkthrough reported zero network attempts and no SMS/email delivery. Adapter success/error tests use labeled mocks. Hosted speech, carrier calls, real messages, provider import and live TLS were not tested.

This is not a hosted production test, uptime/SLA claim, independent penetration-test certificate, browser accessibility assessment or GitHub Actions result. No real customer records, credentials, recordings or private deployment configuration are necessary to reproduce the local checks.

Project attribution and implementation scope are documented in the README, [PORTFOLIO.md](PORTFOLIO.md) and [PROVENANCE.md](PROVENANCE.md).
