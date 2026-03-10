# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project scope

This repository contains a small Python command-line workflow:

1. `check_services.py` performs network/service checks from a CSV input.
2. `summarize_results.py` classifies scan output into liveness tiers.

## Expectations for changes

- Prefer small, targeted patches.
- Keep scripts dependency-free unless explicitly requested.
- Preserve CSV-compatible workflows and existing file names by default.
- When updating logic, also update `README.md` usage notes if behavior changes.

## Validation checklist

Before committing:

- Run `python3 -m py_compile check_services.py summarize_results.py` for syntax checks.
- If behavior is changed, run the two-step workflow locally when sample data is available:
  - `python3 check_services.py`
  - `python3 summarize_results.py`

## Documentation and style

- Keep README instructions command-focused and copy/paste friendly.
- Use clear section headings and short bullets.
- Add comments only where behavior is non-obvious.

## Pull request notes

Include:

- Summary of what changed.
- Any assumptions made.
- Commands run to validate the change.
