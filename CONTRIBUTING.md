# Contributing to DragonEye

Thanks for taking the time to improve DragonEye.

## Development setup

```bash
git clone https://github.com/SanchitKumaRR/DragonEye.git
cd DragonEye
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pip install -e .
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
```

External recon binaries (subfinder, dnsx, httpx, katana, nuclei) are optional.
The test suite uses fake, input-driven executables, so it runs on a clean
machine with no scanners installed.

## Ground rules

- **Scope correctness is the top priority.** Any change to rule parsing,
  matching or target filtering needs a test that proves the deny path.
- **Never add a shell invocation.** Tools are argv-only through
  `tools/runner.py`; adapters return argument lists.
- **New tools are adapters.** Subclass `ToolAdapter`, fill in `spec`, `build`
  and `parse`, then append an instance to `dragoneye/tools/adapters.py`.
  Filtering, timeouts, evidence capture and auditing are handled by the runner.
- **Keep the LLM boxed in.** The model may only return strict JSON and request a
  bounded local search. It must never gain command execution or network access.
- **Fail closed.** Ambiguous scope input should raise `ScopeError` before any
  traffic is sent, not be guessed at.

## Pull requests

1. One logical change per PR.
2. Add or update tests; the suite must stay green.
3. Run `ruff check .` (CI runs it on every supported Python).
4. Update `CHANGELOG.md` under "Unreleased" for user-visible changes.
5. Describe any change to the safety model explicitly — docs and code must
   agree.

## Reporting bugs

Use the issue tracker for normal bugs. For a vulnerability in DragonEye
itself, follow `SECURITY.md` instead of opening a public issue.
