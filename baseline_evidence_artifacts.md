# Baseline Evidence Artifacts for Security Remediation (Phase 1)

## 1. Baseline Grep Evidence
- File: baseline_grep_evidence.txt
- Description: Output of findstr for security-sensitive patterns across the codebase.
- Command:
  ```powershell
  findstr /S /N /I /OFFLINE /C:"password" /C:"secret" /C:"token" /C:"subprocess" /C:"shell" /C:"os.system" /C:"open(" /C:"urlopen" /C:"requests" /C:"get" /C:"post" /C:"put" /C:"delete" /C:"pathlib" /C:"ipaddress" /C:"tool description" /C:"env" /C:"os.environ" * > baseline_grep_evidence.txt
  ```

## 2. Baseline Pytest Evidence
- File: baseline_pytest_evidence.txt
- Description: Output of pytest run to capture current test state.
- Command:
  ```powershell
  python -m pytest --maxfail=1 --disable-warnings > baseline_pytest_evidence.txt
  ```

## 3. Pytest Version Evidence
- File: baseline_pytest_version.txt
- Description: Output of `pip show pytest` to document pytest version.
- Command:
  ```powershell
  pip show pytest > baseline_pytest_version.txt
  ```

---

All evidence files are generated in the project root. Attach these artifacts to the security remediation plan for audit and closure verification.

## 4. Evidence Review Summary (2026-04-12)
- Baseline pytest captured 1 failure in `tests/functional_test.py` caused by `KeyError: 'name'` while printing schema results.
- Baseline grep artifact size is approximately 113 MB and contains broad pattern matches across source, docs, and generated files.
- Pre-remediation pattern counts sampled from baseline artifact:
  - `execSync(`: 1
  - `readonly123`: 9
  - `password123`: 13
  - `shell\s*=\s*True`: 25
- Post-remediation targeted source scan (`bin`, `scripts`, `tests`, excluding `__pycache__`) shows no remaining `readonly123` or `password123` literals.
