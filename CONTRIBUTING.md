# Contributing to K-Scanner

Thank you for considering a contribution to K-Scanner! This is a Linux-focused
memory auditing tool for RWX (W^X) detection and forensic triage.

## How to contribute

1. **Fork the repository** on GitHub or Codeberg.
2. **Create a feature branch** from `main`: `git checkout -b feature/your-feature`
3. **Install dev dependencies**: see `scripts/setup_dev_env.sh`.
4. **Make your changes** following the code style (see `.clang-format`).
5. **Run the test suite**: `make test` (requires root for live `/proc` memory
   access; portable unit tests run without root).
6. **Commit with a conventional message** (see Commit Style below).
7. **Open a pull request** against `main`. Link any related issue.

## Code style

- C99, follow `.clang-format` (run `clang-format -i src/**/*.c include/*.h`).
- Compiler warnings must be clean: `-Wall -Wextra -Wpedantic -std=c99`.
- Shell scripts must pass `shellcheck`.
- Document new flags and behavior in `README.md`.

## Commit style

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add eBPF mmap/mprotect telemetry
fix: correct RWX classification for anonymous pages
docs: document forensic triage workflow
test: add portable JIT detection unit tests
ci: add gcov coverage report
```

Types: `feat`, `fix`, `docs`, `test`, `ci`, `chore`, `refactor`, `security`.

## Privilege model

K-Scanner requires root privileges to inspect `/proc/[PID]/maps` of other
processes. Tests that need root are marked as such and run conditionally in CI.

## Reporting security vulnerabilities

Please do **not** open public issues for security vulnerabilities. Instead, see
`SECURITY.md` for our disclosure policy and contact information.

## License

By contributing, you agree that your contributions will be licensed under the
MIT License (see `LICENSE`).
