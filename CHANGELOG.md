# Changelog

All notable changes to K-Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CHANGELOG, CONTRIBUTING, CODE_OF_CONDUCT and issue/PR templates
- Portable unit tests for RWX parsing, JIT detection and confidence scoring
- Code coverage report (gcov/lcov) in CI

### Changed
- Hardened compiler flags (`-Wpedantic`, `-fstack-protector-strong`,
  `-D_FORTIFY_SOURCE=2`, `-fPIE`, `-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack`)

## [1.0.0] - 2024-01-01

### Added
- Initial public release
- Modular C99 engine
- Interactive ncurses-based Brutalist TUI
- Real-time RWX memory detection via `/proc/[PID]/maps`
- Automated memory dump with SHA256 integrity hashing
- Strings, hex preview, x86-64 disassembly and shellcode detection
- Confidence-based alert levels (LOW / MEDIUM / CRITICAL)
- JIT engine auto-detection (V8, SpiderMonkey, LuaJIT, Mono, .NET, JVM, Dart)
- `--silent-jit` to suppress JIT false positives
- `--watch` headless continuous monitoring (JSON-Lines output)
- JSON / CSV export
- Live regex memory hunting (`--live <PID> <pattern>`)
- eBPF real-time RWX telemetry (`--bpf`, `mmap`, `mprotect`, `shmat`, `execve`)
- YARA rule-based detection (`--yara <rule.yara>`)
- Container-aware detection (Docker, Kubernetes, LXC via cgroup)
- PKGBUILD for AUR
- Man page (`man/kscanner.1`)
- SECURITY.md disclosure policy
- GitHub Actions workflows: CI, CodeQL, Gitleaks

[Unreleased]: https://github.com/jeffersoncesarantunes/K-Scanner/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/jeffersoncesarantunes/K-Scanner/releases/tag/v1.0.0
