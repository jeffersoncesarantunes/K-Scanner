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

