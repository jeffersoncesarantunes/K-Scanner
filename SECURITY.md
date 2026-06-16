# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅       |

## Reporting a Vulnerability

This is a forensic security tool designed for authorized use only. If you discover a security vulnerability, please do NOT open a public issue.

Contact the maintainer directly at jefferson.antunes@gmail.com with details about the issue.

We commit to acknowledging receipt within 48 hours and providing a fix timeline within 7 days.

## Known Limitations

- **TOCTOU in /proc analysis**: The tool reads live kernel memory interfaces (/proc/PID/mem, /proc/PID/maps). Between opening and reading these files, the target PID could be recycled by the kernel. This is an inherent limitation of live forensic analysis and cannot be fully mitigated without kernel snapshots.
- **TOCTOU in YARA scanning**: The YARA rule file path is validated with access() before use in execvp(). A local attacker with write access to the path could theoretically swap the file between check and execution. This window is minimized by re-validation at the point of use.
- **History rewriting**: This repository's git history was cleaned with git-filter-repo to remove accidentally committed sensitive data. If you have an older clone, please re-clone from the latest remote.
