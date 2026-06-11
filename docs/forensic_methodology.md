# Forensic Methodology

## RWX Detection Theory

The **W^X (Write XOR Execute)** security policy says memory pages should be writable or executable, but never both at the same time. K-Scanner looks for violations of that principle — regions where a page has both `W` and `X` permissions simultaneously.

## Indicators of Compromise (IoC)

- **Self-Modifying Code:** Malicious payloads often rewrite their own code in memory to dodge static signatures. That requires RWX pages.
- **Code Injection:** Reflective DLL/SO injection almost always creates RWX regions to run the payload.
- **JIT Vulnerabilities:** Just-In-Time engines (browsers, runtimes) legitimately use RWX, but that makes them high-value targets for exploitation. K-Scanner flags those areas so you can review them.

## Non-Intrusive Principles

K-Scanner follows the **"Order of Volatility"** and standard evidence preservation practices:

- **Passive Metadata Analysis:** It reads from `/proc/maps`, which gives you metadata about a process without stopping it or attaching anything.
- **Operational Safety:** No intrusive calls like `ptrace` or direct `pread` on hardware-mapped memory. That eliminates the risk of freezing the system or triggering a kernel panic — safe for production use.
- **Evidence Integrity:** Everything is read-only against system metadata, so the target environment stays as clean as possible.
