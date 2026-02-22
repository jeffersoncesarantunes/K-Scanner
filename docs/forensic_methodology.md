## ● Forensic Methodology

## ● RWX Detection Theory
In modern computing, the **W^X (Write XOR Execute)** security policy ensures that memory pages are either writable or executable, but never both. K-Scanner is designed to detect violations of this principle.

##  Indicators of Compromise (IoC)
- **Self-Modifying Code**: Malicious payloads often modify their own code in memory to bypass static signatures.
- **Code Injection**: Techniques like *Reflective DLL/SO Injection* typically create RWX regions to execute their payload.
- **JIT Vulnerabilities**: While Just-In-Time engines (like those in browsers) use RWX, they are frequent targets for exploitation. K-Scanner monitors these high-risk areas.

##  Non-Intrusive Principles
K-Scanner adheres to the **"Order of Volatility"** and evidence preservation standards:
- **Passive Metadata Analysis**: The tool reads from `/proc/maps`, which provides metadata about the process without pausing it or attaching a debugger.
- **Operational Safety**: By avoiding intrusive calls like `ptrace` or direct `pread` on hardware-mapped memory, K-Scanner eliminates the risk of system freezes or "Kernel Panics," making it safe for production environments.
- **Evidence Integrity**: The tool performs read-only operations on system metadata to ensure the target environment remains as pristine as possible.
