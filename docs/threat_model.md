## ●   Threat Model

## 1.  Purpose

This document defines the threat boundaries, detection scope, and operational assumptions of K-Scanner.

K-Scanner is not a general-purpose malware detector.  
It is a focused runtime forensic utility designed to identify violations of the W^X (Write XOR Execute) memory protection principle in live Linux systems.

The objective of this document is clarity: what the tool detects, what it does not detect, and under which assumptions it operates.

---

## 2. Security Assumptions

K-Scanner operates under the following assumptions:

- The Linux kernel is trusted and uncompromised.
- `/proc` metadata is reliable and has not been tampered with.
- The operator has sufficient privileges to inspect process memory maps.
- The attacker operates in user space (not kernel-level).

If these assumptions are invalid, detection reliability cannot be guaranteed.

---

## 3. Detection Scope

K-Scanner analyzes `/proc/[PID]/maps` and identifies memory regions that are simultaneously:

- Writable (W)
- Executable (X)

Such regions violate the W^X principle and represent high-risk memory surfaces.

## 3.1 Behaviors Covered

K-Scanner is capable of detecting:

- Explicit RWX mappings (`rwxp`)
- Dynamically allocated executable-writable memory via `mmap`
- Suspicious permission configurations in running processes
- High-risk runtime memory regions in exposed services

---

## 4. Attack Scenarios Covered

## 4.1 Code Injection

Injected shellcode typically requires writable and executable memory.  
If such memory is allocated or modified, K-Scanner will flag it.

## 4.2 Self-Modifying Code

Malware that modifies its own instructions requires RWX memory regions.  
These mappings are detectable.

## 4.3 JIT-Related Risk Surfaces

JIT engines may legitimately allocate RWX pages.  
Although not inherently malicious, these regions are high-value exploitation targets and are intentionally surfaced for analyst review.

---

## 5. Non-Goals

K-Scanner does not detect:

- Kernel-level rootkits
- ROP-based attacks that do not require RWX memory
- File-based malware
- Memory corruption without permission changes
- Attacks that maintain W^X compliance
- Tampering that hides `/proc` visibility

This limitation is intentional. The tool focuses strictly on memory permission anomalies.

---

## 6. False Positives

Legitimate RWX memory usage may occur in:

- JIT runtimes
- Research environments
- Legacy systems

K-Scanner flags RWX as a condition for review, not as definitive malware.

Interpretation remains the responsibility of the analyst.

---

## 7. Evasion Considerations

Advanced attackers may attempt:

- Temporary permission changes (write → execute → revert)
- ROP-based execution
- W^X-compliant injection
- Kernel-level tampering

K-Scanner does not implement anti-evasion techniques at this stage.

---

## 8. Operational Positioning

K-Scanner is best suited for:

- Live system triage
- Incident response pre-analysis
- Runtime integrity inspection
- Hardening validation

It is not intended to replace EDR systems or full memory forensic frameworks.

---

## 9. Summary

K-Scanner solves a narrowly defined but meaningful problem:

Identifying RWX memory regions in live Linux processes using non-intrusive metadata inspection.

Its strength lies in:

- Simplicity
- Transparency
- Low operational risk
- Predictable behavior
