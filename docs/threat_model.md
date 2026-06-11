# Threat Model

## 1. Purpose

This document lays out the threat boundaries, detection scope, and operational assumptions behind K-Scanner.

Let's be clear: K-Scanner is not a general-purpose malware detector. It's a focused runtime forensic utility that identifies violations of the W^X (Write XOR Execute) memory protection principle on live Linux systems.

The point here is clarity — what this tool detects, what it doesn't, and what assumptions it makes.

---

## 2. Security Assumptions

K-Scanner assumes the following:

- The Linux kernel is trusted and hasn't been compromised.
- `/proc` metadata is reliable and hasn't been tampered with.
- The operator has the privileges needed to inspect process memory maps.
- The attacker operates in user space, not at the kernel level.

If any of those assumptions don't hold, detection reliability goes out the window.

---

## 3. Detection Scope

K-Scanner reads `/proc/[PID]/maps` and flags memory regions that are simultaneously:

- Writable (W)
- Executable (X)

Those regions violate the W^X principle and represent high-risk memory surfaces.

### 3.1 Behaviors Covered

K-Scanner can detect:

- Explicit RWX mappings (`rwxp`)
- Dynamically allocated executable-writable memory via `mmap`
- Suspicious permission configurations in running processes
- High-risk runtime memory regions in exposed services

---

## 4. Attack Scenarios Covered

### 4.1 Code Injection

Injected shellcode usually needs writable and executable memory. If that combination shows up, K-Scanner will flag it.

### 4.2 Self-Modifying Code

Malware that rewrites its own instructions needs RWX memory regions. Those mappings are detectable.

### 4.3 JIT-Related Risk Surfaces

JIT engines legitimately allocate RWX pages. That's not inherently malicious, but those regions are prime exploitation targets, so they're surfaced intentionally for analyst review.

---

## 5. Non-Goals

K-Scanner does not detect:

- Kernel-level rootkits
- ROP-based attacks that never need RWX memory
- File-based malware
- Memory corruption that doesn't change permissions
- Attacks that stay W^X-compliant
- Tampering that hides entries from `/proc`

This is by design. The tool focuses narrowly on memory permission anomalies and nothing else.

---

## 6. False Positives

Legitimate RWX memory can show up in:

- JIT runtimes
- Research environments
- Legacy systems

K-Scanner flags RWX as a condition worth reviewing — not as definitive malware. Interpreting the results is still up to you.

---

## 7. Evasion Considerations

Sophisticated attackers might try:

- Temporary permission changes (write -> execute -> revert)
- ROP-based execution
- W^X-compliant injection
- Kernel-level tampering

K-Scanner doesn't implement anti-evasion techniques at this stage. That's future work.

---

## 8. Operational Positioning

K-Scanner fits best in:

- Live system triage
- Incident response pre-analysis
- Runtime integrity inspection
- Hardening validation

It's not meant to replace EDR systems or full memory forensic frameworks. Use it where it fits, and pair it with other tools for the rest.

---

## 9. Summary

K-Scanner solves a narrow but real problem: identifying RWX memory regions in live Linux processes using non-intrusive metadata inspection.

Its strengths are:

- Simplicity
- Transparency
- Low operational risk
- Predictable behavior
