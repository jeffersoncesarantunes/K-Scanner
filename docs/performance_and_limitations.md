## ●  Performance and Limitations

## 1. Design Philosophy

K-Scanner prioritizes operational safety over aggressive inspection.

It performs read-only analysis of `/proc/[PID]/maps` without:

- Attaching debuggers
- Pausing processes
- Reading raw memory pages
- Using intrusive syscalls such as `ptrace`

This ensures minimal impact on production systems.

---

## 2. Performance Characteristics

The scanner's workload depends primarily on:

- Number of running processes
- Size of each memory map file
- Scan frequency (in live mode)

Since it inspects metadata only, the overhead is generally low.

In typical Linux environments:

- CPU impact is minimal
- Memory usage is negligible
- I/O overhead is limited to `/proc` reads

However, in systems with thousands of processes, scan frequency should be tuned appropriately.

---

## 3. Scalability Considerations

K-Scanner scales linearly with the number of processes.

Large multi-tenant servers may require:

- Scan interval adjustments
- Controlled scheduling
- Integration into monitoring pipelines

It is not optimized for distributed orchestration environments by default.

---

## 4. Known Limitations

K-Scanner does not:

- Monitor historical permission transitions
- Correlate memory regions with loaded binaries
- Capture full memory snapshots
- Analyze kernel-space memory
- Detect stealth techniques that maintain W^X compliance

It relies entirely on the integrity of `/proc` metadata.

---

## 5. Privilege Requirements

Access to `/proc/[PID]/maps` may require elevated privileges.

In restricted environments:

- Some processes may be inaccessible
- Partial visibility may occur

This behavior depends on system security configuration.

---

## 6. Operational Trade-Offs

The primary trade-off in K-Scanner is:

Visibility vs. Intrusiveness

By avoiding deep memory inspection, the tool maintains stability and safety — but sacrifices deep behavioral analysis.

This is a deliberate engineering decision.

---

## 7. Recommended Usage Model

K-Scanner is best used as:

- A lightweight diagnostic utility
- A pre-forensic triage scanner
- A complementary security tool

It should be part of a layered defense strategy rather than a standalone detection mechanism.
