# Performance and Limitations

## 1. Design Philosophy

K-Scanner prioritizes operational safety over aggressive inspection. It's a read-only tool at heart.

It analyzes `/proc/[PID]/maps` without:

- Attaching debuggers
- Pausing processes
- Reading raw memory pages
- Using intrusive syscalls like `ptrace`

That means you can run it in production without worrying about collateral damage.

---

## 2. Performance Characteristics

How much overhead does it actually add? It depends on a few things:

- How many processes are running
- How large each memory map file is
- How often you scan (in live mode)

Since it only inspects metadata, the overhead is generally pretty low. In typical Linux environments:

- CPU impact is minimal
- Memory usage is negligible
- I/O is limited to reading `/proc`

That said, if you're on a machine with thousands of processes, you'll want to tune the scan frequency.

---

## 3. Scalability Considerations

K-Scanner scales roughly linearly with the number of processes. On large multi-tenant servers you might need to:

- Adjust scan intervals
- Schedule scans during off-peak windows
- Feed the output into a monitoring pipeline

Out of the box, it's not optimized for distributed orchestration at scale.

---

## 4. Known Limitations

Here's what K-Scanner does not do:

- Track historical permission transitions
- Correlate memory regions with the binaries that loaded them
- Capture full memory snapshots
- Analyze kernel-space memory
- Detect stealth techniques that stay W^X-compliant

It relies entirely on the integrity of `/proc` metadata. If that's been tampered with, the results are only as good as the data coming in.

---

## 5. Privilege Requirements

Reading `/proc/[PID]/maps` often requires elevated privileges. In restricted environments:

- Some processes may be invisible to you
- You'll get partial visibility at best

How much you can see depends on the system's security configuration.

---

## 6. Operational Trade-Offs

The core trade-off in K-Scanner is pretty straightforward:

Visibility vs. Intrusiveness

By avoiding deep memory inspection, the tool stays stable and safe — but you trade that for less deep behavioral analysis. That's a deliberate choice, not an oversight.

---

## 7. Recommended Usage Model

K-Scanner works best as:

- A lightweight diagnostic utility for quick checks
- A pre-forensic triage scanner before you go deeper
- A complementary tool alongside other security measures

Think of it as one layer in a defense-in-depth strategy, not a standalone silver bullet.
