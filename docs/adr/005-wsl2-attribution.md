# ADR 005: Correlate WSL2 guest writes with host-side events

**Status:** Proposed  
**Date:** 2026-09-09

## Problem

Windows may attribute WSL2-backed `/mnt/c/` activity to `vmmemWSL.exe`, not the guest process that initiated it. Treating the VM process as the attacker prevents useful remediation and risks disrupting unrelated guest work.

## Options considered

1. Attribute all WSL2 writes to `vmmemWSL.exe`. This is simple and useful for aggregate detection, but cannot identify a guest PID and over-broad containment impacts the whole distribution.
2. Rely on guest audit/eBPF events alone. This has guest process detail but no authoritative host-side observation and is blind if the guest agent is unavailable or tampered with.
3. Correlate guest audit/eBPF records sent over AF_VSOCK with host ETW file events, using time synchronization and normalized file identity/path evidence.

## Recommendation

Adopt option 3, while retaining option 1 as an explicitly low-confidence fallback. A per-distribution `kavach-wsl` guest agent records file-write intent/completion using auditd where available and a narrowly scoped eBPF trace source when supported. It emits a versioned AF_VSOCK record containing guest PID/start time, executable/cgroup identity, distro ID, mount namespace, normalized `/mnt/<drive>/` path, operation, byte range when available, monotonic and realtime timestamps, and a per-record sequence number.

The host bridge authenticates the expected distro/guest-agent identity, records receive time, periodically estimates clock offset and jitter by challenge/response, translates the guest path to a Windows canonical path/file identity, and joins it with ETW Kernel-File events observed for WSL backing activity. The correlation key is canonical file identity/path plus operation and a bounded, offset-adjusted time window. The initial design targets a 250 ms maximum correlation window, tightened when measured clock uncertainty permits; it does not assert causality merely because two writes occur near each other.

`docs/schemas/wsl-vsock-record-v1.md` defines the bounded, length-framed AF_VSOCK record; `kavach-wsl::GuestWriteRecord` is its inert typed contract. The bridge rejects malformed or unenrolled records before they enter the correlator.

### Clock-offset estimation protocol

At guest-agent enrollment and every 30 seconds thereafter, the host sends a random 128-bit challenge with host monotonic send time `t0`. The guest immediately records guest monotonic receive/send times `g1`/`g2`, echoes the challenge, and the host records receipt time `t3`. The host discards responses with a mismatched challenge, non-monotonic timestamps, or round-trip time above 100 ms. From the lowest-round-trip sample among the most recent five accepted exchanges it derives host-minus-guest offset and a conservative uncertainty bound of half round-trip time plus observed sample spread. A fresh estimate is valid for 90 seconds.

Every in-flight correlation snapshots the newest accepted estimate at record arrival. If the estimate expires before the join completes, if uncertainty exceeds 50 ms, or if three consecutive exchanges fail, the record is downgraded to low confidence and is never later upgraded from a newly measured offset. The bridge continues trying at 30-second cadence; after 90 seconds without an accepted estimate it emits `clock_sync_stale`, treats all PID attribution as ambiguous, and permits only the host-level, reversible policy described below. When synchronization recovers, only newly received records can qualify for medium or high confidence.

Confidence is explicit: **high** requires a unique matching host event, matching file identity/path and operation, a fresh time-offset estimate, and one guest PID/start-time record; **medium** permits a unique normalized path/time match without file identity; **low** is aggregate `vmmemWSL.exe` activity or any multi-match/agent-health failure. High confidence may feed a future guest-targeted response after policy review. Medium and low confidence produce alerts and host-level aggregate evidence only; they must not identify or terminate a guest process. Ambiguous mass writes can, under a separately enabled containment policy, isolate the WSL virtual switch or pause VM-level activity, clearly labeled as distribution-wide and reversible where supported.

## Trade-offs and failure modes

This adds a guest component, clock drift, VSock availability, path translation, and performance overhead. Rapid concurrent writes to the same file, rename races, buffering, dropped audit events, disabled eBPF, and a compromised guest can all make attribution uncertain. Correlation is probabilistic, not forensic proof. Sequence gaps, stale time sync, identity disagreement, or more than one candidate downgrade confidence; the system retains raw correlation inputs and avoids PID-specific enforcement. Host-only detection remains available, but it must present `vmmemWSL.exe` as an opaque source rather than inventing a guest culprit.
