# ADR 003: Separate detection from enforcement

**Status:** Proposed  
**Date:** 2026-09-09

## Problem

A single daemon owning telemetry subscriptions, model loading, WFP changes, and process control has near-total host influence. A parser, model, or IPC vulnerability in that daemon would inherit enforcement authority.

## Options considered

1. Keep one privileged daemon and harden it with ACLs, integrity-level restrictions, anti-tamper checks, and code signing. This reduces some attack paths but leaves a broad trusted computing base and does not contain a compromised parser.
2. Split a constrained detector from a small privileged enforcement broker with narrow IPC.
3. Move all collection and enforcement to a kernel driver. This offers deep access but creates the highest-risk code path, requires driver lifecycle work, and is outside this phase.

## Recommendation

Adopt option 2. The detector runs with the lowest practical service identity and only telemetry/model-read permissions. Where a Windows telemetry provider requires a privilege, grant that specific privilege rather than administrator membership. It cannot alter WFP state, suspend processes, or write protected policy.

The enforcement broker is a separately signed, high-privilege service. It accepts only versioned `verdict` messages on a local named pipe restricted to the detector service SID and broker SID. Connection identity is checked from the OS token; each request includes a protocol version, nonce, expiry, immutable evidence digest, requested action, and policy/model version. The broker validates message size/schema, replay window, sender, policy gates, and action scope before performing anything. It owns audit logging and a fail-safe cleanup path for its own transient rules.

## Trade-offs and failure modes

Two processes and IPC introduce latency, deployment complexity, version skew, and a new denial-of-service boundary. ACL errors or a confused-deputy broker could negate the split, so broker input validation and negative IPC tests are first-class requirements. A detector compromise may still create alerts or exhaust the broker, but cannot directly exercise host-control APIs. If IPC authentication, policy verification, or version compatibility fails, enforcement fails safe: no irreversible action, with a local health alert. This separation also makes future detector sandboxing and independent updates feasible.
