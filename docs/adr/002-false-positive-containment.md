# ADR 002: Tiered containment for suspicious file writes

**Status:** Proposed  
**Date:** 2026-09-09

## Problem

High write entropy and rapid renames occur in legitimate 7-Zip, VeraCrypt, ffmpeg, git-lfs, backup, encryption, and update workflows. Directly killing a process from an entropy heuristic can corrupt work, interrupt backups, and make the product unsafe to deploy.

## Options considered

1. Hard-kill on the first entropy threshold. This limits ongoing writes, but makes a single calibration error destructive to legitimate work and offers poor forensic recovery.
2. Alert only. This preserves availability but may allow ransomware to encrypt many more files while an operator responds.
3. Use an evidence- and policy-gated response ladder: alert, suspend-and-alert by default, and opt-in hard-kill only for high-confidence, corroborated cases.

## Recommendation

Adopt option 3. A lone entropy signal can produce an alert and, when the configurable threshold is met, a reversible **suspend-and-alert** action. Suspension records a durable action ID, process image/hash/signer, affected paths, evidence window, and expiry; an authorized operator can resume it. No automatic resume is performed without an explicit future policy decision, because resumed ransomware is unsafe.

Hard-kill is disabled by default. Enabling it requires an administrator policy change and a high-confidence verdict that combines independent signals such as sustained destructive writes, rename/write breadth, model score calibration, and absence of an allowlist match. The enforcement broker independently verifies the evidence count and policy; a detector cannot request a kill merely by naming a PID.

Known-good high-entropy applications use a local signed allowlist. The allowlist is a signed, versioned JSON document whose entries bind an image SHA-256 and, where available, Authenticode publisher/subject, product identity, scope, and expiration. Verification uses an organization release key pinned in the installed binary. Paths alone never authorize an entry. An expired, malformed, revoked, or unverified list grants no exemption. Allowlisting reduces automated containment only; it still emits telemetry and does not waive network or event-based controls.

The normative field, size, canonicalization, and matching rules are in `docs/schemas/allowlist-v1.md`. Version 1 intentionally cannot authorize `hard_kill`; an allowlist is a false-positive containment control, not permission for irreversible response.

### Interaction with model-degraded observer mode

When ADR 004 places the detector in degraded observer mode, the broker rejects every model-driven `SuspendAndAlert` and `HardKill` request regardless of allowlist state, score, or policy setting. It may accept a request only to persist an `Alert` audit record marked `model_degraded`; it must not reinterpret raw entropy features as a substitute model. An allowlist may still be parsed for health reporting, but it grants and revokes no action while the model is degraded. The first valid, compatible, signed model bundle restores eligibility for normal broker evaluation; it does not retroactively execute rejected actions.

## Trade-offs and failure modes

Suspension can still pause an important backup and cannot undo writes already made; hard-kill can lose in-memory work and destabilize a parent workflow. Attackers may masquerade as an allowlisted filename or abuse a signed binary, hence hash and signer binding plus expiry. A stolen allowlist signing key is a high-impact incident; key rotation and revocation must be supported by the manifest/update design. Conversely, overly broad allowlists become blind spots. If evidence is incomplete, identities disagree, or the policy cannot be verified, the system must alert and avoid irreversible action.
