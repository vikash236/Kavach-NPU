# ADR 006: Global artifact versioning and compatibility

**Status:** Proposed  
**Date:** 2026-09-09

## Problem

The model bundle, evaluation report, allowlist, detector-to-broker verdict, and WSL guest record all cross a trust or process boundary. Independent ad-hoc version fields would make compatibility ambiguous and permit unsafe fallback during partial upgrades.

## Options considered

1. Let each artifact choose its own string version convention. This is easy initially but makes shared tooling and compatibility audits unreliable.
2. Use one global integer for every artifact. This is simple but forces unrelated protocol changes to advance in lockstep.
3. Use a common major/minor envelope with artifact-specific compatibility policy and independent release versions.

## Recommendation

Adopt option 3. Every machine-consumed artifact starts with `artifact_version: { major: u16, minor: u16 }` (or its fixed-wire equivalent). `major` changes only for breaking semantic or binary changes; an implementation must reject an unsupported major. `minor` adds optional, default-safe fields only; an older compatible implementation must reject a message if an added field is marked required-for-safety or has nonzero reserved bits it does not understand.

All integer wire fields are unsigned, bounded, and big-endian where binary. JSON schemas use UTF-8 RFC 8785 canonical bytes before hashing/signing. TOML templates are human-authored inputs and must be converted to their canonical JSON release representation before signing. Unknown fields are rejected for signed policy/model artifacts and binary protocols until a compatible minor-version handler explicitly recognizes them. Artifact identity is always the SHA-256 of canonical bytes plus `artifact_version`, never a filename.

Artifact version is separate from a model `bundle_version` (SemVer), policy generation (`u64` monotonic), rollback generation (`u64` monotonic), and keyring generation (`u64` monotonic). Those values answer different questions and must not be substituted for protocol compatibility.

## Trade-offs and failure modes

Strict rejection can cause temporary degraded operation during staggered upgrades, but silent interpretation is worse at security boundaries. The broker must reject incompatible verdicts; the model loader enters degraded observer mode; and the WSL bridge retains only aggregate telemetry. Version parsing bugs, inconsistent canonicalization, and incorrectly labeling a safety-relevant field optional are residual risks addressed by schema test vectors before implementation.
