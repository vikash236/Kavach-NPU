# `kavach.toml` design schema

**Governing ADRs:** ADR 002, ADR 004, ADR 005, and ADR 006. This is an administrator-authored design contract; no runtime parser exists in this phase. Relative paths resolve beneath the protected Kavach configuration directory. Secrets and private signing keys are invalid in this file.

```toml
artifact_version = { major = 1, minor = 0 }

[containment]
hard_kill_enabled = false
minimum_corroborating_evidence = 3 # 1..=255; ignored unless hard_kill_enabled
suspend_action_ttl_seconds = 3600 # 60..=86400; audit-record retention, not auto-resume

[allowlist]
manifest_path = "policy/allowlist.json"
required_policy_generation = 7

[model]
bundle_directory = "models/active"
minimum_rollback_generation = 42
minimum_keyring_generation = 9
allow_last_known_good = true

[wsl]
correlation_window_ms = 250 # 10..=250; values above 250 are invalid in v1
maximum_clock_uncertainty_ms = 50 # 1..=50
clock_sync_interval_seconds = 30 # fixed at 30 in v1; included for explicit status
clock_sync_stale_after_seconds = 90 # fixed at 90 in v1
ambiguous_vm_containment_enabled = false
```

The configuration file is protected by administrator-only ACLs and loaded atomically. A syntax, bounds, ACL, or version failure selects compiled safe defaults: hard-kill disabled, no allowlist exemption, model rollback/keyring policy at the installed baseline, and WSL attribution alert-only. It never silently broadens enforcement.

`hard_kill_enabled` requires an explicit administrator change and remains subject to ADR 002 evidence gates and ADR 004 verified-model state. `allowlist.manifest_path` must point beneath the protected configuration directory; its signature rules are separate and governed by the allowlist schema. `allow_last_known_good` cannot override key revocation or the minimum rollback generation. `ambiguous_vm_containment_enabled` affects only the distribution-wide, reversible option in ADR 005 and never guest-PID action.
