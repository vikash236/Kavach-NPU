# kavach-train

This crate is intentionally inert. It defines the boundary for the separately operated, access-controlled training pipeline in ADR 001; it neither reads telemetry nor trains a model. Raw datasets, credentials, and unredacted customer data must never be committed here.

The pipeline accepts only dataset manifests conforming to [dataset-manifest-v1.toml](schemas/dataset-manifest-v1.toml) and produces an evaluation report conforming to [evaluation-report-v1.md](schemas/evaluation-report-v1.md). A release process later binds the report hash into the signed model manifest specified by ADR 004.
