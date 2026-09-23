//! kavach-pack: Model bundle packaging, signing, and verification CLI for Kavach-NPU.
//!
//! Conforms to ADR 004, ADR 006, and docs/schemas/model-manifest-v1.md.

mod onnx_builder;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use kavach_core::manifest::{ModelManifest, encode_base64, verify_bundle_dir};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn print_usage() {
    eprintln!(
        r#"kavach-pack - Model Bundle Packaging & Signing Utility

USAGE:
    kavach-pack <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    keygen      Generate Ed25519 keypair for model manifest signing
                Options:
                    --output <DIR>     Output directory for keys (default: keys/)
                    --seed <STRING>    Optional deterministic seed string

    stub-onnx   Generate reference INT8 multi-task stub ONNX file
                Options:
                    --output <FILE>    Output path (default: models/active/kavach_multitask_int8.onnx)
                    --opset <NUM>      ONNX opset version (default: 21)

    sign        Sign manifest.json with Ed25519 key and emit manifest.sig
                Options:
                    --key <FILE>       Path to Ed25519 signing key (raw 32-byte or hex)
                    --manifest <FILE>  Path to manifest.json
                    --output <FILE>    Output path for manifest.sig (default: beside manifest)

    verify      Verify complete bundle directory against Ed25519 public key
                Options:
                    --bundle <DIR>     Directory containing manifest.json, manifest.sig, onnx
                    --pubkey <FILE>    Optional public key file (default: built-in pinned dev key)
                    --rollback <GEN>   Minimum acceptable rollback generation (default: 1)

    init-dev    Convenience command: generate keys, stub ONNX, manifest.json, and manifest.sig
                Options:
                    --bundle-dir <DIR> Target bundle directory (default: models/active)
                    --keys-dir <DIR>   Target keys directory (default: keys)

    help        Display this help message
"#
    );
}

fn parse_arg(args: &[String], flag: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    None
}

fn cmd_keygen(args: &[String]) -> Result<(), String> {
    let out_dir = parse_arg(args, "--output").unwrap_or_else(|| "keys".to_string());
    let seed_str = parse_arg(args, "--seed");

    let signing_key = if let Some(seed) = seed_str {
        let mut seed_bytes = [0u8; 32];
        let bytes = seed.as_bytes();
        let copy_len = bytes.len().min(32);
        seed_bytes[..copy_len].copy_from_slice(&bytes[..copy_len]);
        SigningKey::from_bytes(&seed_bytes)
    } else {
        kavach_core::keys::dev_signing_key()
    };

    let verifying_key = signing_key.verifying_key();
    let pub_bytes = verifying_key.to_bytes();
    let priv_bytes = signing_key.to_bytes();

    fs::create_dir_all(&out_dir).map_err(|e| format!("failed to create dir {out_dir}: {e}"))?;

    let priv_path = Path::new(&out_dir).join("sign.key");
    let priv_hex_path = Path::new(&out_dir).join("sign.key.hex");
    let pub_path = Path::new(&out_dir).join("pub.key");
    let pub_hex_path = Path::new(&out_dir).join("pub.key.hex");

    fs::write(&priv_path, priv_bytes).map_err(|e| format!("write {}: {e}", priv_path.display()))?;
    fs::write(&priv_hex_path, hex::encode(priv_bytes))
        .map_err(|e| format!("write {}: {e}", priv_hex_path.display()))?;
    fs::write(&pub_path, pub_bytes).map_err(|e| format!("write {}: {e}", pub_path.display()))?;
    fs::write(&pub_hex_path, hex::encode(pub_bytes))
        .map_err(|e| format!("write {}: {e}", pub_hex_path.display()))?;

    println!("Generated Ed25519 keypair successfully:");
    println!("  Private key: {}", priv_path.display());
    println!("  Public key:  {}", pub_path.display());
    println!("  Public Key Hex: {}", hex::encode(pub_bytes));
    println!("  Public Key Array: {:?}", pub_bytes);
    Ok(())
}

fn cmd_stub_onnx(args: &[String]) -> Result<(), String> {
    let out_file = parse_arg(args, "--output")
        .unwrap_or_else(|| "models/active/kavach_multitask_int8.onnx".to_string());
    let opset: i64 = parse_arg(args, "--opset")
        .and_then(|s| s.parse().ok())
        .unwrap_or(21);

    let onnx_bytes = onnx_builder::generate_kavach_stub_onnx(opset);
    let digest = Sha256::digest(&onnx_bytes);
    let sha256_hex = hex::encode(digest);

    if let Some(parent) = Path::new(&out_file).parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create parent dir for {out_file}: {e}"))?;
    }

    fs::write(&out_file, &onnx_bytes).map_err(|e| format!("write {out_file}: {e}"))?;

    println!("Generated reference stub ONNX file:");
    println!("  Path:   {}", out_file);
    println!("  Size:   {} bytes", onnx_bytes.len());
    println!("  Opset:  {}", opset);
    println!("  SHA256: {}", sha256_hex);
    Ok(())
}

fn load_signing_key(path_str: &str) -> Result<SigningKey, String> {
    let data = fs::read(path_str).map_err(|e| format!("failed to read key file {path_str}: {e}"))?;
    if data.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data);
        return Ok(SigningKey::from_bytes(&arr));
    }
    // Check if it's hex string
    if let Ok(text) = std::str::from_utf8(&data) {
        let clean = text.trim();
        if clean.len() == 64 {
            let bytes = hex::decode(clean).map_err(|e| format!("hex decode key: {e}"))?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Ok(SigningKey::from_bytes(&arr));
        }
    }
    Err(format!(
        "key file {path_str} must be 32 raw bytes or 64 hex characters (found {} bytes)",
        data.len()
    ))
}

fn load_verifying_key(path_str: Option<&str>) -> Result<VerifyingKey, String> {
    if let Some(p) = path_str {
        let data = fs::read(p).map_err(|e| format!("read pubkey {p}: {e}"))?;
        if data.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&data);
            return VerifyingKey::from_bytes(&arr)
                .map_err(|e| format!("invalid ed25519 verifying key: {e}"));
        }
        if let Ok(text) = std::str::from_utf8(&data) {
            let clean = text.trim();
            if clean.len() == 64 {
                let bytes = hex::decode(clean).map_err(|e| format!("hex decode pubkey: {e}"))?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return VerifyingKey::from_bytes(&arr)
                    .map_err(|e| format!("invalid ed25519 verifying key: {e}"));
            }
        }
        Err(format!(
            "pubkey {p} must be 32 raw bytes or 64 hex characters (found {} bytes)",
            data.len()
        ))
    } else {
        // Built-in dev verifying key
        Ok(kavach_core::keys::dev_verifying_key())
    }
}

fn cmd_sign(args: &[String]) -> Result<(), String> {
    let key_file = parse_arg(args, "--key").ok_or_else(|| "missing required --key flag".to_string())?;
    let manifest_file =
        parse_arg(args, "--manifest").ok_or_else(|| "missing required --manifest flag".to_string())?;
    let output_file = parse_arg(args, "--output").unwrap_or_else(|| {
        let p = Path::new(&manifest_file);
        let parent = p.parent().unwrap_or_else(|| Path::new("."));
        parent.join("manifest.sig").to_string_lossy().to_string()
    });

    let signing_key = load_signing_key(&key_file)?;
    let manifest_bytes = fs::read(&manifest_file)
        .map_err(|e| format!("read manifest {manifest_file}: {e}"))?;

    // Validate that manifest is parseable ModelManifest before signing
    let parsed: ModelManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("manifest validation failed: {e}"))?;

    let digest = Sha256::digest(&manifest_bytes);
    let signature = signing_key.sign(&digest);
    let sig_b64 = encode_base64(&signature.to_bytes());

    fs::write(&output_file, &sig_b64).map_err(|e| format!("write {output_file}: {e}"))?;

    println!("Manifest signed successfully:");
    println!("  Manifest:   {}", manifest_file);
    println!("  Bundle Ver: {}", parsed.bundle_version);
    println!("  Key ID:     {}", parsed.key_id);
    println!("  Sig File:   {}", output_file);
    println!("  Sig B64:    {}", sig_b64);
    Ok(())
}

fn cmd_verify(args: &[String]) -> Result<(), String> {
    let bundle_dir_str =
        parse_arg(args, "--bundle").unwrap_or_else(|| "models/active".to_string());
    let pubkey_file = parse_arg(args, "--pubkey");
    let min_rollback: u64 = parse_arg(args, "--rollback")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    let bundle_dir = Path::new(&bundle_dir_str);
    let verifying_key = load_verifying_key(pubkey_file.as_deref())?;

    println!("Verifying bundle in {}...", bundle_dir.display());
    match verify_bundle_dir(bundle_dir, &verifying_key, min_rollback) {
        Ok(manifest) => {
            println!("\n[OK] Model bundle verified successfully!");
            println!("  Artifact Version: {}.{}", manifest.artifact_version.major, manifest.artifact_version.minor);
            println!("  Bundle Version:   {}", manifest.bundle_version);
            println!("  Rollback Gen:     {}", manifest.rollback_generation);
            println!("  Key ID:           {}", manifest.key_id);
            println!("  ONNX File:        {}", manifest.onnx.file);
            println!("  ONNX SHA-256:     {}", manifest.onnx.sha256);
            println!("  ONNX Opset:       {}", manifest.onnx.opset);
            println!("  Tensors:          {} tensors", manifest.tensors.len());
            for t in &manifest.tensors {
                println!("    - {} ({}, {}, shape: {:?})", t.name, t.direction, t.dtype, t.shape);
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("\n[FAILED] Model bundle verification failed: {e}");
            Err(e.to_string())
        }
    }
}

pub fn create_dev_bundle(bundle_dir: &Path, keys_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(bundle_dir)
        .map_err(|e| format!("failed to create dir {}: {e}", bundle_dir.display()))?;
    fs::create_dir_all(keys_dir)
        .map_err(|e| format!("failed to create dir {}: {e}", keys_dir.display()))?;

    // 1. Generate dev keys
    let signing_key = kavach_core::keys::dev_signing_key();
    let verifying_key = signing_key.verifying_key();
    let priv_bytes = signing_key.to_bytes();
    let pub_bytes = verifying_key.to_bytes();

    fs::write(keys_dir.join("dev_root.key"), priv_bytes)
        .map_err(|e| format!("write dev_root.key: {e}"))?;
    fs::write(keys_dir.join("dev_root.pub"), pub_bytes)
        .map_err(|e| format!("write dev_root.pub: {e}"))?;
    fs::write(keys_dir.join("dev_root.pub.hex"), hex::encode(pub_bytes))
        .map_err(|e| format!("write dev_root.pub.hex: {e}"))?;

    // 2. Generate stub ONNX
    let onnx_bytes = onnx_builder::generate_kavach_stub_onnx(21);
    let onnx_file = bundle_dir.join("kavach_multitask_int8.onnx");
    fs::write(&onnx_file, &onnx_bytes).map_err(|e| format!("write {}: {e}", onnx_file.display()))?;

    let onnx_sha256 = hex::encode(Sha256::digest(&onnx_bytes));

    // 3. Generate canonical manifest.json
    let manifest_content = format!(
        r#"{{
  "artifact_version": {{
    "major": 1,
    "minor": 0
  }},
  "bundle_version": "0.1.0-dev",
  "rollback_generation": 1,
  "created_at": "2026-09-23T00:00:00Z",
  "key_id": "model-2026-a",
  "onnx": {{
    "file": "kavach_multitask_int8.onnx",
    "sha256": "{onnx_sha256}",
    "opset": 21,
    "quantization": "int8_qdq"
  }},
  "tensors": [
    {{
      "name": "io_input",
      "direction": "input",
      "dtype": "int8",
      "shape": [1, 10, 4]
    }},
    {{
      "name": "io_score",
      "direction": "output",
      "dtype": "float32",
      "shape": [1, 1]
    }},
    {{
      "name": "net_input",
      "direction": "input",
      "dtype": "int8",
      "shape": [1, 32, 4]
    }},
    {{
      "name": "net_score",
      "direction": "output",
      "dtype": "float32",
      "shape": [1, 1]
    }},
    {{
      "name": "audit_input",
      "direction": "input",
      "dtype": "int8",
      "shape": [1, 16, 4]
    }},
    {{
      "name": "audit_score",
      "direction": "output",
      "dtype": "float32",
      "shape": [1, 1]
    }}
  ],
  "compatibility": {{
    "detector": {{
      "min_inclusive": "0.1.0",
      "max_exclusive": "0.2.0"
    }},
    "onnx_runtime": {{
      "min_inclusive": "1.20.0",
      "max_exclusive": "1.22.0"
    }}
  }},
  "evaluation_report_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "sbom_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}}"#
    );

    let manifest_file = bundle_dir.join("manifest.json");
    fs::write(&manifest_file, manifest_content.as_bytes())
        .map_err(|e| format!("write {}: {e}", manifest_file.display()))?;

    // 4. Sign manifest
    let manifest_digest = Sha256::digest(manifest_content.as_bytes());
    let sig = signing_key.sign(&manifest_digest);
    let sig_b64 = encode_base64(&sig.to_bytes());

    let sig_file = bundle_dir.join("manifest.sig");
    fs::write(&sig_file, &sig_b64).map_err(|e| format!("write {}: {e}", sig_file.display()))?;

    // 5. Verify bundle
    verify_bundle_dir(bundle_dir, &verifying_key, 1)
        .map_err(|e| format!("self-verification of generated bundle failed: {e}"))?;

    println!("Reference signed model bundle initialized successfully at {}:", bundle_dir.display());
    println!("  ONNX File:     {}", onnx_file.display());
    println!("  ONNX SHA-256:  {}", onnx_sha256);
    println!("  Manifest:      {}", manifest_file.display());
    println!("  Signature:     {}", sig_file.display());
    println!("  Keys:          {}", keys_dir.display());
    Ok(())
}

fn cmd_init_dev(args: &[String]) -> Result<(), String> {
    let bundle_dir = PathBuf::from(
        parse_arg(args, "--bundle-dir").unwrap_or_else(|| "models/active".to_string()),
    );
    let keys_dir =
        PathBuf::from(parse_arg(args, "--keys-dir").unwrap_or_else(|| "keys".to_string()));
    create_dev_bundle(&bundle_dir, &keys_dir)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    let result = match args[1].as_str() {
        "keygen" => cmd_keygen(&args[2..]),
        "stub-onnx" => cmd_stub_onnx(&args[2..]),
        "sign" => cmd_sign(&args[2..]),
        "verify" => cmd_verify(&args[2..]),
        "init-dev" => cmd_init_dev(&args[2..]),
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        other => {
            eprintln!("Unknown subcommand: {}\n", other);
            print_usage();
            Err(format!("unknown subcommand: {other}"))
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
