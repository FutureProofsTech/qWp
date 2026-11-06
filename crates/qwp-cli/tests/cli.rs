//! End-to-end CLI tests.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use qwp_hash::hash32;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_qwp")
}

fn workspace() -> PathBuf {
    let unique = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("qwp-cli-test-{}-{unique}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn run(arguments: &[&str]) -> std::process::Output {
    Command::new(binary()).args(arguments).output().unwrap()
}

#[test]
fn version_help_and_selftests() {
    let version = run(&["version"]);
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains("qwp"));

    let help = run(&["help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("qhs-keygen"));

    assert!(run(&["selftest"]).status.success());
    assert!(run(&["qhs-selftest"]).status.success());
}

#[test]
fn hash_entropy_and_usage_errors() {
    let hash = run(&["hash", "abc"]);
    assert!(hash.status.success());
    assert_eq!(
        String::from_utf8_lossy(&hash.stdout).trim(),
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    );

    let entropy = run(&["entropy", "8"]);
    assert!(entropy.status.success());
    assert_eq!(String::from_utf8_lossy(&entropy.stdout).trim().len(), 16);

    let max_entropy = run(&["entropy", "4096"]);
    assert!(max_entropy.status.success());
    assert_eq!(
        String::from_utf8_lossy(&max_entropy.stdout).trim().len(),
        8192
    );
    assert!(!run(&["entropy", "4097"]).status.success());

    assert!(!run(&["qhs-keygen"]).status.success());
    assert!(!run(&["qhs-sign"]).status.success());
    assert!(!run(&["qhs-verify"]).status.success());
    assert!(!run(&["unknown"]).status.success());
}

#[test]
fn qhs_error_paths() {
    let directory = workspace();
    let public = directory.join("public.key");
    let private = directory.join("private.key");
    let message = directory.join("message.txt");
    let signature = directory.join("message.sig");
    let missing = directory.join("missing.bin");
    fs::write(&message, b"qWp CLI error paths\n").unwrap();

    let public_text = public.to_string_lossy().to_string();
    let private_text = private.to_string_lossy().to_string();
    let message_text = message.to_string_lossy().to_string();
    let signature_text = signature.to_string_lossy().to_string();
    let missing_text = missing.to_string_lossy().to_string();

    assert!(
        run(&["qhs-keygen", &public_text, &private_text])
            .status
            .success()
    );
    assert!(
        run(&["qhs-sign", &private_text, &message_text, &signature_text])
            .status
            .success()
    );

    let missing_key = run(&["qhs-sign", &missing_text, &message_text, &signature_text]);
    assert!(!missing_key.status.success());
    let missing_verify = run(&["qhs-verify", &missing_text, &message_text, &signature_text]);
    assert!(!missing_verify.status.success());

    let mut signature_bytes = fs::read(&signature).unwrap();
    signature_bytes[10] ^= 1;
    fs::write(&signature, &signature_bytes).unwrap();
    let tampered = run(&["qhs-verify", &public_text, &message_text, &signature_text]);
    assert!(!tampered.status.success());

    let mut key_bytes = fs::read(&private).unwrap();
    key_bytes[36..38].copy_from_slice(&256_u16.to_le_bytes());
    fs::write(&private, &key_bytes).unwrap();
    let exhausted = run(&["qhs-sign", &private_text, &message_text, &signature_text]);
    assert!(!exhausted.status.success());

    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn qhs_keygen_sign_verify_end_to_end() {
    let directory = workspace();
    let public = directory.join("public.key");
    let private = directory.join("private.key");
    let message = directory.join("message.txt");
    let signature = directory.join("message.sig");
    fs::write(&message, b"qWp CLI integration message\n").unwrap();

    let public_text = public.to_string_lossy().to_string();
    let private_text = private.to_string_lossy().to_string();
    let message_text = message.to_string_lossy().to_string();
    let signature_text = signature.to_string_lossy().to_string();

    let keygen = run(&["qhs-keygen", &public_text, &private_text]);
    assert!(keygen.status.success(), "{keygen:?}");
    assert_eq!(fs::metadata(&public).unwrap().len(), 64);
    assert_eq!(fs::metadata(&private).unwrap().len(), 64);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&private).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let cache = directory.join("private.key.cache");
    assert_eq!(fs::metadata(&cache).unwrap().len(), 8232);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&cache).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let old_time =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    fs::OpenOptions::new()
        .write(true)
        .open(&cache)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(old_time))
        .unwrap();

    let sign = run(&["qhs-sign", &private_text, &message_text, &signature_text]);
    assert!(sign.status.success(), "{sign:?}");
    assert_eq!(fs::metadata(&signature).unwrap().len(), 2408);
    assert_eq!(fs::metadata(&cache).unwrap().modified().unwrap(), old_time);

    let verify = run(&["qhs-verify", &public_text, &message_text, &signature_text]);
    assert!(verify.status.success(), "{verify:?}");

    fs::remove_file(&cache).unwrap();
    let sign_again = run(&["qhs-sign", &private_text, &message_text, &signature_text]);
    assert!(sign_again.status.success(), "{sign_again:?}");
    assert!(cache.exists());
    assert!(
        run(&["qhs-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    fs::write(&message, b"wrong message\n").unwrap();
    let wrong = run(&["qhs-verify", &public_text, &message_text, &signature_text]);
    assert!(!wrong.status.success());

    let overwrite = run(&["qhs-keygen", &public_text, &private_text]);
    assert!(!overwrite.status.success());

    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn qhs_cache_corruption_and_foreign_cache_fall_back() {
    let directory = workspace();
    let public = directory.join("public.key");
    let private = directory.join("private.key");
    let message = directory.join("message.txt");
    let signature = directory.join("message.sig");
    fs::write(&message, b"qWp cache resilience\n").unwrap();

    let public_text = public.to_string_lossy().to_string();
    let private_text = private.to_string_lossy().to_string();
    let message_text = message.to_string_lossy().to_string();
    let signature_text = signature.to_string_lossy().to_string();

    let keygen = run(&["qhs-keygen", &public_text, &private_text]);
    assert!(keygen.status.success(), "{keygen:?}");
    let cache = directory.join("private.key.cache");
    let canonical_cache = fs::read(&cache).unwrap();
    assert_eq!(canonical_cache.len(), 8232);

    for offset in 0..4 {
        let mut corrupted_header = canonical_cache.clone();
        corrupted_header[offset] = 0xff;
        let checksum = hash32(&corrupted_header[..8_228]).to_bytes();
        corrupted_header[8_228..8_232].copy_from_slice(&checksum[..4]);
        fs::write(&cache, &corrupted_header).unwrap();
        let sign = run(&["qhs-sign", &private_text, &message_text, &signature_text]);
        assert!(sign.status.success(), "{sign:?}");
        assert_eq!(fs::read(&cache).unwrap(), canonical_cache);
    }

    let mut corrupted_leaf = canonical_cache.clone();
    corrupted_leaf[100] ^= 1;
    fs::write(&cache, &corrupted_leaf).unwrap();
    let sign = run(&["qhs-sign", &private_text, &message_text, &signature_text]);
    assert!(sign.status.success(), "{sign:?}");
    assert_eq!(fs::read(&cache).unwrap(), canonical_cache);
    assert!(
        run(&["qhs-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let mut corrupted_fingerprint = canonical_cache.clone();
    corrupted_fingerprint[4] ^= 1;
    fs::write(&cache, &corrupted_fingerprint).unwrap();
    let sign = run(&["qhs-sign", &private_text, &message_text, &signature_text]);
    assert!(sign.status.success(), "{sign:?}");
    assert_eq!(fs::read(&cache).unwrap(), canonical_cache);

    fs::write(&cache, &canonical_cache[..100]).unwrap();
    let sign = run(&["qhs-sign", &private_text, &message_text, &signature_text]);
    assert!(sign.status.success(), "{sign:?}");
    assert_eq!(fs::read(&cache).unwrap(), canonical_cache);

    fs::write(&cache, vec![0_u8; 8_233]).unwrap();
    let sign = run(&["qhs-sign", &private_text, &message_text, &signature_text]);
    assert!(sign.status.success(), "{sign:?}");
    assert_eq!(fs::read(&cache).unwrap(), canonical_cache);

    let foreign_public = directory.join("foreign-public.key");
    let foreign_private = directory.join("foreign-private.key");
    let foreign_public_text = foreign_public.to_string_lossy().to_string();
    let foreign_private_text = foreign_private.to_string_lossy().to_string();
    let foreign_keygen = run(&["qhs-keygen", &foreign_public_text, &foreign_private_text]);
    assert!(foreign_keygen.status.success(), "{foreign_keygen:?}");
    let foreign_cache = directory.join("foreign-private.key.cache");
    let foreign_bytes = fs::read(&foreign_cache).unwrap();
    assert_ne!(foreign_bytes, canonical_cache);

    fs::write(&cache, &foreign_bytes).unwrap();
    let sign = run(&["qhs-sign", &private_text, &message_text, &signature_text]);
    assert!(sign.status.success(), "{sign:?}");
    assert_eq!(fs::read(&cache).unwrap(), canonical_cache);
    assert!(
        run(&["qhs-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let _ = fs::remove_dir_all(&directory);
}
