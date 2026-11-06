//! End-to-end CLI tests.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

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

    let sign = run(&["qhs-sign", &private_text, &message_text, &signature_text]);
    assert!(sign.status.success(), "{sign:?}");
    assert_eq!(fs::metadata(&signature).unwrap().len(), 2408);

    let verify = run(&["qhs-verify", &public_text, &message_text, &signature_text]);
    assert!(verify.status.success(), "{verify:?}");

    fs::write(&message, b"wrong message\n").unwrap();
    let wrong = run(&["qhs-verify", &public_text, &message_text, &signature_text]);
    assert!(!wrong.status.success());

    let overwrite = run(&["qhs-keygen", &public_text, &private_text]);
    assert!(!overwrite.status.success());

    let _ = fs::remove_dir_all(&directory);
}
