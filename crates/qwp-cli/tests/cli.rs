//! End-to-end CLI tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use qwp_hash::{Hasher, derive_key32};

fn cache_mac(seed: &[u8; 32], context: &[u8], body: &[u8]) -> [u8; 32] {
    let key = derive_key32(context, seed).to_bytes();
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(body);
    hasher.finalize().to_bytes()
}

fn cache_mac64(seed: &[u8; 64], context: &[u8], body: &[u8]) -> [u8; 32] {
    let key = derive_key32(context, seed).to_bytes();
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(body);
    hasher.finalize().to_bytes()
}

fn private_seed(path: &Path) -> [u8; 32] {
    let bytes = fs::read(path).unwrap();
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&bytes[4..36]);
    seed
}

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
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help_text.contains("qhs-keygen"));
    assert!(help_text.contains("qhs2-keygen"));
    assert!(help_text.contains("qhs3-keygen"));
    assert!(help_text.contains("qhs31-keygen"));
    assert!(help_text.contains("qhs4-keygen"));
    assert!(help_text.contains("qhs4-sign"));
    assert!(help_text.contains("qhs4-verify"));
    assert!(help_text.contains("qhs41-keygen"));
    assert!(help_text.contains("qhs41-sign"));
    assert!(help_text.contains("qhs41-verify"));
    assert!(help_text.contains("qhs42-keygen"));
    assert!(help_text.contains("qhs42-sign"));
    assert!(help_text.contains("qhs42-verify"));
    assert!(help_text.contains("qhs5-keygen"));
    assert!(help_text.contains("qhs5-sign"));
    assert!(help_text.contains("qhs5-verify"));
    assert!(help_text.contains("qhs6-keygen"));
    assert!(help_text.contains("qhs6-sign"));
    assert!(help_text.contains("qhs6-verify"));
    assert!(help_text.contains("qhse-verify"));

    assert!(run(&["selftest"]).status.success());
    assert!(run(&["qhs-selftest"]).status.success());
    assert!(run(&["qhs2-selftest"]).status.success());
    assert!(run(&["qhs3-selftest"]).status.success());
    assert!(run(&["qhs31-selftest"]).status.success());
    assert!(run(&["qhs4-selftest"]).status.success());
    assert!(run(&["qhs41-selftest"]).status.success());
    assert!(run(&["qhs42-selftest"]).status.success());
    assert!(run(&["qhs5-selftest"]).status.success());
    assert!(run(&["qhs6-selftest"]).status.success());
    assert!(run(&["qhse-selftest"]).status.success());
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
    assert!(!run(&["qhs2-keygen"]).status.success());
    assert!(!run(&["qhs2-sign"]).status.success());
    assert!(!run(&["qhs2-verify"]).status.success());
    assert!(!run(&["qhs3-keygen"]).status.success());
    assert!(!run(&["qhs3-sign"]).status.success());
    assert!(!run(&["qhs3-verify"]).status.success());
    assert!(!run(&["qhs31-keygen"]).status.success());
    assert!(!run(&["qhs31-sign"]).status.success());
    assert!(!run(&["qhs31-verify"]).status.success());
    assert!(!run(&["qhs4-keygen"]).status.success());
    assert!(!run(&["qhs4-sign"]).status.success());
    assert!(!run(&["qhs4-verify"]).status.success());
    assert!(!run(&["qhs41-keygen"]).status.success());
    assert!(!run(&["qhs41-sign"]).status.success());
    assert!(!run(&["qhs41-verify"]).status.success());
    assert!(!run(&["qhs42-keygen"]).status.success());
    assert!(!run(&["qhs42-sign"]).status.success());
    assert!(!run(&["qhs42-verify"]).status.success());
    assert!(!run(&["qhs5-keygen"]).status.success());
    assert!(!run(&["qhs5-sign"]).status.success());
    assert!(!run(&["qhs5-verify"]).status.success());
    assert!(!run(&["qhs6-keygen"]).status.success());
    assert!(!run(&["qhs6-sign"]).status.success());
    assert!(!run(&["qhs6-verify"]).status.success());
    assert!(!run(&["qhse-verify"]).status.success());
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
    assert_eq!(fs::metadata(&cache).unwrap().len(), 8260);
    let state = directory.join("private.key.state");
    assert_eq!(fs::metadata(&state).unwrap().len(), 38);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&cache).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let state_mode = fs::metadata(&state).unwrap().permissions().mode() & 0o777;
        assert_eq!(state_mode, 0o600);
    }
    let seed = private_seed(&private);
    let cache_bytes = fs::read(&cache).unwrap();
    let expected_fingerprint = derive_key32(b"qWp QHS-1 cache fingerprint", &seed).to_bytes();
    assert_eq!(&cache_bytes[4..36], &expected_fingerprint);
    let state_bytes = fs::read(&state).unwrap();
    let expected_state_mac = cache_mac(&seed, b"qWp key state guard", &state_bytes[..6]);
    assert_eq!(&state_bytes[6..38], &expected_state_mac);

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

    let signed_key = fs::read(&private).unwrap();
    let signed_state = fs::read(&state).unwrap();
    let mut rolled_back = signed_key.clone();
    rolled_back[36..38].copy_from_slice(&0_u16.to_le_bytes());
    fs::write(&private, &rolled_back).unwrap();
    let rollback = run(&["qhs-sign", &private_text, &message_text, &signature_text]);
    assert!(!rollback.status.success());
    assert!(String::from_utf8_lossy(&rollback.stderr).contains("rollback"));
    fs::write(&private, &signed_key).unwrap();
    fs::write(&state, &signed_state).unwrap();

    let mut ahead = fs::read(&private).unwrap();
    ahead[36..38].copy_from_slice(&2_u16.to_le_bytes());
    fs::write(&private, &ahead).unwrap();
    let caught_up = run(&["qhs-sign", &private_text, &message_text, &signature_text]);
    assert!(caught_up.status.success());
    let caught_up_state = fs::read(&state).unwrap();
    assert_eq!(
        u16::from_le_bytes([caught_up_state[4], caught_up_state[5]]),
        3
    );

    fs::remove_file(&state).unwrap();
    let sign_after_guard_loss = run(&["qhs-sign", &private_text, &message_text, &signature_text]);
    assert!(!sign_after_guard_loss.status.success());
    assert!(
        String::from_utf8_lossy(&sign_after_guard_loss.stderr).contains("missing"),
        "{sign_after_guard_loss:?}"
    );
    fs::write(&state, &caught_up_state).unwrap();

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
fn qhs2_keygen_sign_verify_end_to_end() {
    let directory = workspace();
    let public = directory.join("public.key");
    let private = directory.join("private.key");
    let message = directory.join("message.txt");
    let signature = directory.join("message.sig");
    fs::write(&message, b"qWp QHS-2 CLI integration message\n").unwrap();

    let public_text = public.to_string_lossy().to_string();
    let private_text = private.to_string_lossy().to_string();
    let message_text = message.to_string_lossy().to_string();
    let signature_text = signature.to_string_lossy().to_string();

    let keygen = run(&["qhs2-keygen", &public_text, &private_text]);
    assert!(keygen.status.success(), "{keygen:?}");
    assert_eq!(fs::metadata(&public).unwrap().len(), 64);
    assert_eq!(fs::metadata(&private).unwrap().len(), 64);

    let cache = directory.join("private.key.cache");
    assert_eq!(fs::metadata(&cache).unwrap().len(), 8260);
    let cache_bytes = fs::read(&cache).unwrap();
    assert_eq!(&cache_bytes[..4], &[2, 2, 8, 2]);
    let seed = private_seed(&private);
    let expected_fingerprint = derive_key32(b"qWp QHS-2 cache fingerprint", &seed).to_bytes();
    assert_eq!(&cache_bytes[4..36], &expected_fingerprint);
    let state = directory.join("private.key.state");
    let state_bytes = fs::read(&state).unwrap();
    let expected_state_mac = cache_mac(&seed, b"qWp key state guard", &state_bytes[..6]);
    assert_eq!(&state_bytes[6..38], &expected_state_mac);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&private).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let cache_mode = fs::metadata(&cache).unwrap().permissions().mode() & 0o777;
        assert_eq!(cache_mode, 0o600);
    }

    let old_time =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    fs::OpenOptions::new()
        .write(true)
        .open(&cache)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(old_time))
        .unwrap();

    let sign = run(&["qhs2-sign", &private_text, &message_text, &signature_text]);
    assert!(sign.status.success(), "{sign:?}");
    assert_eq!(fs::metadata(&signature).unwrap().len(), 1704);
    let signature_bytes = fs::read(&signature).unwrap();
    assert_eq!(&signature_bytes[..2], &[2, 2]);
    assert_eq!(fs::metadata(&cache).unwrap().modified().unwrap(), old_time);

    let verify = run(&["qhs2-verify", &public_text, &message_text, &signature_text]);
    assert!(verify.status.success(), "{verify:?}");

    fs::remove_file(&cache).unwrap();
    let sign_again = run(&["qhs2-sign", &private_text, &message_text, &signature_text]);
    assert!(sign_again.status.success(), "{sign_again:?}");
    assert!(cache.exists());
    assert!(
        run(&["qhs2-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let mut tampered = fs::read(&signature).unwrap();
    tampered[10] ^= 1;
    fs::write(&signature, &tampered).unwrap();
    assert!(
        !run(&["qhs2-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    fs::write(&message, b"wrong message\n").unwrap();
    assert!(
        !run(&["qhs2-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let mut key_bytes = fs::read(&private).unwrap();
    key_bytes[36..38].copy_from_slice(&256_u16.to_le_bytes());
    fs::write(&private, &key_bytes).unwrap();
    assert!(
        !run(&["qhs2-sign", &private_text, &message_text, &signature_text])
            .status
            .success()
    );

    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn qhs5_keygen_sign_verify_cache_and_rollback() {
    let directory = workspace();
    let public = directory.join("public.key");
    let private = directory.join("private.key");
    let message = directory.join("message.txt");
    let signature = directory.join("message.sig");
    fs::write(&message, b"qWp QHS-5 CLI integration message\n").unwrap();

    let public_text = public.to_string_lossy().to_string();
    let private_text = private.to_string_lossy().to_string();
    let message_text = message.to_string_lossy().to_string();
    let signature_text = signature.to_string_lossy().to_string();

    let keygen = run(&["qhs5-keygen", &public_text, &private_text]);
    assert!(keygen.status.success(), "{keygen:?}");
    assert_eq!(fs::metadata(&public).unwrap().len(), 72);
    assert_eq!(fs::metadata(&private).unwrap().len(), 72);
    assert_eq!(&fs::read(&public).unwrap()[..4], &[6, 6, 8, 0]);
    let key_bytes = fs::read(&private).unwrap();
    assert_eq!(&key_bytes[..4], &[6, 6, 8, 0]);
    assert_eq!(&key_bytes[68..70], &0_u16.to_le_bytes());

    let cache = directory.join("private.key.cache");
    let state = directory.join("private.key.state");
    assert_eq!(fs::metadata(&cache).unwrap().len(), 16_452);
    assert_eq!(fs::metadata(&state).unwrap().len(), 38);
    let cache_bytes = fs::read(&cache).unwrap();
    assert_eq!(&cache_bytes[..4], &[6, 6, 8, 2]);
    let state_bytes = fs::read(&state).unwrap();
    assert_eq!(&state_bytes[..4], &[6, 6, 8, 0]);
    assert_eq!(&state_bytes[4..6], &0_u16.to_le_bytes());

    let mut seed = [0_u8; 64];
    seed.copy_from_slice(&key_bytes[4..68]);
    let expected_fingerprint = derive_key32(b"qWp QHS-5 cache fingerprint", &seed).to_bytes();
    assert_eq!(&cache_bytes[4..36], &expected_fingerprint);
    let expected_state_mac = cache_mac64(&seed, b"qWp QHS-5 key state guard", &state_bytes[..6]);
    assert_eq!(&state_bytes[6..38], &expected_state_mac);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&private, &cache, &state] {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    let old_time =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    fs::OpenOptions::new()
        .write(true)
        .open(&cache)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(old_time))
        .unwrap();

    let sign = run(&["qhs5-sign", &private_text, &message_text, &signature_text]);
    assert!(sign.status.success(), "{sign:?}");
    assert_eq!(fs::metadata(&signature).unwrap().len(), 6_216);
    let signature_bytes = fs::read(&signature).unwrap();
    assert_eq!(&signature_bytes[..4], &[6, 6, 0, 0]);
    assert_eq!(fs::metadata(&cache).unwrap().modified().unwrap(), old_time);
    let key_after_first = fs::read(&private).unwrap();
    let state_after_first = fs::read(&state).unwrap();
    assert_eq!(&key_after_first[68..70], &1_u16.to_le_bytes());
    assert_eq!(&state_after_first[4..6], &1_u16.to_le_bytes());
    assert!(
        run(&["qhs5-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let sign_again = run(&["qhs5-sign", &private_text, &message_text, &signature_text]);
    assert!(sign_again.status.success(), "{sign_again:?}");
    assert_eq!(&fs::read(&signature).unwrap()[..4], &[6, 6, 1, 0]);
    assert_eq!(&fs::read(&private).unwrap()[68..70], &2_u16.to_le_bytes());
    assert_eq!(&fs::read(&state).unwrap()[4..6], &2_u16.to_le_bytes());
    assert!(
        run(&["qhs5-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let mut rolled_back = key_after_first.clone();
    rolled_back[68..70].copy_from_slice(&1_u16.to_le_bytes());
    fs::write(&private, &rolled_back).unwrap();
    let rollback = run(&["qhs5-sign", &private_text, &message_text, &signature_text]);
    assert!(!rollback.status.success());
    assert!(String::from_utf8_lossy(&rollback.stderr).contains("rollback"));
    fs::write(&private, &key_after_first).unwrap();
    fs::write(&state, &state_after_first).unwrap();

    fs::write(&cache, b"corrupt cache").unwrap();
    let cache_recovery = run(&["qhs5-sign", &private_text, &message_text, &signature_text]);
    assert!(cache_recovery.status.success(), "{cache_recovery:?}");
    assert_eq!(fs::metadata(&cache).unwrap().len(), 16_452);
    assert!(
        run(&["qhs5-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let mut tampered = fs::read(&signature).unwrap();
    tampered[100] ^= 1;
    fs::write(&signature, &tampered).unwrap();
    assert!(
        !run(&["qhs5-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    fs::write(&message, b"wrong message\n").unwrap();
    assert!(
        !run(&["qhs5-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );
    assert!(
        !run(&["qhs42-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let overwrite = run(&["qhs5-keygen", &public_text, &private_text]);
    assert!(!overwrite.status.success());

    let mut exhausted = fs::read(&private).unwrap();
    exhausted[68..70].copy_from_slice(&256_u16.to_le_bytes());
    fs::write(&private, &exhausted).unwrap();
    assert!(
        !run(&["qhs5-sign", &private_text, &message_text, &signature_text])
            .status
            .success()
    );

    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn qhs6_keygen_sign_verify_cache_and_rollback() {
    let directory = workspace();
    let public = directory.join("public.key");
    let private = directory.join("private.key");
    let message = directory.join("message.txt");
    let signature = directory.join("message.sig");
    fs::write(&message, b"qWp QHS-6 CLI integration message\n").unwrap();

    let public_text = public.to_string_lossy().to_string();
    let private_text = private.to_string_lossy().to_string();
    let message_text = message.to_string_lossy().to_string();
    let signature_text = signature.to_string_lossy().to_string();

    let keygen = run(&["qhs6-keygen", &public_text, &private_text]);
    assert!(keygen.status.success(), "{keygen:?}");
    assert_eq!(fs::metadata(&public).unwrap().len(), 108);
    assert_eq!(fs::metadata(&private).unwrap().len(), 108);
    assert_eq!(&fs::read(&public).unwrap()[..4], &[7, 7, 8, 0]);
    let key_bytes = fs::read(&private).unwrap();
    assert_eq!(&key_bytes[..4], &[7, 7, 8, 0]);
    assert_eq!(&key_bytes[72..74], &0_u16.to_le_bytes());

    let cache = directory.join("private.key.cache");
    let state = directory.join("private.key.state");
    assert_eq!(fs::metadata(&cache).unwrap().len(), 16_452);
    assert_eq!(fs::metadata(&state).unwrap().len(), 38);
    let cache_bytes = fs::read(&cache).unwrap();
    assert_eq!(&cache_bytes[..4], &[7, 7, 8, 2]);
    let state_bytes = fs::read(&state).unwrap();
    assert_eq!(&state_bytes[..4], &[7, 7, 8, 0]);
    assert_eq!(&state_bytes[4..6], &0_u16.to_le_bytes());

    let mut seed = [0_u8; 64];
    seed.copy_from_slice(&key_bytes[8..72]);
    let expected_fingerprint = derive_key32(b"qWp QHS-6 cache fingerprint", &seed).to_bytes();
    assert_eq!(&cache_bytes[4..36], &expected_fingerprint);
    let expected_state_mac = cache_mac64(&seed, b"qWp QHS-6 key state guard", &state_bytes[..6]);
    assert_eq!(&state_bytes[6..38], &expected_state_mac);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&private, &cache, &state] {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    let old_time =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    fs::OpenOptions::new()
        .write(true)
        .open(&cache)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(old_time))
        .unwrap();

    let sign = run(&["qhs6-sign", &private_text, &message_text, &signature_text]);
    assert!(sign.status.success(), "{sign:?}");
    assert_eq!(fs::metadata(&signature).unwrap().len(), 6_284);
    let signature_bytes = fs::read(&signature).unwrap();
    assert_eq!(&signature_bytes[..4], &[7, 7, 0, 0]);
    assert_eq!(fs::metadata(&cache).unwrap().modified().unwrap(), old_time);
    let key_after_first = fs::read(&private).unwrap();
    let state_after_first = fs::read(&state).unwrap();
    assert_eq!(&key_after_first[72..74], &1_u16.to_le_bytes());
    assert_eq!(&state_after_first[4..6], &1_u16.to_le_bytes());
    assert!(
        run(&["qhs6-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let sign_again = run(&["qhs6-sign", &private_text, &message_text, &signature_text]);
    assert!(sign_again.status.success(), "{sign_again:?}");
    assert_eq!(&fs::read(&signature).unwrap()[..4], &[7, 7, 1, 0]);
    assert_eq!(&fs::read(&private).unwrap()[72..74], &2_u16.to_le_bytes());
    assert_eq!(&fs::read(&state).unwrap()[4..6], &2_u16.to_le_bytes());
    assert!(
        run(&["qhs6-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let mut rolled_back = key_after_first.clone();
    rolled_back[72..74].copy_from_slice(&1_u16.to_le_bytes());
    fs::write(&private, &rolled_back).unwrap();
    let rollback = run(&["qhs6-sign", &private_text, &message_text, &signature_text]);
    assert!(!rollback.status.success());
    assert!(String::from_utf8_lossy(&rollback.stderr).contains("rollback"));
    fs::write(&private, &key_after_first).unwrap();
    fs::write(&state, &state_after_first).unwrap();

    fs::write(&cache, b"corrupt cache").unwrap();
    let cache_recovery = run(&["qhs6-sign", &private_text, &message_text, &signature_text]);
    assert!(cache_recovery.status.success(), "{cache_recovery:?}");
    assert_eq!(fs::metadata(&cache).unwrap().len(), 16_452);
    assert!(
        run(&["qhs6-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let mut tampered = fs::read(&signature).unwrap();
    tampered[100] ^= 1;
    fs::write(&signature, &tampered).unwrap();
    assert!(
        !run(&["qhs6-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    fs::write(&message, b"wrong message\n").unwrap();
    assert!(
        !run(&["qhs6-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );
    assert!(
        !run(&["qhs5-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let overwrite = run(&["qhs6-keygen", &public_text, &private_text]);
    assert!(!overwrite.status.success());

    let mut exhausted = fs::read(&private).unwrap();
    exhausted[72..74].copy_from_slice(&256_u16.to_le_bytes());
    fs::write(&private, &exhausted).unwrap();
    assert!(
        !run(&["qhs6-sign", &private_text, &message_text, &signature_text])
            .status
            .success()
    );

    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn qhse_verify_profile_end_to_end() {
    let directory = workspace();
    let message = directory.join("message.txt");
    fs::write(&message, b"qWp QHS-E CLI message\n").unwrap();
    let message_text = message.to_string_lossy().to_string();

    for (version, prefix, signature_size) in [
        ("1", "qhs", 2_408_u64),
        ("2", "qhs2", 1_704_u64),
        ("3", "qhs3", 1_832_u64),
    ] {
        let public = directory.join(format!("{prefix}-public.key"));
        let private = directory.join(format!("{prefix}-private.key"));
        let signature = directory.join(format!("{prefix}.sig"));
        let public_text = public.to_string_lossy().to_string();
        let private_text = private.to_string_lossy().to_string();
        let signature_text = signature.to_string_lossy().to_string();

        assert!(
            run(&[&format!("{prefix}-keygen"), &public_text, &private_text])
                .status
                .success()
        );
        assert!(
            run(&[
                &format!("{prefix}-sign"),
                &private_text,
                &message_text,
                &signature_text
            ])
            .status
            .success()
        );
        assert_eq!(fs::metadata(&signature).unwrap().len(), signature_size);
        assert!(
            run(&[
                "qhse-verify",
                version,
                &public_text,
                &message_text,
                &signature_text
            ])
            .status
            .success()
        );
        let original_signature = fs::read(&signature).unwrap();
        let mut tampered = original_signature.clone();
        tampered[10] ^= 1;
        fs::write(&signature, &tampered).unwrap();
        assert!(
            !run(&[
                "qhse-verify",
                version,
                &public_text,
                &message_text,
                &signature_text
            ])
            .status
            .success()
        );

        fs::write(&message, b"wrong message\n").unwrap();
        assert!(
            !run(&[
                "qhse-verify",
                version,
                &public_text,
                &message_text,
                &signature_text
            ])
            .status
            .success()
        );
        fs::write(&signature, &original_signature).unwrap();
        fs::write(&message, b"qWp QHS-E CLI message\n").unwrap();
        if version != "2" {
            assert!(
                !run(&[
                    "qhse-verify",
                    "2",
                    &public_text,
                    &message_text,
                    &signature_text
                ])
                .status
                .success()
            );
        }
    }

    let public1 = directory.join("qhs-public.key");
    let signature1 = directory.join("qhs.sig");
    let public1_text = public1.to_string_lossy().to_string();
    let signature1_text = signature1.to_string_lossy().to_string();
    let mut tail_key = fs::read(&public1).unwrap();
    tail_key[36] ^= 1;
    fs::write(&public1, &tail_key).unwrap();
    assert!(
        !run(&[
            "qhse-verify",
            "1",
            &public1_text,
            &message_text,
            &signature1_text
        ])
        .status
        .success()
    );

    let public3 = directory.join("qhs3-public.key");
    let signature3 = directory.join("qhs3.sig");
    let public3_text = public3.to_string_lossy().to_string();
    let signature3_text = signature3.to_string_lossy().to_string();
    assert!(
        run(&[
            "qhse-verify",
            "31",
            &public3_text,
            &message_text,
            &signature3_text
        ])
        .status
        .success()
    );

    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn state_guard_corruption_and_missing_guard_fail() {
    for (prefix, signature_size) in [("qhs", 2_408_u64), ("qhs5", 6_216), ("qhs6", 6_284)] {
        let directory = workspace();
        let public = directory.join(format!("{prefix}-public.key"));
        let private = directory.join(format!("{prefix}-private.key"));
        let message = directory.join("message.txt");
        let signature = directory.join("message.sig");
        fs::write(&message, b"qWp state guard attack message\n").unwrap();
        let public_text = public.to_string_lossy().to_string();
        let private_text = private.to_string_lossy().to_string();
        let message_text = message.to_string_lossy().to_string();
        let signature_text = signature.to_string_lossy().to_string();

        assert!(
            run(&[&format!("{prefix}-keygen"), &public_text, &private_text])
                .status
                .success()
        );
        assert!(
            run(&[
                &format!("{prefix}-sign"),
                &private_text,
                &message_text,
                &signature_text
            ])
            .status
            .success()
        );
        assert_eq!(fs::metadata(&signature).unwrap().len(), signature_size);

        let state = directory.join(format!("{prefix}-private.key.state"));
        let good_state = fs::read(&state).unwrap();
        let mut corrupt = good_state.clone();
        corrupt[0] ^= 1;
        fs::write(&state, &corrupt).unwrap();
        let corrupt_result = run(&[
            &format!("{prefix}-sign"),
            &private_text,
            &message_text,
            &signature_text,
        ]);
        assert!(!corrupt_result.status.success());
        assert!(
            String::from_utf8_lossy(&corrupt_result.stderr).contains("corrupt"),
            "{corrupt_result:?}"
        );

        fs::write(&state, &good_state).unwrap();
        fs::remove_file(&state).unwrap();
        let missing_result = run(&[
            &format!("{prefix}-sign"),
            &private_text,
            &message_text,
            &signature_text,
        ]);
        assert!(!missing_result.status.success());
        assert!(
            String::from_utf8_lossy(&missing_result.stderr).contains("missing"),
            "{missing_result:?}"
        );

        let fresh = workspace();
        let fresh_public = fresh.join("public.key");
        let fresh_private = fresh.join("private.key");
        let fresh_message = fresh.join("message.txt");
        let fresh_signature = fresh.join("message.sig");
        fs::write(&fresh_message, b"fresh key\n").unwrap();
        let fresh_public_text = fresh_public.to_string_lossy().to_string();
        let fresh_private_text = fresh_private.to_string_lossy().to_string();
        let fresh_message_text = fresh_message.to_string_lossy().to_string();
        let fresh_signature_text = fresh_signature.to_string_lossy().to_string();
        assert!(
            run(&[
                &format!("{prefix}-keygen"),
                &fresh_public_text,
                &fresh_private_text
            ])
            .status
            .success()
        );
        fs::remove_file(fresh.join("private.key.state")).unwrap();
        assert!(
            run(&[
                &format!("{prefix}-sign"),
                &fresh_private_text,
                &fresh_message_text,
                &fresh_signature_text
            ])
            .status
            .success()
        );

        let _ = fs::remove_dir_all(&directory);
        let _ = fs::remove_dir_all(&fresh);
    }
}

#[test]
fn qhs2_rejects_v1_keys_and_signatures() {
    let directory = workspace();
    let v1_public = directory.join("v1-public.key");
    let v1_private = directory.join("v1-private.key");
    let v2_public = directory.join("v2-public.key");
    let v2_private = directory.join("v2-private.key");
    let message = directory.join("message.txt");
    let signature = directory.join("message.sig");
    fs::write(&message, b"qWp cross-version\n").unwrap();

    let v1_public_text = v1_public.to_string_lossy().to_string();
    let v1_private_text = v1_private.to_string_lossy().to_string();
    let v2_public_text = v2_public.to_string_lossy().to_string();
    let v2_private_text = v2_private.to_string_lossy().to_string();
    let message_text = message.to_string_lossy().to_string();
    let signature_text = signature.to_string_lossy().to_string();

    assert!(
        run(&["qhs-keygen", &v1_public_text, &v1_private_text])
            .status
            .success()
    );
    assert!(
        run(&["qhs2-keygen", &v2_public_text, &v2_private_text])
            .status
            .success()
    );
    assert!(
        run(&[
            "qhs2-sign",
            &v2_private_text,
            &message_text,
            &signature_text
        ])
        .status
        .success()
    );

    assert!(
        !run(&[
            "qhs2-sign",
            &v1_private_text,
            &message_text,
            &signature_text
        ])
        .status
        .success()
    );
    assert!(
        !run(&["qhs-sign", &v2_private_text, &message_text, &signature_text])
            .status
            .success()
    );
    assert!(
        !run(&[
            "qhs2-verify",
            &v1_public_text,
            &message_text,
            &signature_text
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "qhs-verify",
            &v2_public_text,
            &message_text,
            &signature_text
        ])
        .status
        .success()
    );

    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn qhs3_keygen_sign_verify_end_to_end() {
    let directory = workspace();
    let public = directory.join("public.key");
    let private = directory.join("private.key");
    let message = directory.join("message.txt");
    let signature = directory.join("message.sig");
    fs::write(&message, b"qWp QHS-3 CLI integration message\n").unwrap();

    let public_text = public.to_string_lossy().to_string();
    let private_text = private.to_string_lossy().to_string();
    let message_text = message.to_string_lossy().to_string();
    let signature_text = signature.to_string_lossy().to_string();

    let keygen = run(&["qhs3-keygen", &public_text, &private_text]);
    assert!(keygen.status.success(), "{keygen:?}");
    assert_eq!(fs::metadata(&public).unwrap().len(), 64);
    assert_eq!(fs::metadata(&private).unwrap().len(), 64);

    let cache = directory.join("private.key.cache");
    assert_eq!(fs::metadata(&cache).unwrap().len(), 131_140);
    let cache_bytes = fs::read(&cache).unwrap();
    assert_eq!(&cache_bytes[..4], &[3, 3, 12, 2]);
    let seed = private_seed(&private);
    let expected_fingerprint = derive_key32(b"qWp QHS-3 cache fingerprint", &seed).to_bytes();
    assert_eq!(&cache_bytes[4..36], &expected_fingerprint);
    let state = directory.join("private.key.state");
    let state_bytes = fs::read(&state).unwrap();
    let expected_state_mac = cache_mac(&seed, b"qWp key state guard", &state_bytes[..6]);
    assert_eq!(&state_bytes[6..38], &expected_state_mac);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&private).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let cache_mode = fs::metadata(&cache).unwrap().permissions().mode() & 0o777;
        assert_eq!(cache_mode, 0o600);
    }

    let old_time =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    fs::OpenOptions::new()
        .write(true)
        .open(&cache)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(old_time))
        .unwrap();

    let sign = run(&["qhs3-sign", &private_text, &message_text, &signature_text]);
    assert!(sign.status.success(), "{sign:?}");
    assert_eq!(fs::metadata(&signature).unwrap().len(), 1832);
    let signature_bytes = fs::read(&signature).unwrap();
    assert_eq!(&signature_bytes[..2], &[3, 3]);
    assert_eq!(fs::metadata(&cache).unwrap().modified().unwrap(), old_time);

    let verify = run(&["qhs3-verify", &public_text, &message_text, &signature_text]);
    assert!(verify.status.success(), "{verify:?}");

    let canonical_cache = fs::read(&cache).unwrap();
    let seed = private_seed(&private);
    for offset in 0..4 {
        let mut corrupted_header = canonical_cache.clone();
        corrupted_header[offset] = 0xff;
        let mac = cache_mac(&seed, b"qWp QHS-3 cache mac", &corrupted_header[..131_108]);
        corrupted_header[131_108..131_140].copy_from_slice(&mac);
        fs::write(&cache, &corrupted_header).unwrap();
        let sign = run(&["qhs3-sign", &private_text, &message_text, &signature_text]);
        assert!(sign.status.success(), "{sign:?}");
        assert_eq!(fs::read(&cache).unwrap(), canonical_cache);
    }

    fs::remove_file(&cache).unwrap();
    let sign_again = run(&["qhs3-sign", &private_text, &message_text, &signature_text]);
    assert!(sign_again.status.success(), "{sign_again:?}");
    assert!(cache.exists());
    assert!(
        run(&["qhs3-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let mut tampered = fs::read(&signature).unwrap();
    tampered[10] ^= 1;
    fs::write(&signature, &tampered).unwrap();
    assert!(
        !run(&["qhs3-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    fs::write(&message, b"wrong message\n").unwrap();
    assert!(
        !run(&["qhs3-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let mut key_bytes = fs::read(&private).unwrap();
    key_bytes[36..38].copy_from_slice(&4096_u16.to_le_bytes());
    fs::write(&private, &key_bytes).unwrap();
    assert!(
        !run(&["qhs3-sign", &private_text, &message_text, &signature_text])
            .status
            .success()
    );

    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn qhs3_rejects_v1_and_v2_keys_and_signatures() {
    let directory = workspace();
    let v1_public = directory.join("v1-public.key");
    let v1_private = directory.join("v1-private.key");
    let v2_public = directory.join("v2-public.key");
    let v2_private = directory.join("v2-private.key");
    let v3_public = directory.join("v3-public.key");
    let v3_private = directory.join("v3-private.key");
    let message = directory.join("message.txt");
    let signature = directory.join("message.sig");
    fs::write(&message, b"qWp cross-version QHS-3\n").unwrap();

    let v1_public_text = v1_public.to_string_lossy().to_string();
    let v1_private_text = v1_private.to_string_lossy().to_string();
    let v2_public_text = v2_public.to_string_lossy().to_string();
    let v2_private_text = v2_private.to_string_lossy().to_string();
    let v3_public_text = v3_public.to_string_lossy().to_string();
    let v3_private_text = v3_private.to_string_lossy().to_string();
    let message_text = message.to_string_lossy().to_string();
    let signature_text = signature.to_string_lossy().to_string();

    assert!(
        run(&["qhs-keygen", &v1_public_text, &v1_private_text])
            .status
            .success()
    );
    assert!(
        run(&["qhs2-keygen", &v2_public_text, &v2_private_text])
            .status
            .success()
    );
    assert!(
        run(&["qhs3-keygen", &v3_public_text, &v3_private_text])
            .status
            .success()
    );
    assert!(
        run(&[
            "qhs3-sign",
            &v3_private_text,
            &message_text,
            &signature_text
        ])
        .status
        .success()
    );

    assert!(
        !run(&[
            "qhs3-sign",
            &v1_private_text,
            &message_text,
            &signature_text
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "qhs3-sign",
            &v2_private_text,
            &message_text,
            &signature_text
        ])
        .status
        .success()
    );
    assert!(
        !run(&["qhs-sign", &v3_private_text, &message_text, &signature_text])
            .status
            .success()
    );
    assert!(
        !run(&[
            "qhs2-sign",
            &v3_private_text,
            &message_text,
            &signature_text
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "qhs3-verify",
            &v1_public_text,
            &message_text,
            &signature_text
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "qhs3-verify",
            &v2_public_text,
            &message_text,
            &signature_text
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "qhs-verify",
            &v3_public_text,
            &message_text,
            &signature_text
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "qhs2-verify",
            &v3_public_text,
            &message_text,
            &signature_text
        ])
        .status
        .success()
    );

    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn qhs_cache_random_bytes_fall_back() {
    let directory = workspace();
    let public = directory.join("public.key");
    let private = directory.join("private.key");
    let message = directory.join("message.txt");
    let signature = directory.join("message.sig");
    fs::write(&message, b"qWp random cache fallback\n").unwrap();

    let public_text = public.to_string_lossy().to_string();
    let private_text = private.to_string_lossy().to_string();
    let message_text = message.to_string_lossy().to_string();
    let signature_text = signature.to_string_lossy().to_string();

    assert!(
        run(&["qhs-keygen", &public_text, &private_text])
            .status
            .success()
    );
    let cache = directory.join("private.key.cache");
    let canonical = fs::read(&cache).unwrap();
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for _ in 0..16 {
        let mut random = vec![0_u8; canonical.len()];
        for byte in &mut random {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = u8::try_from(state & 0xff).unwrap_or(0);
        }
        fs::write(&cache, &random).unwrap();
        let sign = run(&["qhs-sign", &private_text, &message_text, &signature_text]);
        assert!(sign.status.success(), "{sign:?}");
        assert_eq!(fs::read(&cache).unwrap(), canonical);
    }
    assert!(
        run(&["qhs-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn qhs_key_lock_rejects_second_writer() {
    let directory = workspace();
    let public = directory.join("public.key");
    let private = directory.join("private.key");
    let message = directory.join("message.txt");
    let signature = directory.join("message.sig");
    fs::write(&message, b"qWp lock test\n").unwrap();

    let public_text = public.to_string_lossy().to_string();
    let private_text = private.to_string_lossy().to_string();
    let message_text = message.to_string_lossy().to_string();
    let signature_text = signature.to_string_lossy().to_string();

    assert!(
        run(&["qhs-keygen", &public_text, &private_text])
            .status
            .success()
    );
    let lock_path = format!("{private_text}.lock");
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();
    lock.try_lock().unwrap();

    let blocked = run(&["qhs-sign", &private_text, &message_text, &signature_text]);
    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("locked"));

    drop(lock);
    let mut released = None;
    for _ in 0..20 {
        let output = run(&["qhs-sign", &private_text, &message_text, &signature_text]);
        if output.status.success() {
            released = Some(output);
            break;
        }
        released = Some(output);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let released = released.unwrap();
    assert!(released.status.success(), "{released:?}");

    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn qhs31_tree_cache_sign_verify_end_to_end() {
    let directory = workspace();
    let public = directory.join("public.key");
    let private = directory.join("private.key");
    let message = directory.join("message.txt");
    let signature = directory.join("message.sig");
    fs::write(&message, b"qWp QHS-3.1 tree cache message\n").unwrap();

    let public_text = public.to_string_lossy().to_string();
    let private_text = private.to_string_lossy().to_string();
    let message_text = message.to_string_lossy().to_string();
    let signature_text = signature.to_string_lossy().to_string();

    let keygen = run(&["qhs31-keygen", &public_text, &private_text]);
    assert!(keygen.status.success(), "{keygen:?}");
    assert_eq!(fs::metadata(&public).unwrap().len(), 64);
    assert_eq!(fs::metadata(&private).unwrap().len(), 64);

    let tree_cache = directory.join("private.key.treecache");
    assert_eq!(fs::metadata(&tree_cache).unwrap().len(), 262_180);
    let tree_bytes = fs::read(&tree_cache).unwrap();
    assert_eq!(&tree_bytes[..4], &[3, 3, 12, 3]);
    let seed = private_seed(&private);
    let expected_fingerprint = derive_key32(b"qWp QHS-3.1 cache fingerprint", &seed).to_bytes();
    assert_eq!(&tree_bytes[4..36], &expected_fingerprint);
    let expected_tree_mac = cache_mac(&seed, b"qWp QHS-3.1 tree cache mac", &tree_bytes[..262_148]);
    assert_eq!(&tree_bytes[262_148..262_180], &expected_tree_mac);
    let state = directory.join("private.key.state");
    let state_bytes = fs::read(&state).unwrap();
    let expected_state_mac = cache_mac(&seed, b"qWp key state guard", &state_bytes[..6]);
    assert_eq!(&state_bytes[6..38], &expected_state_mac);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&tree_cache).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let old_time =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    fs::OpenOptions::new()
        .write(true)
        .open(&tree_cache)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(old_time))
        .unwrap();

    let sign = run(&["qhs31-sign", &private_text, &message_text, &signature_text]);
    assert!(sign.status.success(), "{sign:?}");
    assert_eq!(fs::metadata(&signature).unwrap().len(), 1832);
    assert_eq!(
        fs::metadata(&tree_cache).unwrap().modified().unwrap(),
        old_time
    );
    assert!(
        run(&["qhs31-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );
    assert!(
        run(&["qhs3-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let qhs3_sign = run(&["qhs3-sign", &private_text, &message_text, &signature_text]);
    assert!(qhs3_sign.status.success(), "{qhs3_sign:?}");
    assert!(
        run(&["qhs31-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let canonical_tree = fs::read(&tree_cache).unwrap();
    let seed = private_seed(&private);
    let mut corrupted_header = canonical_tree.clone();
    corrupted_header[3] = 0xff;
    let mac = cache_mac(
        &seed,
        b"qWp QHS-3.1 tree cache mac",
        &corrupted_header[..262_148],
    );
    corrupted_header[262_148..262_180].copy_from_slice(&mac);
    fs::write(&tree_cache, &corrupted_header).unwrap();
    let sign = run(&["qhs31-sign", &private_text, &message_text, &signature_text]);
    assert!(sign.status.success(), "{sign:?}");
    assert_eq!(fs::read(&tree_cache).unwrap(), canonical_tree);

    fs::remove_file(&tree_cache).unwrap();
    let sign_again = run(&["qhs31-sign", &private_text, &message_text, &signature_text]);
    assert!(sign_again.status.success(), "{sign_again:?}");
    assert!(tree_cache.exists());
    assert!(
        run(&["qhs31-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let mut tampered = fs::read(&signature).unwrap();
    tampered[10] ^= 1;
    fs::write(&signature, &tampered).unwrap();
    assert!(
        !run(&["qhs31-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    fs::write(&message, b"wrong message\n").unwrap();
    assert!(
        !run(&["qhs31-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let mut key_bytes = fs::read(&private).unwrap();
    key_bytes[36..38].copy_from_slice(&4096_u16.to_le_bytes());
    fs::write(&private, &key_bytes).unwrap();
    assert!(
        !run(&["qhs31-sign", &private_text, &message_text, &signature_text])
            .status
            .success()
    );

    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn qhs4_stateless_keygen_sign_verify_end_to_end() {
    let directory = workspace();
    let public = directory.join("public.key");
    let private = directory.join("private.key");
    let message = directory.join("message.txt");
    let signature = directory.join("message.sig");
    let missing = directory.join("missing.bin");
    fs::write(&message, b"qWp QHS-4 stateless CLI message\n").unwrap();

    let public_text = public.to_string_lossy().to_string();
    let private_text = private.to_string_lossy().to_string();
    let message_text = message.to_string_lossy().to_string();
    let signature_text = signature.to_string_lossy().to_string();
    let missing_text = missing.to_string_lossy().to_string();

    assert!(
        !run(&["qhs4-sign", &missing_text, &message_text, &signature_text])
            .status
            .success()
    );
    assert!(
        !run(&["qhs4-verify", &missing_text, &message_text, &signature_text])
            .status
            .success()
    );

    let keygen = run(&["qhs4-keygen", &public_text, &private_text]);
    assert!(keygen.status.success(), "{keygen:?}");
    assert_eq!(fs::metadata(&public).unwrap().len(), 68);
    assert_eq!(fs::metadata(&private).unwrap().len(), 68);
    let public_bytes = fs::read(&public).unwrap();
    let private_bytes = fs::read(&private).unwrap();
    assert_eq!(&public_bytes[..4], &[4, 4, 64, 0]);
    assert_eq!(&private_bytes[..4], &[4, 4, 64, 0]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&private).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    assert!(!directory.join("private.key.cache").exists());
    assert!(!directory.join("private.key.state").exists());
    assert!(!directory.join("private.key.treecache").exists());

    let old_time =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    fs::OpenOptions::new()
        .write(true)
        .open(&private)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(old_time))
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&private, fs::Permissions::from_mode(0o400)).unwrap();
    }

    let sign = run(&["qhs4-sign", &private_text, &message_text, &signature_text]);
    assert!(sign.status.success(), "{sign:?}");
    assert_eq!(fs::metadata(&signature).unwrap().len(), 18_216);
    let signature_bytes = fs::read(&signature).unwrap();
    assert_eq!(&signature_bytes[..4], &[4, 4, 64, 0]);
    assert_eq!(fs::read(&private).unwrap(), private_bytes);
    assert_eq!(
        fs::metadata(&private).unwrap().modified().unwrap(),
        old_time
    );
    assert!(!directory.join("private.key.cache").exists());
    assert!(!directory.join("private.key.state").exists());
    assert!(!directory.join("private.key.treecache").exists());

    let verify = run(&["qhs4-verify", &public_text, &message_text, &signature_text]);
    assert!(verify.status.success(), "{verify:?}");

    let mut tampered = signature_bytes.clone();
    tampered[10] ^= 1;
    fs::write(&signature, &tampered).unwrap();
    assert!(
        !run(&["qhs4-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    fs::write(&signature, &signature_bytes).unwrap();
    fs::write(&message, b"wrong message\n").unwrap();
    assert!(
        !run(&["qhs4-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    fs::write(&message, b"qWp QHS-4 stateless CLI message\n").unwrap();
    let wrong_public = directory.join("wrong-public.key");
    let mut wrong_public_bytes = public_bytes.clone();
    wrong_public_bytes[4] ^= 1;
    fs::write(&wrong_public, &wrong_public_bytes).unwrap();
    let wrong_public_text = wrong_public.to_string_lossy().to_string();
    assert!(
        !run(&[
            "qhs4-verify",
            &wrong_public_text,
            &message_text,
            &signature_text
        ])
        .status
        .success()
    );

    let overwrite = run(&["qhs4-keygen", &public_text, &private_text]);
    assert!(!overwrite.status.success());
    assert_eq!(fs::read(&private).unwrap(), private_bytes);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut bad_key = private_bytes.clone();
    bad_key[0] = 0;
    fs::write(&private, &bad_key).unwrap();
    assert!(
        !run(&["qhs4-sign", &private_text, &message_text, &signature_text])
            .status
            .success()
    );

    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn qhs41_parallel_keygen_sign_verify_end_to_end() {
    let directory = workspace();
    let public = directory.join("public.key");
    let private = directory.join("private.key");
    let message = directory.join("message.txt");
    let signature = directory.join("signature.sig");
    fs::write(&message, b"qWp QHS-4.1 parallel CLI message\n").unwrap();

    let public_text = public.to_string_lossy().to_string();
    let private_text = private.to_string_lossy().to_string();
    let message_text = message.to_string_lossy().to_string();
    let signature_text = signature.to_string_lossy().to_string();

    let keygen = run(&["qhs41-keygen", &public_text, &private_text]);
    assert!(keygen.status.success(), "{keygen:?}");
    assert_eq!(fs::metadata(&public).unwrap().len(), 68);
    assert_eq!(fs::metadata(&private).unwrap().len(), 68);
    let public_bytes = fs::read(&public).unwrap();
    let private_bytes = fs::read(&private).unwrap();
    assert_eq!(&public_bytes[..4], &[4, 4, 64, 0]);
    assert_eq!(&private_bytes[..4], &[4, 4, 64, 0]);
    assert!(!directory.join("private.key.cache").exists());
    assert!(!directory.join("private.key.state").exists());

    let old_time =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    fs::OpenOptions::new()
        .write(true)
        .open(&private)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(old_time))
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&private, fs::Permissions::from_mode(0o400)).unwrap();
    }

    let sign = run(&["qhs41-sign", &private_text, &message_text, &signature_text]);
    assert!(sign.status.success(), "{sign:?}");
    assert_eq!(fs::metadata(&signature).unwrap().len(), 18_216);
    let signature_bytes = fs::read(&signature).unwrap();
    assert_eq!(&signature_bytes[..4], &[4, 4, 64, 0]);
    assert_eq!(fs::read(&private).unwrap(), private_bytes);
    assert_eq!(
        fs::metadata(&private).unwrap().modified().unwrap(),
        old_time
    );
    assert!(!directory.join("private.key.cache").exists());
    assert!(!directory.join("private.key.state").exists());

    assert!(
        run(&["qhs41-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );
    assert!(
        run(&["qhs4-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let mut tampered = signature_bytes.clone();
    tampered[100] ^= 1;
    fs::write(&signature, &tampered).unwrap();
    assert!(
        !run(&["qhs41-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );
    assert!(
        !run(&["qhs4-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    fs::write(&signature, &signature_bytes).unwrap();
    fs::write(&message, b"wrong message\n").unwrap();
    assert!(
        !run(&["qhs41-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    fs::write(&message, b"qWp QHS-4.1 parallel CLI message\n").unwrap();
    let wrong_public = directory.join("wrong-public.key");
    let mut wrong_public_bytes = public_bytes.clone();
    wrong_public_bytes[4] ^= 1;
    fs::write(&wrong_public, &wrong_public_bytes).unwrap();
    let wrong_public_text = wrong_public.to_string_lossy().to_string();
    assert!(
        !run(&[
            "qhs41-verify",
            &wrong_public_text,
            &message_text,
            &signature_text
        ])
        .status
        .success()
    );

    let overwrite = run(&["qhs41-keygen", &public_text, &private_text]);
    assert!(!overwrite.status.success());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut bad_key = private_bytes.clone();
    bad_key[0] = 0;
    fs::write(&private, &bad_key).unwrap();
    assert!(
        !run(&["qhs41-sign", &private_text, &message_text, &signature_text])
            .status
            .success()
    );

    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn qhs42_compact_keygen_sign_verify_end_to_end() {
    let directory = workspace();
    let public = directory.join("public.key");
    let private = directory.join("private.key");
    let message = directory.join("message.txt");
    let signature = directory.join("signature.sig");
    fs::write(&message, b"qWp QHS-4.2 compact CLI message\n").unwrap();

    let public_text = public.to_string_lossy().to_string();
    let private_text = private.to_string_lossy().to_string();
    let message_text = message.to_string_lossy().to_string();
    let signature_text = signature.to_string_lossy().to_string();

    let keygen = run(&["qhs42-keygen", &public_text, &private_text]);
    assert!(keygen.status.success(), "{keygen:?}");
    assert_eq!(fs::metadata(&public).unwrap().len(), 68);
    assert_eq!(fs::metadata(&private).unwrap().len(), 68);
    let public_bytes = fs::read(&public).unwrap();
    let private_bytes = fs::read(&private).unwrap();
    assert_eq!(&public_bytes[..4], &[5, 5, 56, 0]);
    assert_eq!(&private_bytes[..4], &[5, 5, 56, 0]);
    assert!(!directory.join("private.key.cache").exists());
    assert!(!directory.join("private.key.state").exists());

    let old_time =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    fs::OpenOptions::new()
        .write(true)
        .open(&private)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(old_time))
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&private, fs::Permissions::from_mode(0o400)).unwrap();
    }

    let sign = run(&["qhs42-sign", &private_text, &message_text, &signature_text]);
    assert!(sign.status.success(), "{sign:?}");
    assert_eq!(fs::metadata(&signature).unwrap().len(), 14_344);
    let signature_bytes = fs::read(&signature).unwrap();
    assert_eq!(&signature_bytes[..4], &[5, 5, 56, 0]);
    assert_eq!(fs::read(&private).unwrap(), private_bytes);
    assert_eq!(
        fs::metadata(&private).unwrap().modified().unwrap(),
        old_time
    );
    assert!(!directory.join("private.key.cache").exists());
    assert!(!directory.join("private.key.state").exists());

    assert!(
        run(&["qhs42-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );
    assert!(
        !run(&["qhs4-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    let mut tampered = signature_bytes.clone();
    tampered[100] ^= 1;
    fs::write(&signature, &tampered).unwrap();
    assert!(
        !run(&["qhs42-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    fs::write(&signature, &signature_bytes).unwrap();
    fs::write(&message, b"wrong message\n").unwrap();
    assert!(
        !run(&["qhs42-verify", &public_text, &message_text, &signature_text])
            .status
            .success()
    );

    fs::write(&message, b"qWp QHS-4.2 compact CLI message\n").unwrap();
    let wrong_public = directory.join("wrong-public.key");
    let mut wrong_public_bytes = public_bytes.clone();
    wrong_public_bytes[4] ^= 1;
    fs::write(&wrong_public, &wrong_public_bytes).unwrap();
    let wrong_public_text = wrong_public.to_string_lossy().to_string();
    assert!(
        !run(&[
            "qhs42-verify",
            &wrong_public_text,
            &message_text,
            &signature_text
        ])
        .status
        .success()
    );

    let overwrite = run(&["qhs42-keygen", &public_text, &private_text]);
    assert!(!overwrite.status.success());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut bad_key = private_bytes.clone();
    bad_key[0] = 0;
    fs::write(&private, &bad_key).unwrap();
    assert!(
        !run(&["qhs42-sign", &private_text, &message_text, &signature_text])
            .status
            .success()
    );

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
    assert_eq!(canonical_cache.len(), 8260);
    let seed = private_seed(&private);

    for offset in 0..4 {
        let mut corrupted_header = canonical_cache.clone();
        corrupted_header[offset] = 0xff;
        let mac = cache_mac(&seed, b"qWp QHS-1 cache mac", &corrupted_header[..8_228]);
        corrupted_header[8_228..8_260].copy_from_slice(&mac);
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
