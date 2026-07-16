// nkct-keyring-shim — a C-ABI wrapper over nkCryptoTool-rust's keyring
// (`keyring.db`, the redb my-identities store), so the C++ nkCryptoTool can
// share ONE keyring.db with the Rust binary. All crypto/format logic is reused
// from nk-crypto-tool, so what C++ writes is byte-identical to what Rust writes.
//
// C ABI is blocking and string/byte based. Result: 0 = ok, negative = error.
// Any returned *mut c_char must be freed with nkct_kr_string_free.

use std::ffi::{c_char, c_int, CStr, CString};
use std::path::Path;

use nk_crypto_tool::keyring::{self, KeyringStore};

pub const KR_OK: c_int = 0;
pub const KR_ERR: c_int = -1;
pub const KR_NOT_FOUND: c_int = -2;

/// # Safety: `s` must be a pointer from this library, or null.
#[no_mangle]
pub unsafe extern "C" fn nkct_kr_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

unsafe fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        None
    } else {
        CStr::from_ptr(p).to_str().ok()
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolve the my-identities slot role, mirroring the Rust CLI's
/// resolve_my_key_role: ML-KEM→enc, ML-DSA→sign implied; P-256 must be told.
/// `role_hint` may be "enc" / "sign" / "".
fn resolve_role(
    inferred: Option<&'static str>,
    role_hint: &str,
    algo: &str,
) -> Result<&'static str, String> {
    match (inferred, role_hint) {
        (Some(r), "") => Ok(r),
        (Some(r), h) if h == r => Ok(r),
        (Some(r), h) => Err(format!("--key-role {h} contradicts the key ({algo} is a {r} key)")),
        (None, "enc") => Ok("enc"),
        (None, "sign") => Ok("sign"),
        (None, "") => Err(format!("{algo} serves both roles — specify enc|sign")),
        (None, other) => Err(format!("--key-role must be enc or sign, got {other}")),
    }
}

fn open(db_path: &str) -> Result<KeyringStore, String> {
    if let Some(parent) = Path::new(db_path).parent().filter(|p| !p.as_os_str().is_empty()) {
        let _ = std::fs::create_dir_all(parent);
    }
    KeyringStore::open(Path::new(db_path)).map_err(|e| format!("open {db_path}: {e}"))
}

/// Generate a key pair straight into keyring.db (no key file). `algo` one of
/// ML-KEM-512/768/1024, ML-DSA-44/65/87, P-256. `role_hint` "enc"/"sign"/"".
/// `handle` e.g. "me". Returns KR_OK; writes the 64-hex fingerprint (NUL-term)
/// to `out_fp_hex` if non-null (caller frees with nkct_kr_string_free).
///
/// # Safety: all `*const c_char` NUL-terminated or null; `out_fp_hex` a
/// writable `*mut *mut c_char` or null.
#[no_mangle]
pub unsafe extern "C" fn nkct_kr_gen_my_key(
    db_path: *const c_char,
    algo: *const c_char,
    role_hint: *const c_char,
    handle: *const c_char,
    passphrase: *const c_char,
    out_fp_hex: *mut *mut c_char,
) -> c_int {
    let r = (|| -> Result<String, String> {
        let db = cstr(db_path).ok_or("db_path")?;
        let algo = cstr(algo).ok_or("algo")?;
        let role_hint = cstr(role_hint).unwrap_or("");
        let handle = cstr(handle).unwrap_or("me");
        let pass = cstr(passphrase).ok_or("passphrase")?;
        if pass.is_empty() {
            return Err("gen-my-key requires a passphrase".into());
        }
        // Generate + wrap to encrypted PKCS#8 — reusing nk-crypto-tool so the
        // bytes match the Rust CLI's gen-my-key exactly.
        let enc_der = match algo {
            "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024" => {
                let (raw, _, _) = nk_crypto_tool::backend::pqc_keygen_kem(algo).map_err(|e| e.to_string())?;
                nk_crypto_tool::utils::wrap_pqc_priv_to_pkcs8_encrypted(&raw, algo, pass).map_err(|e| e.to_string())?
            }
            "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87" => {
                let (raw, _, _) = nk_crypto_tool::backend::pqc_keygen_dsa(algo).map_err(|e| e.to_string())?;
                nk_crypto_tool::utils::wrap_pqc_priv_to_pkcs8_encrypted(&raw, algo, pass).map_err(|e| e.to_string())?
            }
            "P-256" => {
                let (priv_der, _) = nk_crypto_tool::backend::generate_ecc_key_pair("prime256v1").map_err(|e| e.to_string())?;
                nk_crypto_tool::utils::encrypt_pkcs8_der(&priv_der, pass).map_err(|e| e.to_string())?
            }
            other => return Err(format!("unsupported --key-algo {other}")),
        };
        let pem = nk_crypto_tool::utils::wrap_to_pem(&enc_der, "ENCRYPTED PRIVATE KEY");
        let (algo, inferred, rec) =
            keyring::build_my_identity_record(pem.as_bytes(), pass, None, now_secs())
                .map_err(|e| e.to_string())?;
        let role = resolve_role(inferred, role_hint, &algo)?;
        let store = open(db)?;
        store.put_my_identity(handle, role, &algo, &rec).map_err(|e| e.to_string())?;
        Ok(hex::encode(rec.fingerprint))
    })();
    match r {
        Ok(fp) => {
            if !out_fp_hex.is_null() {
                *out_fp_hex = CString::new(fp).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
            }
            KR_OK
        }
        Err(_) => KR_ERR,
    }
}

/// Import an existing encrypted-PKCS#8-PEM key into keyring.db. `pem` points to
/// `pem_len` bytes. Same validation as the Rust import-my-key.
///
/// # Safety: pointers valid; `pem` `pem_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn nkct_kr_import_my_key(
    db_path: *const c_char,
    pem: *const u8,
    pem_len: usize,
    role_hint: *const c_char,
    handle: *const c_char,
    passphrase: *const c_char,
) -> c_int {
    let r = (|| -> Result<(), String> {
        let db = cstr(db_path).ok_or("db_path")?;
        let role_hint = cstr(role_hint).unwrap_or("");
        let handle = cstr(handle).unwrap_or("me");
        let pass = cstr(passphrase).ok_or("passphrase")?;
        if pem.is_null() {
            return Err("pem".into());
        }
        let pem_bytes = std::slice::from_raw_parts(pem, pem_len);
        let (algo, inferred, rec) =
            keyring::build_my_identity_record(pem_bytes, pass, None, now_secs())
                .map_err(|e| e.to_string())?;
        let role = resolve_role(inferred, role_hint, &algo)?;
        let store = open(db)?;
        store.put_my_identity(handle, role, &algo, &rec).map_err(|e| e.to_string())?;
        Ok(())
    })();
    if r.is_ok() { KR_OK } else { KR_ERR }
}

/// Fetch + unlock a stored identity. On success writes the still-encrypted
/// PKCS#8 PEM (the same bytes a key file holds) to `out_pem` (NUL-terminated,
/// caller frees). The unlock re-derives the public half and checks the binding,
/// so a tampered record fails. Returns KR_OK / KR_NOT_FOUND / KR_ERR.
///
/// # Safety: pointers NUL-terminated/null; `out_pem` writable or null.
#[no_mangle]
pub unsafe extern "C" fn nkct_kr_get_unlocked(
    db_path: *const c_char,
    handle: *const c_char,
    role: *const c_char,
    algo: *const c_char,
    passphrase: *const c_char,
    out_pem: *mut *mut c_char,
) -> c_int {
    let db = match cstr(db_path) { Some(s) => s, None => return KR_ERR };
    let handle = cstr(handle).unwrap_or("me");
    let role = match cstr(role) { Some(s) => s, None => return KR_ERR };
    let algo = match cstr(algo) { Some(s) => s, None => return KR_ERR };
    let pass = match cstr(passphrase) { Some(s) => s, None => return KR_ERR };
    if !Path::new(db).exists() {
        return KR_NOT_FOUND;
    }
    let store = match open(db) { Ok(s) => s, Err(_) => return KR_ERR };
    let rec = match store.get_my_identity(handle, role, algo) {
        Ok(Some(r)) => r,
        Ok(None) => return KR_NOT_FOUND,
        Err(_) => return KR_ERR,
    };
    match keyring::unlock_and_verify_identity(&rec, algo, pass) {
        Ok(pem) => {
            if !out_pem.is_null() {
                *out_pem = CString::new(pem.as_str())
                    .map(|s| s.into_raw())
                    .unwrap_or(std::ptr::null_mut());
            }
            KR_OK
        }
        Err(_) => KR_ERR,
    }
}

/// List slots as newline-separated `handle:role:algo:fp8hex` lines (NUL-term,
/// caller frees). Metadata only — no passphrase, no private key.
///
/// # Safety: `db_path` NUL-terminated; returns null on error.
#[no_mangle]
pub unsafe extern "C" fn nkct_kr_list(db_path: *const c_char) -> *mut c_char {
    let db = match cstr(db_path) { Some(s) => s, None => return std::ptr::null_mut() };
    if !Path::new(db).exists() {
        return CString::new("").map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
    }
    let store = match open(db) { Ok(s) => s, Err(_) => return std::ptr::null_mut() };
    let list = match store.list_my_identities() { Ok(v) => v, Err(_) => return std::ptr::null_mut() };
    let mut out = String::new();
    for (h, ro, al, rec) in list {
        out.push_str(&format!("{h}:{ro}:{al}:{}\n", hex::encode(&rec.fingerprint[..8])));
    }
    CString::new(out).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}
