//! Unified secret resolution & optional OS Keyring storage (`keyring://rship/<slot>`).
//!
//! Any secret field in [`crate::config::AppConfig`] across any storage provider can hold
//! either a direct value or a `keyring://rship/<slot>` reference. Enable the `keyring`
//! Cargo feature to resolve and persist secrets in the platform keyring:
//! - Windows Credential Manager
//! - macOS Keychain Services
//! - Linux Secret Service

use rship_core::{Error, Result};

/// Service namespace used for OS Keyring entries.
pub const KEYRING_SERVICE: &str = "rship";

/// URI prefix identifying a secret stored in the OS Keyring.
pub const KEYRING_PREFIX: &str = "keyring://rship/";

/// Returns `true` when `val` is a `keyring://rship/<slot>` pointer.
pub fn is_keyring_ref(val: &str) -> bool {
    val.starts_with(KEYRING_PREFIX)
}

#[cfg(feature = "keyring")]
fn map_keyring_error(action: &str, err: keyring::Error) -> Error {
    match err {
        keyring::Error::NoEntry => Error::permission_denied(format!("{action}: {err}")),
        keyring::Error::NoStorageAccess(_)
        | keyring::Error::PlatformFailure(_)
        | keyring::Error::BadEncoding(_)
        | keyring::Error::TooLong(_, _)
        | keyring::Error::Invalid(_, _) => Error::config(format!("{action}: {err}")),
        _ => Error::permission_denied(format!("{action}: {err}")),
    }
}

/// Resolve a potentially keyring-backed secret value into its runtime plaintext.
pub fn resolve_secret(raw: &str) -> Result<String> {
    if let Some(slot) = raw.strip_prefix(KEYRING_PREFIX) {
        #[cfg(feature = "keyring")]
        {
            let entry = keyring::Entry::new(KEYRING_SERVICE, slot).map_err(|e| {
                map_keyring_error(&format!("initialize OS keyring entry `{slot}`"), e)
            })?;
            entry
                .get_password()
                .map_err(|e| map_keyring_error(&format!("read secret `{slot}` from OS keyring"), e))
        }
        #[cfg(not(feature = "keyring"))]
        {
            Err(Error::unsupported(format!(
                "secret `{KEYRING_PREFIX}{slot}` requires the `keyring` Cargo feature on `rship`"
            )))
        }
    } else {
        Ok(raw.to_string())
    }
}

/// Resolve an optional secret value, preserving `None`.
pub fn resolve_opt_secret(opt: Option<&str>) -> Result<Option<String>> {
    match opt {
        Some(v) => Ok(Some(resolve_secret(v)?)),
        None => Ok(None),
    }
}

/// Select the persisted secret value (preferring a non-empty override over an existing
/// configured value) and resolve it for immediate runtime use.
///
/// - When reusing an existing `keyring://rship/<slot>` pointer with no override, `stored`
///   keeps the `keyring://` pointer while `resolved` holds the plaintext secret for runtime use.
/// - When rotating a secret with a new plaintext override on a field that is already
///   `keyring://rship/<slot>`, `updater` updates `<slot>` in place and preserves the `keyring://`
///   pointer in config (preventing plaintext downgrades and orphaned keyring entries).
pub fn resolve_stored_and_runtime_secret_with<R, U>(
    override_arg: Option<String>,
    existing: Option<&str>,
    mut resolver: R,
    mut updater: U,
) -> Result<Option<(String, String)>>
where
    R: FnMut(&str) -> Result<String>,
    U: FnMut(&str, &str) -> Result<String>,
{
    let new_val = override_arg.filter(|s| !s.trim().is_empty());
    let prev = existing.filter(|s| !s.trim().is_empty());

    match (new_val, prev) {
        (Some(new_val), Some(prev_val)) => {
            if let Some(slot) = prev_val.strip_prefix(KEYRING_PREFIX)
                && !is_keyring_ref(&new_val)
            {
                let reference = updater(slot, &new_val)?;
                return Ok(Some((reference, new_val)));
            }
            let resolved = resolver(&new_val)?;
            Ok(Some((new_val, resolved)))
        }
        (Some(new_val), None) => {
            let resolved = resolver(&new_val)?;
            Ok(Some((new_val, resolved)))
        }
        (None, Some(prev_val)) => {
            let resolved = resolver(prev_val)?;
            Ok(Some((prev_val.to_string(), resolved)))
        }
        (None, None) => Ok(None),
    }
}

/// Update an existing `keyring://rship/<slot>` entry in place if `new_val` replaces a
/// keyring-backed secret on re-configuration, or clean up the old keyring entry if the
/// secret field is explicitly cleared.
pub fn preserve_or_rotate_secret(
    new_val: Option<String>,
    existing: Option<&str>,
) -> Result<Option<String>> {
    match (new_val, existing) {
        (Some(v), Some(prev))
            if !v.trim().is_empty() && !is_keyring_ref(&v) && prev.starts_with(KEYRING_PREFIX) =>
        {
            let slot = &prev[KEYRING_PREFIX.len()..];
            Ok(Some(store_secret(slot, &v)?))
        }
        (None, Some(prev)) => {
            delete_secret_if_ref(prev);
            Ok(None)
        }
        (other, _) => Ok(other),
    }
}

/// Store a secret in the OS Keyring and return its `keyring://rship/<slot>` pointer.
pub fn store_secret(slot: &str, value: &str) -> Result<String> {
    #[cfg(feature = "keyring")]
    {
        let entry = keyring::Entry::new(KEYRING_SERVICE, slot)
            .map_err(|e| map_keyring_error(&format!("initialize OS keyring entry `{slot}`"), e))?;
        entry
            .set_password(value)
            .map_err(|e| map_keyring_error(&format!("save secret `{slot}` to OS keyring"), e))?;
        Ok(format!("{KEYRING_PREFIX}{slot}"))
    }
    #[cfg(not(feature = "keyring"))]
    {
        let _ = value;
        Err(Error::unsupported(format!(
            "storing secret `{slot}` in OS keyring requires the `keyring` Cargo feature on `rship`"
        )))
    }
}

/// Best-effort deletion of an OS Keyring entry if `raw` is a `keyring://` reference.
pub fn delete_secret_if_ref(raw: &str) {
    #[cfg(feature = "keyring")]
    {
        if let Some(slot) = raw.strip_prefix(KEYRING_PREFIX)
            && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, slot)
        {
            let _ = entry.inner.delete_credential();
        }
    }
    #[cfg(not(feature = "keyring"))]
    {
        let _ = raw;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn passes_through_direct_secret_and_recognizes_keyring_refs() {
        assert!(!is_keyring_ref("plain-secret"));
        assert!(is_keyring_ref("keyring://rship/my-s3.secret_access_key"));
        assert_eq!(resolve_secret("plain-secret").unwrap(), "plain-secret");
    }

    #[test]
    fn reauth_resolves_and_rotates_keyring_ref_while_preserving_pointer() {
        let store = RefCell::new(std::collections::HashMap::from([(
            "gdrive.client_secret".to_string(),
            "GOCSPX-decrypted-secret".to_string(),
        )]));

        let resolver = |raw: &str| -> Result<String> {
            if let Some(slot) = raw.strip_prefix(KEYRING_PREFIX) {
                Ok(store
                    .borrow()
                    .get(slot)
                    .cloned()
                    .expect("slot present in mock keyring"))
            } else {
                Ok(raw.to_string())
            }
        };
        let updater = |slot: &str, value: &str| -> Result<String> {
            store
                .borrow_mut()
                .insert(slot.to_string(), value.to_string());
            Ok(format!("{KEYRING_PREFIX}{slot}"))
        };

        let (stored, runtime) = resolve_stored_and_runtime_secret_with(
            None,
            Some("keyring://rship/gdrive.client_secret"),
            &resolver,
            &updater,
        )
        .unwrap()
        .unwrap();
        assert_eq!(stored, "keyring://rship/gdrive.client_secret");
        assert_eq!(runtime, "GOCSPX-decrypted-secret");

        let (stored_rot, runtime_rot) = resolve_stored_and_runtime_secret_with(
            Some("GOCSPX-rotated-secret".to_string()),
            Some("keyring://rship/gdrive.client_secret"),
            &resolver,
            &updater,
        )
        .unwrap()
        .unwrap();
        assert_eq!(stored_rot, "keyring://rship/gdrive.client_secret");
        assert_eq!(runtime_rot, "GOCSPX-rotated-secret");
        assert_eq!(
            store
                .borrow()
                .get("gdrive.client_secret")
                .map(String::as_str),
            Some("GOCSPX-rotated-secret")
        );
    }
}
