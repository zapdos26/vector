#![allow(dead_code)]

use std::collections::HashMap;
use std::time::{Duration, Instant};

const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// TTL-based cache for resolving numeric UIDs to usernames.
///
/// Avoids repeated NSS/SSSD lookups (which can hit LDAP and take 50-200ms
/// per call in IDM/IPA environments) by caching UID→username mappings.
pub struct UidCache {
    cache: HashMap<u32, CacheEntry>,
    ttl: Duration,
}

struct CacheEntry {
    username: String,
    inserted_at: Instant,
}

impl UidCache {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            ttl: DEFAULT_TTL,
        }
    }

    /// Resolves a UID to a username, using the cache if available.
    /// Falls back to the stringified UID on lookup failure.
    #[cfg(unix)]
    pub fn resolve(&mut self, uid: u32) -> String {
        let now = Instant::now();

        if let Some(entry) = self.cache.get(&uid) {
            if now.duration_since(entry.inserted_at) < self.ttl {
                return entry.username.clone();
            }
        }

        let username = lookup_username(uid).unwrap_or_else(|| uid.to_string());
        self.cache.insert(
            uid,
            CacheEntry {
                username: username.clone(),
                inserted_at: now,
            },
        );
        username
    }

    #[cfg(not(unix))]
    pub fn resolve(&mut self, uid: u32) -> String {
        uid.to_string()
    }
}

impl Default for UidCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve a UID to a username via `getpwuid_r`.
#[cfg(unix)]
fn lookup_username(uid: u32) -> Option<String> {
    use nix::libc;
    use std::ffi::CStr;
    use std::mem::MaybeUninit;

    let mut buf = vec![0u8; 1024];
    let mut pwd = MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut::<libc::passwd>();

    loop {
        let ret = unsafe {
            libc::getpwuid_r(
                uid,
                pwd.as_mut_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };

        if ret == libc::ERANGE {
            // Buffer too small, grow and retry
            buf.resize(buf.len() * 2, 0);
            continue;
        }

        if ret != 0 || result.is_null() {
            return None;
        }

        let pw = unsafe { pwd.assume_init() };
        let name = unsafe { CStr::from_ptr(pw.pw_name) };
        return name.to_str().ok().map(String::from);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uid_cache_returns_consistent_results() {
        let mut cache = UidCache::new();
        let result1 = cache.resolve(0);
        let result2 = cache.resolve(0);
        assert_eq!(result1, result2);
        // UID 0 should resolve to "root" on Unix
        #[cfg(unix)]
        assert_eq!(result1, "root");
    }

    #[test]
    fn test_uid_cache_unknown_uid_returns_string() {
        let mut cache = UidCache::new();
        // Very high UID unlikely to exist
        let result = cache.resolve(4_294_967_294);
        assert_eq!(result, "4294967294");
    }
}
