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
    last_eviction: Instant,
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
            last_eviction: Instant::now(),
        }
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            cache: HashMap::new(),
            ttl,
            last_eviction: Instant::now(),
        }
    }

    /// Resolves a UID to a username, using the cache if available.
    /// Falls back to the stringified UID on lookup failure.
    /// Periodically evicts expired entries to prevent unbounded growth.
    #[cfg(unix)]
    pub fn resolve(&mut self, uid: u32) -> String {
        let now = Instant::now();

        // Evict expired entries once per TTL period
        if now.duration_since(self.last_eviction) >= self.ttl {
            self.cache
                .retain(|_, entry| now.duration_since(entry.inserted_at) < self.ttl);
            self.last_eviction = now;
        }

        if let Some(entry) = self.cache.get(&uid)
            && now.duration_since(entry.inserted_at) < self.ttl
        {
            return entry.username.clone();
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
    fn test_uid_cache_resolves_root() {
        let mut cache = UidCache::new();
        let result = cache.resolve(0);
        #[cfg(unix)]
        assert_eq!(result, "root");
    }

    #[test]
    fn test_uid_cache_unknown_uid_returns_string() {
        let mut cache = UidCache::new();
        let result = cache.resolve(4_294_967_294);
        assert_eq!(result, "4294967294");
    }

    #[test]
    fn test_uid_cache_stores_entry() {
        let mut cache = UidCache::new();
        assert!(cache.cache.is_empty());
        cache.resolve(0);
        assert_eq!(cache.cache.len(), 1);
        // Second resolve should reuse the cached entry, not add a new one
        cache.resolve(0);
        assert_eq!(cache.cache.len(), 1);
    }

    #[test]
    fn test_uid_cache_respects_ttl_expiry() {
        // A zero-TTL cache means every entry is immediately expired.
        let mut cache = UidCache::with_ttl(Duration::from_secs(0));
        cache.resolve(0);
        let first_inserted = cache.cache.get(&0).unwrap().inserted_at;

        // Small sleep so the next Instant is strictly later
        std::thread::sleep(Duration::from_millis(5));

        cache.resolve(0);
        let second_inserted = cache.cache.get(&0).unwrap().inserted_at;

        // With TTL=0 the entry was expired and re-inserted, so the
        // timestamp must have advanced.
        assert!(
            second_inserted > first_inserted,
            "expired entry should have been re-inserted with a newer timestamp"
        );
    }

    #[test]
    fn test_uid_cache_serves_from_cache_within_ttl() {
        let mut cache = UidCache::with_ttl(Duration::from_secs(600));
        cache.resolve(0);
        let first_inserted = cache.cache.get(&0).unwrap().inserted_at;

        std::thread::sleep(Duration::from_millis(5));

        cache.resolve(0);
        let second_inserted = cache.cache.get(&0).unwrap().inserted_at;

        // With a long TTL the cached entry should NOT have been replaced.
        assert_eq!(
            first_inserted, second_inserted,
            "cached entry should be reused within TTL"
        );
    }

    #[test]
    fn test_uid_cache_evicts_expired_entries() {
        let mut cache = UidCache::with_ttl(Duration::from_millis(200));
        // Populate with two UIDs (within TTL window)
        cache.resolve(0);
        cache.resolve(4_294_967_294);
        assert_eq!(cache.cache.len(), 2);

        // Sleep well past TTL, then resolve a different UID to trigger eviction
        std::thread::sleep(Duration::from_millis(300));
        cache.resolve(1);

        // The two old entries should have been evicted; only UID 1 remains
        assert_eq!(cache.cache.len(), 1);
        assert!(cache.cache.contains_key(&1));
    }
}
