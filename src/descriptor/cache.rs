//! Descriptor caching for improved performance.
//!
//! This module provides in-memory caching of Tor descriptors to avoid
//! repeated downloads from the Tor process. Caching significantly improves
//! performance for applications that frequently query descriptor information.
//!
//! # Overview
//!
//! The descriptor cache stores parsed descriptors with automatic expiration
//! based on their validity periods. Different descriptor types have different
//! cache lifetimes:
//!
//! - **Consensus documents**: 3 hours (typical validity period)
//! - **Server descriptors**: 24 hours (published daily)
//! - **Microdescriptors**: 24 hours (referenced by consensus)
//!
//! # Thread Safety
//!
//! The cache is thread-safe and can be shared across multiple tasks using
//! `Arc<DescriptorCache>`. All operations use interior mutability with
//! `RwLock` for concurrent access.
//!
//! # Example
//!
//! ```rust
//! use stem_rs::descriptor::cache::DescriptorCache;
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let cache = DescriptorCache::new()
//!     .with_consensus_ttl(Duration::from_secs(3 * 3600))
//!     .with_max_entries(1000);
//!
//! // Cache is automatically used by Controller methods
//! // when enabled via Controller::with_descriptor_cache()
//! # Ok(())
//! # }
//! ```
//!
//! # Memory Management
//!
//! The cache automatically evicts expired entries and enforces a maximum
//! entry limit to prevent unbounded memory growth. When the limit is reached,
//! the least recently used entries are evicted.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use super::{Microdescriptor, NetworkStatusDocument, ServerDescriptor};

/// Default TTL for consensus documents (3 hours).
const DEFAULT_CONSENSUS_TTL: Duration = Duration::from_secs(3 * 3600);

/// Default TTL for server descriptors (24 hours).
const DEFAULT_SERVER_DESCRIPTOR_TTL: Duration = Duration::from_secs(24 * 3600);

/// Default TTL for microdescriptors (24 hours).
const DEFAULT_MICRODESCRIPTOR_TTL: Duration = Duration::from_secs(24 * 3600);

/// Default maximum number of cached entries.
const DEFAULT_MAX_ENTRIES: usize = 1000;

/// A cached entry with expiration time.
#[derive(Debug, Clone)]
struct CacheEntry<T> {
    value: T,
    expires_at: Instant,
    last_accessed: Instant,
}

impl<T> CacheEntry<T> {
    fn new(value: T, ttl: Duration) -> Self {
        let now = Instant::now();
        Self {
            value,
            expires_at: now + ttl,
            last_accessed: now,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    fn touch(&mut self) {
        self.last_accessed = Instant::now();
    }
}

/// In-memory cache for Tor descriptors.
///
/// Provides automatic expiration and LRU eviction for efficient memory usage.
/// The cache is thread-safe and can be shared across multiple tasks.
///
/// # Example
///
/// ```rust
/// use stem_rs::descriptor::cache::DescriptorCache;
/// use std::time::Duration;
///
/// let cache = DescriptorCache::new()
///     .with_consensus_ttl(Duration::from_secs(3600))
///     .with_max_entries(500);
///
/// // Cache is used automatically by Controller when enabled
/// ```
#[derive(Debug, Clone)]
pub struct DescriptorCache {
    inner: Arc<RwLock<CacheInner>>,
}

#[derive(Debug)]
struct CacheInner {
    consensus: Option<CacheEntry<NetworkStatusDocument>>,
    server_descriptors: HashMap<String, CacheEntry<ServerDescriptor>>,
    microdescriptors: HashMap<String, CacheEntry<Microdescriptor>>,
    consensus_ttl: Duration,
    server_descriptor_ttl: Duration,
    microdescriptor_ttl: Duration,
    max_entries: usize,
    stats: CacheStats,
}

/// Statistics about cache performance.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Number of evictions due to expiration.
    pub expirations: u64,
    /// Number of evictions due to size limit.
    pub evictions: u64,
}

impl CacheStats {
    /// Returns the cache hit rate as a percentage (0.0 to 100.0).
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

impl DescriptorCache {
    /// Creates a new descriptor cache with default settings.
    ///
    /// Default settings:
    /// - Consensus TTL: 3 hours
    /// - Server descriptor TTL: 24 hours
    /// - Microdescriptor TTL: 24 hours
    /// - Max entries: 1000
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(CacheInner {
                consensus: None,
                server_descriptors: HashMap::new(),
                microdescriptors: HashMap::new(),
                consensus_ttl: DEFAULT_CONSENSUS_TTL,
                server_descriptor_ttl: DEFAULT_SERVER_DESCRIPTOR_TTL,
                microdescriptor_ttl: DEFAULT_MICRODESCRIPTOR_TTL,
                max_entries: DEFAULT_MAX_ENTRIES,
                stats: CacheStats::default(),
            })),
        }
    }

    /// Sets the TTL for consensus documents.
    pub fn with_consensus_ttl(self, ttl: Duration) -> Self {
        self.inner.write().unwrap().consensus_ttl = ttl;
        self
    }

    /// Sets the TTL for server descriptors.
    pub fn with_server_descriptor_ttl(self, ttl: Duration) -> Self {
        self.inner.write().unwrap().server_descriptor_ttl = ttl;
        self
    }

    /// Sets the TTL for microdescriptors.
    pub fn with_microdescriptor_ttl(self, ttl: Duration) -> Self {
        self.inner.write().unwrap().microdescriptor_ttl = ttl;
        self
    }

    /// Sets the maximum number of cached entries.
    ///
    /// When this limit is reached, the least recently used entries are evicted.
    pub fn with_max_entries(self, max: usize) -> Self {
        self.inner.write().unwrap().max_entries = max;
        self
    }

    /// Retrieves the cached consensus document if available and not expired.
    pub fn get_consensus(&self) -> Option<NetworkStatusDocument> {
        let mut inner = self.inner.write().unwrap();

        if let Some(entry) = &mut inner.consensus {
            if entry.is_expired() {
                inner.consensus = None;
                inner.stats.expirations += 1;
                inner.stats.misses += 1;
                return None;
            }
            entry.touch();
            let value = entry.value.clone();
            inner.stats.hits += 1;
            return Some(value);
        }

        inner.stats.misses += 1;
        None
    }

    /// Stores a consensus document in the cache.
    pub fn put_consensus(&self, consensus: NetworkStatusDocument) {
        let mut inner = self.inner.write().unwrap();
        let ttl = inner.consensus_ttl;
        inner.consensus = Some(CacheEntry::new(consensus, ttl));
    }

    /// Retrieves a cached server descriptor by fingerprint.
    pub fn get_server_descriptor(&self, fingerprint: &str) -> Option<ServerDescriptor> {
        let mut inner = self.inner.write().unwrap();

        let is_expired = inner
            .server_descriptors
            .get(fingerprint)
            .map(|entry| entry.is_expired())
            .unwrap_or(false);

        if is_expired {
            inner.server_descriptors.remove(fingerprint);
            inner.stats.expirations += 1;
            inner.stats.misses += 1;
            return None;
        }

        if let Some(entry) = inner.server_descriptors.get_mut(fingerprint) {
            entry.touch();
            let value = entry.value.clone();
            inner.stats.hits += 1;
            return Some(value);
        }

        inner.stats.misses += 1;
        None
    }

    /// Stores a server descriptor in the cache.
    pub fn put_server_descriptor(&self, fingerprint: String, descriptor: ServerDescriptor) {
        let mut inner = self.inner.write().unwrap();
        let ttl = inner.server_descriptor_ttl;

        inner.evict_if_needed();
        inner
            .server_descriptors
            .insert(fingerprint, CacheEntry::new(descriptor, ttl));
    }

    /// Retrieves a cached microdescriptor by digest.
    pub fn get_microdescriptor(&self, digest: &str) -> Option<Microdescriptor> {
        let mut inner = self.inner.write().unwrap();

        let is_expired = inner
            .microdescriptors
            .get(digest)
            .map(|entry| entry.is_expired())
            .unwrap_or(false);

        if is_expired {
            inner.microdescriptors.remove(digest);
            inner.stats.expirations += 1;
            inner.stats.misses += 1;
            return None;
        }

        if let Some(entry) = inner.microdescriptors.get_mut(digest) {
            entry.touch();
            let value = entry.value.clone();
            inner.stats.hits += 1;
            return Some(value);
        }

        inner.stats.misses += 1;
        None
    }

    /// Stores a microdescriptor in the cache.
    pub fn put_microdescriptor(&self, digest: String, descriptor: Microdescriptor) {
        let mut inner = self.inner.write().unwrap();
        let ttl = inner.microdescriptor_ttl;

        inner.evict_if_needed();
        inner
            .microdescriptors
            .insert(digest, CacheEntry::new(descriptor, ttl));
    }

    /// Clears all cached entries.
    pub fn clear(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.consensus = None;
        inner.server_descriptors.clear();
        inner.microdescriptors.clear();
    }

    /// Removes expired entries from the cache.
    pub fn evict_expired(&self) {
        let mut inner = self.inner.write().unwrap();

        if let Some(entry) = &inner.consensus {
            if entry.is_expired() {
                inner.consensus = None;
                inner.stats.expirations += 1;
            }
        }

        let mut expired_server_keys = Vec::new();
        for (key, entry) in &inner.server_descriptors {
            if entry.is_expired() {
                expired_server_keys.push(key.clone());
            }
        }
        for key in expired_server_keys {
            inner.server_descriptors.remove(&key);
            inner.stats.expirations += 1;
        }

        let mut expired_micro_keys = Vec::new();
        for (key, entry) in &inner.microdescriptors {
            if entry.is_expired() {
                expired_micro_keys.push(key.clone());
            }
        }
        for key in expired_micro_keys {
            inner.microdescriptors.remove(&key);
            inner.stats.expirations += 1;
        }
    }

    /// Returns the current cache statistics.
    pub fn stats(&self) -> CacheStats {
        self.inner.read().unwrap().stats.clone()
    }

    /// Returns the number of entries currently in the cache.
    pub fn len(&self) -> usize {
        let inner = self.inner.read().unwrap();
        let consensus_count = if inner.consensus.is_some() { 1 } else { 0 };
        consensus_count + inner.server_descriptors.len() + inner.microdescriptors.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl CacheInner {
    fn evict_if_needed(&mut self) {
        let total_entries = self.server_descriptors.len() + self.microdescriptors.len();

        if total_entries >= self.max_entries {
            self.evict_lru();
        }
    }

    fn evict_lru(&mut self) {
        let mut all_entries: Vec<(String, Instant, bool)> = Vec::new();

        for (key, entry) in &self.server_descriptors {
            all_entries.push((key.clone(), entry.last_accessed, false));
        }

        for (key, entry) in &self.microdescriptors {
            all_entries.push((key.clone(), entry.last_accessed, true));
        }

        all_entries.sort_by_key(|(_, accessed, _)| *accessed);

        let total_entries = self.server_descriptors.len() + self.microdescriptors.len();
        let to_evict = if total_entries >= self.max_entries {
            (total_entries - self.max_entries + 1).max(1)
        } else {
            return;
        };

        for (key, _, is_micro) in all_entries.iter().take(to_evict) {
            if *is_micro {
                self.microdescriptors.remove(key);
            } else {
                self.server_descriptors.remove(key);
            }
            self.stats.evictions += 1;
        }
    }
}

impl Default for DescriptorCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::Descriptor;
    use chrono::Utc;

    fn create_test_consensus() -> NetworkStatusDocument {
        NetworkStatusDocument::parse(
            r#"network-status-version 3
vote-status consensus
consensus-method 1
valid-after 2023-01-01 00:00:00
fresh-until 2023-01-01 01:00:00
valid-until 2023-01-01 03:00:00
"#,
        )
        .unwrap()
    }

    fn create_test_server_descriptor() -> ServerDescriptor {
        ServerDescriptor::new(
            "TestRelay".to_string(),
            "192.168.1.1".parse().unwrap(),
            9001,
            Utc::now(),
            "test".to_string(),
        )
    }

    fn create_test_microdescriptor() -> Microdescriptor {
        Microdescriptor::parse(
            "onion-key\n-----BEGIN RSA PUBLIC KEY-----\ntest\n-----END RSA PUBLIC KEY-----\n",
        )
        .unwrap()
    }

    #[test]
    fn test_cache_consensus() {
        let cache = DescriptorCache::new();
        let consensus = create_test_consensus();

        assert!(cache.get_consensus().is_none());

        cache.put_consensus(consensus.clone());

        let cached = cache.get_consensus();
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().consensus_method, consensus.consensus_method);
    }

    #[test]
    fn test_cache_server_descriptor() {
        let cache = DescriptorCache::new();
        let descriptor = create_test_server_descriptor();
        let fingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();

        assert!(cache.get_server_descriptor(&fingerprint).is_none());

        cache.put_server_descriptor(fingerprint.clone(), descriptor.clone());

        let cached = cache.get_server_descriptor(&fingerprint);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().nickname, descriptor.nickname);
    }

    #[test]
    fn test_cache_microdescriptor() {
        let cache = DescriptorCache::new();
        let descriptor = create_test_microdescriptor();
        let digest = "test_digest".to_string();

        assert!(cache.get_microdescriptor(&digest).is_none());

        cache.put_microdescriptor(digest.clone(), descriptor.clone());

        let cached = cache.get_microdescriptor(&digest);
        assert!(cached.is_some());
    }

    #[test]
    fn test_cache_expiration() {
        let cache = DescriptorCache::new().with_consensus_ttl(Duration::from_millis(10));

        let consensus = create_test_consensus();
        cache.put_consensus(consensus);

        assert!(cache.get_consensus().is_some());

        std::thread::sleep(Duration::from_millis(20));

        assert!(cache.get_consensus().is_none());
    }

    #[test]
    fn test_cache_clear() {
        let cache = DescriptorCache::new();

        cache.put_consensus(create_test_consensus());
        cache.put_server_descriptor("fp1".to_string(), create_test_server_descriptor());
        cache.put_microdescriptor("digest1".to_string(), create_test_microdescriptor());

        assert_eq!(cache.len(), 3);

        cache.clear();

        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_stats() {
        let cache = DescriptorCache::new();
        let consensus = create_test_consensus();

        cache.put_consensus(consensus);

        assert!(cache.get_consensus().is_some());
        assert!(cache.get_consensus().is_some());

        let stats = cache.stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 0);
        assert!(stats.hit_rate() > 99.0);
    }

    #[test]
    fn test_cache_eviction() {
        let cache = DescriptorCache::new().with_max_entries(5);

        for i in 0..10 {
            cache.put_server_descriptor(format!("fp{}", i), create_test_server_descriptor());
        }

        assert!(cache.len() <= 5);

        let stats = cache.stats();
        assert!(stats.evictions > 0);
    }

    #[test]
    fn test_evict_expired() {
        let cache = DescriptorCache::new().with_server_descriptor_ttl(Duration::from_millis(10));

        cache.put_server_descriptor("fp1".to_string(), create_test_server_descriptor());
        cache.put_server_descriptor("fp2".to_string(), create_test_server_descriptor());

        assert_eq!(cache.len(), 2);

        std::thread::sleep(Duration::from_millis(20));

        cache.evict_expired();

        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_lru_eviction() {
        let cache = DescriptorCache::new().with_max_entries(3);

        cache.put_server_descriptor("fp1".to_string(), create_test_server_descriptor());
        cache.put_server_descriptor("fp2".to_string(), create_test_server_descriptor());
        cache.put_server_descriptor("fp3".to_string(), create_test_server_descriptor());

        cache.get_server_descriptor("fp1");
        cache.get_server_descriptor("fp2");

        std::thread::sleep(Duration::from_millis(10));

        cache.put_server_descriptor("fp4".to_string(), create_test_server_descriptor());

        assert!(cache.get_server_descriptor("fp1").is_some());
        assert!(cache.get_server_descriptor("fp2").is_some());
    }

    #[test]
    fn test_cache_hit_rate() {
        let cache = DescriptorCache::new();

        cache.put_consensus(create_test_consensus());

        cache.get_consensus();
        cache.get_consensus();
        cache.get_server_descriptor("missing");

        let stats = cache.stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_rate() - 66.67).abs() < 0.1);
    }
}
