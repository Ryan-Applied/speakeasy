//! DHT module -- thin wrapper around Veilid's RoutingContext for
//! record creation, reading, writing, watching, and garbage collection.
//!
//! This module abstracts the DHT operations needed by chat, sync, and files.
//! All crypto is handled before data reaches this layer -- this module stores
//! and retrieves opaque byte blobs.

use anyhow::Result;
use async_trait::async_trait;

/// Abstraction over DHT record operations.
/// Implemented against veilid_core::RoutingContext in production,
/// with an in-memory mock for testing.
#[async_trait]
pub trait DhtOps: Send + Sync {
    /// Create a new DHT record with a single-writer schema.
    /// Returns the record key.
    async fn create_record(&self) -> Result<Vec<u8>>;

    /// Open an existing DHT record by key.
    async fn open_record(&self, key: &[u8]) -> Result<()>;

    /// Close a DHT record.
    async fn close_record(&self, key: &[u8]) -> Result<()>;

    /// Read a subkey value from a record.
    async fn get_subkey(&self, key: &[u8], subkey: u32) -> Result<Option<Vec<u8>>>;

    /// Write a value to a subkey.
    async fn set_subkey(&self, key: &[u8], subkey: u32, data: &[u8]) -> Result<()>;

    /// Watch a record for changes. Returns a watch ID.
    async fn watch_record(&self, key: &[u8]) -> Result<u64>;

    /// Cancel a watch.
    async fn cancel_watch(&self, key: &[u8], watch_id: u64) -> Result<()>;

    /// Inspect a record to get subkey sequence numbers.
    /// Returns a vec of (subkey_index, sequence_number) for changed subkeys.
    async fn inspect_record(&self, key: &[u8]) -> Result<Vec<(u32, u64)>>;

    /// Delete a local record (does not remove from DHT network).
    async fn delete_record(&self, key: &[u8]) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Production implementation backed by VeilidNode.
// Record keys are stored as their Display string encoding (e.g. "VLD0:abc...")
// so callers are byte-agnostic.
// ---------------------------------------------------------------------------

use crate::veilid_node::VeilidNode;
use std::sync::Arc;

/// Production DhtOps backed by a running VeilidNode.
pub struct VeilidDht {
    node: Arc<VeilidNode>,
}

impl VeilidDht {
    pub fn new(node: Arc<VeilidNode>) -> Self {
        Self { node }
    }

    fn parse_key(raw: &[u8]) -> Result<veilid_core::RecordKey> {
        let s = std::str::from_utf8(raw)
            .map_err(|_| anyhow::anyhow!("record key is not valid UTF-8"))?;
        s.parse::<veilid_core::RecordKey>()
            .map_err(|e| anyhow::anyhow!("parse RecordKey: {}", e))
    }
}

#[async_trait]
impl DhtOps for VeilidDht {
    async fn create_record(&self) -> Result<Vec<u8>> {
        let desc = self.node.create_dht_record_default().await?;
        Ok(desc.key().to_string().into_bytes())
    }

    async fn open_record(&self, key: &[u8]) -> Result<()> {
        let rk = Self::parse_key(key)?;
        let _desc = self.node.open_dht_record(rk, None).await?;
        Ok(())
    }

    async fn close_record(&self, key: &[u8]) -> Result<()> {
        let rk = Self::parse_key(key)?;
        self.node.close_dht_record(rk).await
    }

    async fn get_subkey(&self, key: &[u8], subkey: u32) -> Result<Option<Vec<u8>>> {
        let rk = Self::parse_key(key)?;
        self.node.get_dht_value(rk, subkey, false).await
    }

    async fn set_subkey(&self, key: &[u8], subkey: u32, data: &[u8]) -> Result<()> {
        let rk = Self::parse_key(key)?;
        self.node
            .set_dht_value(rk, subkey, data.to_vec(), None)
            .await
    }

    async fn watch_record(&self, key: &[u8]) -> Result<u64> {
        let rk = Self::parse_key(key)?;
        let ok = self.node.watch_dht_record(rk, None).await?;
        Ok(if ok { 1 } else { 0 })
    }

    async fn cancel_watch(&self, _key: &[u8], _watch_id: u64) -> Result<()> {
        // veilid-core 0.5.3 doesn't expose cancel_watch on RoutingContext;
        // watches expire on their own. This is a no-op placeholder.
        Ok(())
    }

    async fn inspect_record(&self, _key: &[u8]) -> Result<Vec<(u32, u64)>> {
        // inspect_dht_record not directly on RoutingContext in 0.5.3;
        // would need VeilidAPI-level access. Placeholder returns empty.
        Ok(vec![])
    }

    async fn delete_record(&self, key: &[u8]) -> Result<()> {
        // Close is the closest operation; local deletion is not exposed.
        self.close_record(key).await
    }
}

// ---------------------------------------------------------------------------
// In-memory mock for testing.
// ---------------------------------------------------------------------------

/// In-memory DHT mock for testing.
pub struct MockDht {
    records: std::sync::Mutex<std::collections::HashMap<Vec<u8>, Vec<Option<Vec<u8>>>>>,
}

impl MockDht {
    pub fn new() -> Self {
        Self {
            records: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[async_trait]
impl DhtOps for MockDht {
    async fn create_record(&self) -> Result<Vec<u8>> {
        let mut key = vec![0u8; 36];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
        let mut records = self.records.lock().unwrap();
        records.insert(key.clone(), vec![None; 2048]);
        Ok(key)
    }

    async fn open_record(&self, _key: &[u8]) -> Result<()> {
        Ok(())
    }

    async fn close_record(&self, _key: &[u8]) -> Result<()> {
        Ok(())
    }

    async fn get_subkey(&self, key: &[u8], subkey: u32) -> Result<Option<Vec<u8>>> {
        let records = self.records.lock().unwrap();
        if let Some(record) = records.get(key) {
            Ok(record.get(subkey as usize).cloned().flatten())
        } else {
            Ok(None)
        }
    }

    async fn set_subkey(&self, key: &[u8], subkey: u32, data: &[u8]) -> Result<()> {
        let mut records = self.records.lock().unwrap();
        if let Some(record) = records.get_mut(key) {
            if (subkey as usize) < record.len() {
                record[subkey as usize] = Some(data.to_vec());
            }
        }
        Ok(())
    }

    async fn watch_record(&self, _key: &[u8]) -> Result<u64> {
        Ok(1)
    }

    async fn cancel_watch(&self, _key: &[u8], _watch_id: u64) -> Result<()> {
        Ok(())
    }

    async fn inspect_record(&self, key: &[u8]) -> Result<Vec<(u32, u64)>> {
        let records = self.records.lock().unwrap();
        if let Some(record) = records.get(key) {
            let changed: Vec<(u32, u64)> = record.iter().enumerate()
                .filter(|(_, v)| v.is_some())
                .map(|(i, _)| (i as u32, 1))
                .collect();
            Ok(changed)
        } else {
            Ok(vec![])
        }
    }

    async fn delete_record(&self, key: &[u8]) -> Result<()> {
        self.records.lock().unwrap().remove(key);
        Ok(())
    }
}

/// DhtOps delegation for Arc<T> where T: DhtOps, so tests can share
/// a MockDht across the test and SyncService.
#[async_trait]
impl<T: DhtOps> DhtOps for Arc<T> {
    async fn create_record(&self) -> Result<Vec<u8>> { (**self).create_record().await }
    async fn open_record(&self, key: &[u8]) -> Result<()> { (**self).open_record(key).await }
    async fn close_record(&self, key: &[u8]) -> Result<()> { (**self).close_record(key).await }
    async fn get_subkey(&self, key: &[u8], subkey: u32) -> Result<Option<Vec<u8>>> { (**self).get_subkey(key, subkey).await }
    async fn set_subkey(&self, key: &[u8], subkey: u32, data: &[u8]) -> Result<()> { (**self).set_subkey(key, subkey, data).await }
    async fn watch_record(&self, key: &[u8]) -> Result<u64> { (**self).watch_record(key).await }
    async fn cancel_watch(&self, key: &[u8], watch_id: u64) -> Result<()> { (**self).cancel_watch(key, watch_id).await }
    async fn inspect_record(&self, key: &[u8]) -> Result<Vec<(u32, u64)>> { (**self).inspect_record(key).await }
    async fn delete_record(&self, key: &[u8]) -> Result<()> { (**self).delete_record(key).await }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_dht_roundtrip() {
        let dht = MockDht::new();
        let key = dht.create_record().await.unwrap();

        dht.set_subkey(&key, 0, b"hello").await.unwrap();
        let val = dht.get_subkey(&key, 0).await.unwrap();
        assert_eq!(val, Some(b"hello".to_vec()));

        let val = dht.get_subkey(&key, 1).await.unwrap();
        assert_eq!(val, None);
    }
}
