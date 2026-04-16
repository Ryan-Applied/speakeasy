//! Transport module -- manages Veilid app calls, private routes, and
//! connection state tracking.

use anyhow::Result;
use async_trait::async_trait;

/// Abstraction over the network transport layer.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send a message to a peer via app call.
    async fn send(&self, route: &[u8], data: &[u8]) -> Result<Vec<u8>>;

    /// Create a private route for receiving messages.
    async fn create_route(&self) -> Result<Vec<u8>>;

    /// Get the current route data for sharing with peers.
    fn current_route(&self) -> Option<Vec<u8>>;

    /// Check if a peer route is reachable.
    async fn probe_route(&self, route: &[u8]) -> Result<bool>;
}

/// Placeholder transport for offline/testing scenarios.
pub struct OfflineTransport;

#[async_trait]
impl Transport for OfflineTransport {
    async fn send(&self, _route: &[u8], _data: &[u8]) -> Result<Vec<u8>> {
        anyhow::bail!("offline: no transport available")
    }

    async fn create_route(&self) -> Result<Vec<u8>> {
        Ok(vec![0u8; 32])
    }

    fn current_route(&self) -> Option<Vec<u8>> {
        None
    }

    async fn probe_route(&self, _route: &[u8]) -> Result<bool> {
        Ok(false)
    }
}
