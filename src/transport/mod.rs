//! Transport module -- manages Veilid app calls, private routes, and
//! connection state tracking.

use crate::veilid_node::VeilidNode;
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Abstraction over the network transport layer.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send a request to a peer via app_call (request/response, max 32KB).
    async fn send(&self, route: &[u8], data: &[u8]) -> Result<Vec<u8>>;

    /// Send a fire-and-forget notification via app_message (max 32KB).
    async fn notify(&self, route: &[u8], data: &[u8]) -> Result<()>;

    /// Create a private route for receiving messages. Returns the route blob.
    async fn create_route(&self) -> Result<Vec<u8>>;

    /// Get the current route blob for sharing with peers.
    fn current_route(&self) -> Option<Vec<u8>>;

    /// Check if a peer route is reachable.
    async fn probe_route(&self, route: &[u8]) -> Result<bool>;
}

// ---------------------------------------------------------------------------
// Production transport backed by VeilidNode.
// ---------------------------------------------------------------------------

/// Real transport using Veilid private routes and app_call/app_message.
pub struct VeilidTransport {
    node: Arc<VeilidNode>,
    /// Our current route blob (shareable with peers so they can reach us).
    route_blob: RwLock<Option<Vec<u8>>>,
    /// Our route ID (for cleanup on drop).
    route_id: RwLock<Option<veilid_core::RouteId>>,
}

impl VeilidTransport {
    pub fn new(node: Arc<VeilidNode>) -> Self {
        Self {
            node,
            route_blob: RwLock::new(None),
            route_id: RwLock::new(None),
        }
    }

    /// Allocate our receiving route. Call once after node is attached.
    pub async fn init_route(&self) -> Result<Vec<u8>> {
        let (rid, blob) = self.node.allocate_private_route().await?;
        *self.route_blob.write().await = Some(blob.clone());
        *self.route_id.write().await = Some(rid);
        info!("transport: private route allocated ({} bytes)", blob.len());
        Ok(blob)
    }
}

#[async_trait]
impl Transport for VeilidTransport {
    async fn send(&self, route: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let remote_route = self
            .node
            .import_remote_route(route)
            .context("import remote route")?;
        let target = veilid_core::Target::RouteId(remote_route);
        self.node
            .app_call(target, data.to_vec())
            .await
            .context("app_call failed")
    }

    async fn notify(&self, route: &[u8], data: &[u8]) -> Result<()> {
        let remote_route = self
            .node
            .import_remote_route(route)
            .context("import remote route")?;
        let target = veilid_core::Target::RouteId(remote_route);
        self.node
            .app_message(target, data.to_vec())
            .await
            .context("app_message failed")
    }

    async fn create_route(&self) -> Result<Vec<u8>> {
        self.init_route().await
    }

    fn current_route(&self) -> Option<Vec<u8>> {
        // try_read to avoid blocking — returns None if locked.
        self.route_blob
            .try_read()
            .ok()
            .and_then(|guard| guard.clone())
    }

    async fn probe_route(&self, route: &[u8]) -> Result<bool> {
        // Attempt a lightweight app_call with an empty ping. If it returns
        // any response (even empty), the route is alive.
        match self.send(route, b"ping").await {
            Ok(_) => Ok(true),
            Err(e) => {
                warn!("route probe failed: {}", e);
                Ok(false)
            }
        }
    }
}

/// Blanket impl so Arc<T: Transport> is also Transport.
#[async_trait]
impl<T: Transport> Transport for Arc<T> {
    async fn send(&self, route: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        (**self).send(route, data).await
    }
    async fn notify(&self, route: &[u8], data: &[u8]) -> Result<()> {
        (**self).notify(route, data).await
    }
    async fn create_route(&self) -> Result<Vec<u8>> {
        (**self).create_route().await
    }
    fn current_route(&self) -> Option<Vec<u8>> {
        (**self).current_route()
    }
    async fn probe_route(&self, route: &[u8]) -> Result<bool> {
        (**self).probe_route(route).await
    }
}

// ---------------------------------------------------------------------------
// Offline transport for testing.
// ---------------------------------------------------------------------------

/// Placeholder transport for offline/testing scenarios.
pub struct OfflineTransport;

#[async_trait]
impl Transport for OfflineTransport {
    async fn send(&self, _route: &[u8], _data: &[u8]) -> Result<Vec<u8>> {
        anyhow::bail!("offline: no transport available")
    }
    async fn notify(&self, _route: &[u8], _data: &[u8]) -> Result<()> {
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
