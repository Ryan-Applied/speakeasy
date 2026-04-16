//! QR module -- re-exports QR generation and scanning functionality.
//!
//! Generation is handled by invite::QrService.
//! Camera-based QR scanning is Phase 2 (requires Tauri plugin or nokhwa crate).

pub use crate::invite::QrService;

// Phase 2: QR scanning via camera
// pub struct QrScanner { ... }
// impl QrScanner {
//     pub async fn scan_from_camera() -> Result<String> { ... }
// }
