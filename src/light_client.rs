//! Light client implementation for instant blockchain sync
//!
//! This module provides a lightweight client that can verify the entire
//! blockchain history using only the latest zk-SNARK proof (~100 MB).

use crate::error::{Result, ZkSnarkError};
use crate::types::Proof;
use crate::verifier::ProofVerifier;
use std::time::Instant;
use tracing::info;

/// Light client state
#[derive(Debug, Clone)]
pub struct LightClientState {
    /// Latest state root
    pub state_root: [u8; 64],

    /// Latest snapshot number
    pub snapshot_number: u64,

    /// Latest proof
    pub proof: Option<Proof>,

    /// Timestamp of last sync
    pub last_sync: u64,

    /// Whether state is verified
    pub verified: bool,
}

impl LightClientState {
    /// Create a new light client state
    pub fn new() -> Self {
        Self {
            state_root: [0u8; 64],
            snapshot_number: 0,
            proof: None,
            last_sync: 0,
            verified: false,
        }
    }

    /// Update state with a new proof
    pub fn update(&mut self, proof: Proof) {
        self.state_root = proof.state_root;
        self.snapshot_number = proof.snapshot_number;
        self.proof = Some(proof);
        self.last_sync = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.verified = false;
    }
}

impl Default for LightClientState {
    fn default() -> Self {
        Self::new()
    }
}

/// Light client for blockchain verification
pub struct LightClient {
    /// Client state
    state: LightClientState,

    /// Proof verifier
    verifier: ProofVerifier,

    /// Sync statistics
    sync_stats: SyncStats,
}

/// Synchronization statistics
#[derive(Debug, Clone)]
pub struct SyncStats {
    /// Total syncs performed
    pub total_syncs: u64,

    /// Total time spent syncing (milliseconds)
    pub total_sync_time_ms: u64,

    /// Average sync time (milliseconds)
    pub average_sync_time_ms: u64,

    /// Last sync time (milliseconds)
    pub last_sync_time_ms: u64,

    /// Total data downloaded (bytes)
    pub total_data_downloaded: u64,
}

impl Default for SyncStats {
    fn default() -> Self {
        Self {
            total_syncs: 0,
            total_sync_time_ms: 0,
            average_sync_time_ms: 0,
            last_sync_time_ms: 0,
            total_data_downloaded: 0,
        }
    }
}

impl LightClient {
    /// Create a new light client
    pub fn new() -> Self {
        info!("Initializing light client");

        Self {
            state: LightClientState::new(),
            verifier: ProofVerifier::new(),
            sync_stats: SyncStats::default(),
        }
    }

    /// Load verifying key for proof verification
    pub fn load_verifying_key(&mut self, key_data: Vec<u8>) -> Result<()> {
        self.verifier.load_verifying_key(key_data)?;
        info!("Verifying key loaded for light client");
        Ok(())
    }

    /// Sync with the latest proof
    pub fn sync(&mut self, proof: Proof) -> Result<()> {
        let start = Instant::now();

        info!("Light client syncing to snapshot {}", proof.snapshot_number);

        // Verify the proof
        self.verifier.verify_proof(&proof)?;

        // Update state
        self.state.update(proof.clone());
        self.state.verified = true;

        // Update statistics
        let sync_time_ms = start.elapsed().as_millis() as u64;
        self.sync_stats.total_syncs += 1;
        self.sync_stats.total_sync_time_ms += sync_time_ms;
        self.sync_stats.last_sync_time_ms = sync_time_ms;
        self.sync_stats.average_sync_time_ms =
            self.sync_stats.total_sync_time_ms / self.sync_stats.total_syncs;
        self.sync_stats.total_data_downloaded += proof.proof_data.len() as u64;

        info!("Light client synced successfully in {}ms", sync_time_ms);

        Ok(())
    }

    /// Get the current state
    pub fn state(&self) -> &LightClientState {
        &self.state
    }

    /// Get the current state root
    pub fn state_root(&self) -> [u8; 64] {
        self.state.state_root
    }

    /// Get the current snapshot number
    pub fn snapshot_number(&self) -> u64 {
        self.state.snapshot_number
    }

    /// Check if state is verified
    pub fn is_verified(&self) -> bool {
        self.state.verified
    }

    /// Get sync statistics
    pub fn sync_stats(&self) -> &SyncStats {
        &self.sync_stats
    }

    /// Estimate bandwidth for full sync
    pub fn estimate_bandwidth(&self) -> u64 {
        // Proof size: ~192 bytes
        // Metadata: ~100 bytes
        // Total: ~300 bytes per snapshot
        300
    }

    /// Estimate time to sync
    pub fn estimate_sync_time(&self) -> u64 {
        // Average verification time: ~30ms
        // Network latency: ~50ms
        // Total: ~80ms
        80
    }

    /// Export client state for backup
    pub fn export_state(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();

        // Export state root
        data.extend_from_slice(&self.state.state_root);

        // Export snapshot number
        data.extend_from_slice(&self.state.snapshot_number.to_le_bytes());

        // Export verification status
        data.push(if self.state.verified { 1 } else { 0 });

        Ok(data)
    }

    /// Import client state from backup
    pub fn import_state(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < 73 {
            return Err(ZkSnarkError::InvalidProofFormat);
        }

        // Import state root
        let mut state_root = [0u8; 64];
        state_root.copy_from_slice(&data[0..64]);
        self.state.state_root = state_root;

        // Import snapshot number
        let snapshot_number = u64::from_le_bytes([
            data[64], data[65], data[66], data[67], data[68], data[69], data[70], data[71],
        ]);
        self.state.snapshot_number = snapshot_number;

        // Import verification status
        self.state.verified = data[72] != 0;

        info!("Light client state imported");
        Ok(())
    }
}

impl Default for LightClient {
    fn default() -> Self {
        Self::new()
    }
}
