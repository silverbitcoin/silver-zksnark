//! Integration with Cascade + Mercury consensus protocol
//!
//! This module provides integration between zk-SNARK proofs and the
//! Cascade + Mercury consensus mechanism.

use crate::error::{Result, ZkSnarkError};
use crate::types::Proof;
use tracing::{info, debug, error};
use std::collections::VecDeque;

/// Snapshot with associated zk-SNARK proof
#[derive(Debug, Clone)]
pub struct ProvenSnapshot {
    /// Snapshot number
    pub snapshot_number: u64,
    
    /// State root after this snapshot
    pub state_root: [u8; 64],
    
    /// Merkle root of transactions
    pub transactions_root: [u8; 64],
    
    /// zk-SNARK proof of validity
    pub proof: Proof,
    
    /// Number of transactions in snapshot
    pub transaction_count: u64,
    
    /// Validators who signed this snapshot
    pub signers: Vec<Vec<u8>>,
}

impl ProvenSnapshot {
    /// Create a new proven snapshot
    pub fn new(
        snapshot_number: u64,
        state_root: [u8; 64],
        transactions_root: [u8; 64],
        proof: Proof,
        transaction_count: u64,
    ) -> Self {
        Self {
            snapshot_number,
            state_root,
            transactions_root,
            proof,
            transaction_count,
            signers: Vec::new(),
        }
    }

    /// Add a validator signature
    pub fn add_signer(&mut self, validator: Vec<u8>) {
        if !self.signers.contains(&validator) {
            self.signers.push(validator);
        }
    }

    /// Check if snapshot has sufficient signatures (2/3+ of validators)
    pub fn has_sufficient_signatures(&self, total_validators: usize) -> bool {
        let required = (total_validators * 2 + 2) / 3; // Ceiling of 2/3
        self.signers.len() >= required
    }
}

/// Proof chain for consensus
pub struct ProofChain {
    /// Snapshots in order
    snapshots: VecDeque<ProvenSnapshot>,
    
    /// Maximum snapshots to keep in memory
    max_snapshots: usize,
    
    /// Total validators in the network
    total_validators: usize,
}

impl ProofChain {
    /// Create a new proof chain
    pub fn new(total_validators: usize) -> Self {
        Self {
            snapshots: VecDeque::new(),
            max_snapshots: 1000, // Keep last 1000 snapshots in memory
            total_validators,
        }
    }

    /// Add a proven snapshot to the chain
    pub fn add_snapshot(&mut self, snapshot: ProvenSnapshot) -> Result<()> {
        // Verify snapshot number is sequential
        if !self.snapshots.is_empty() {
            let last_snapshot = self.snapshots.back().unwrap();
            if snapshot.snapshot_number != last_snapshot.snapshot_number + 1 {
                return Err(ZkSnarkError::VerificationFailed(
                    format!(
                        "Snapshot number mismatch: expected {}, got {}",
                        last_snapshot.snapshot_number + 1,
                        snapshot.snapshot_number
                    )
                ));
            }

            // Verify proof chain continuity
            if snapshot.proof.previous_proof_hash != last_snapshot.proof.hash() {
                return Err(ZkSnarkError::VerificationFailed(
                    "Proof chain broken: previous proof hash mismatch".to_string()
                ));
            }
        }

        // Verify snapshot has sufficient signatures
        if !snapshot.has_sufficient_signatures(self.total_validators) {
            return Err(ZkSnarkError::VerificationFailed(
                format!(
                    "Insufficient signatures: {} < {}",
                    snapshot.signers.len(),
                    (self.total_validators * 2 + 2) / 3
                )
            ));
        }

        info!("Adding snapshot {} to proof chain", snapshot.snapshot_number);

        self.snapshots.push_back(snapshot);

        // Trim old snapshots if necessary
        while self.snapshots.len() > self.max_snapshots {
            self.snapshots.pop_front();
        }

        Ok(())
    }

    /// Get the latest snapshot
    pub fn latest_snapshot(&self) -> Option<&ProvenSnapshot> {
        self.snapshots.back()
    }

    /// Get a snapshot by number
    pub fn get_snapshot(&self, snapshot_number: u64) -> Option<&ProvenSnapshot> {
        self.snapshots.iter().find(|s| s.snapshot_number == snapshot_number)
    }

    /// Get the latest state root
    pub fn latest_state_root(&self) -> Option<[u8; 64]> {
        self.latest_snapshot().map(|s| s.state_root)
    }

    /// Get the number of snapshots in the chain
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Verify the entire proof chain
    pub fn verify_chain(&self) -> Result<bool> {
        if self.snapshots.is_empty() {
            return Ok(true);
        }

        info!("Verifying proof chain with {} snapshots", self.snapshots.len());

        // Verify first snapshot has zero previous proof hash
        let first = self.snapshots.front().unwrap();
        if first.proof.snapshot_number != 0 {
            return Err(ZkSnarkError::VerificationFailed(
                "First snapshot must be genesis (snapshot 0)".to_string()
            ));
        }

        // Verify chain continuity
        let mut prev_snapshot = first;
        for snapshot in self.snapshots.iter().skip(1) {
            // Verify snapshot numbers are sequential
            if snapshot.snapshot_number != prev_snapshot.snapshot_number + 1 {
                return Err(ZkSnarkError::VerificationFailed(
                    format!(
                        "Snapshot number gap: {} -> {}",
                        prev_snapshot.snapshot_number,
                        snapshot.snapshot_number
                    )
                ));
            }

            // Verify proof chain
            if snapshot.proof.previous_proof_hash != prev_snapshot.proof.hash() {
                return Err(ZkSnarkError::VerificationFailed(
                    "Proof chain broken".to_string()
                ));
            }

            prev_snapshot = snapshot;
        }

        info!("Proof chain verification successful");
        Ok(true)
    }

    /// Get proof reward for a snapshot
    pub fn calculate_proof_reward(&self, snapshot_number: u64) -> u64 {
        // Base reward: 10 SBTC per proof
        let base_reward = 10_000_000_000u64; // 10 SBTC in MIST (9 decimals)
        
        // Bonus for early participation (first 100 snapshots)
        if snapshot_number < 100 {
            base_reward + (100 - snapshot_number as u64) * 100_000_000 // Up to 1 SBTC bonus
        } else {
            base_reward
        }
    }

    /// Export proof chain for light client sync
    pub fn export_for_sync(&self) -> Result<Vec<u8>> {
        if self.snapshots.is_empty() {
            return Err(ZkSnarkError::InvalidCircuit("Empty proof chain".to_string()));
        }

        let mut data = Vec::new();

        // Export only the latest snapshot (for light client)
        if let Some(latest) = self.latest_snapshot() {
            data.extend_from_slice(&latest.snapshot_number.to_le_bytes());
            data.extend_from_slice(&latest.state_root);
            data.extend_from_slice(&latest.transactions_root);
            data.extend_from_slice(&latest.proof.proof_data);
        }

        Ok(data)
    }
}

/// Consensus integration manager
pub struct ConsensusIntegration {
    /// Proof chain
    proof_chain: ProofChain,
    
    /// Pending proofs waiting for signatures
    pending_proofs: Vec<ProvenSnapshot>,
}

impl ConsensusIntegration {
    /// Create a new consensus integration manager
    pub fn new(total_validators: usize) -> Self {
        Self {
            proof_chain: ProofChain::new(total_validators),
            pending_proofs: Vec::new(),
        }
    }

    /// Submit a proof for a snapshot
    pub fn submit_proof(&mut self, snapshot: ProvenSnapshot) -> Result<()> {
        debug!("Submitting proof for snapshot {}", snapshot.snapshot_number);
        self.pending_proofs.push(snapshot);
        Ok(())
    }

    /// Add a validator signature to a pending proof
    pub fn add_signature(&mut self, snapshot_number: u64, validator: Vec<u8>) -> Result<()> {
        if let Some(snapshot) = self.pending_proofs.iter_mut().find(|s| s.snapshot_number == snapshot_number) {
            snapshot.add_signer(validator);
            
            // Check if snapshot now has sufficient signatures
            if snapshot.has_sufficient_signatures(self.proof_chain.total_validators) {
                info!("Snapshot {} has sufficient signatures, finalizing", snapshot_number);
            }
            
            Ok(())
        } else {
            Err(ZkSnarkError::VerificationFailed(
                format!("Snapshot {} not found", snapshot_number)
            ))
        }
    }

    /// Finalize pending proofs that have sufficient signatures
    pub fn finalize_pending_proofs(&mut self) -> Result<usize> {
        let mut finalized_count = 0;
        
        // Sort pending proofs by snapshot number
        self.pending_proofs.sort_by_key(|s| s.snapshot_number);
        
        // Finalize proofs with sufficient signatures
        let mut to_remove = Vec::new();
        for (i, snapshot) in self.pending_proofs.iter().enumerate() {
            if snapshot.has_sufficient_signatures(self.proof_chain.total_validators) {
                self.proof_chain.add_snapshot(snapshot.clone())?;
                to_remove.push(i);
                finalized_count += 1;
            }
        }
        
        // Remove finalized proofs (in reverse order to maintain indices)
        for i in to_remove.iter().rev() {
            self.pending_proofs.remove(*i);
        }
        
        Ok(finalized_count)
    }

    /// Get the latest state root
    pub fn latest_state_root(&self) -> Option<[u8; 64]> {
        self.proof_chain.latest_state_root()
    }

    /// Get the proof chain
    pub fn proof_chain(&self) -> &ProofChain {
        &self.proof_chain
    }

    /// Verify the entire consensus state
    pub fn verify_consensus_state(&self) -> Result<bool> {
        self.proof_chain.verify_chain()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ProofMetadata;
    use std::time::SystemTime;

    fn create_test_snapshot(snapshot_number: u64) -> ProvenSnapshot {
        let proof = Proof {
            proof_data: vec![0u8; 192],
            metadata: ProofMetadata {
                timestamp: SystemTime::now(),
                prover: vec![1u8; 32],
                transaction_count: 100,
                generation_time_ms: 150,
                gpu_accelerated: true,
            },
            state_root: [snapshot_number as u8; 64],
            previous_proof_hash: if snapshot_number == 0 { [0u8; 64] } else { [snapshot_number as u8 - 1; 64] },
            snapshot_number,
        };

        ProvenSnapshot::new(
            snapshot_number,
            [snapshot_number as u8; 64],
            [snapshot_number as u8 + 1; 64],
            proof,
            100,
        )
    }

    #[test]
    fn test_proven_snapshot_creation() {
        let snapshot = create_test_snapshot(0);
        assert_eq!(snapshot.snapshot_number, 0);
        assert_eq!(snapshot.transaction_count, 100);
    }

    #[test]
    fn test_sufficient_signatures() {
        let mut snapshot = create_test_snapshot(0);
        assert!(!snapshot.has_sufficient_signatures(100));
        
        for i in 0..67 {
            snapshot.add_signer(vec![i as u8; 32]);
        }
        assert!(snapshot.has_sufficient_signatures(100));
    }

    #[test]
    fn test_proof_chain_creation() {
        let chain = ProofChain::new(100);
        assert_eq!(chain.snapshot_count(), 0);
    }

    #[test]
    fn test_proof_chain_add_snapshot() {
        let mut chain = ProofChain::new(100);
        let mut snapshot = create_test_snapshot(0);
        
        for i in 0..67 {
            snapshot.add_signer(vec![i as u8; 32]);
        }
        
        let result = chain.add_snapshot(snapshot);
        assert!(result.is_ok());
        assert_eq!(chain.snapshot_count(), 1);
    }

    #[test]
    fn test_consensus_integration() {
        let mut integration = ConsensusIntegration::new(100);
        let mut snapshot = create_test_snapshot(0);
        
        for i in 0..67 {
            snapshot.add_signer(vec![i as u8; 32]);
        }
        
        integration.submit_proof(snapshot).unwrap();
        let finalized = integration.finalize_pending_proofs().unwrap();
        assert_eq!(finalized, 1);
    }

    #[test]
    fn test_proof_reward_calculation() {
        let chain = ProofChain::new(100);
        let reward_0 = chain.calculate_proof_reward(0);
        let reward_50 = chain.calculate_proof_reward(50);
        let reward_100 = chain.calculate_proof_reward(100);
        
        assert!(reward_0 > reward_50);
        assert!(reward_50 > reward_100);
    }
}
