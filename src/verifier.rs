use crate::{
    error::{Result, ZkSnarkError},
    types::Proof,
};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof as Groth16Proof, VerifyingKey as Groth16VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use parking_lot::RwLock;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Instant;
use tracing::{error, info};

/// Proof verifier for validating recursive zk-SNARKs
pub struct ProofVerifier {
    verifying_key: Arc<RwLock<Option<Groth16VerifyingKey<Bn254>>>>,
}

impl ProofVerifier {
    /// Create a new proof verifier
    pub fn new() -> Self {
        Self {
            verifying_key: Arc::new(RwLock::new(None)),
        }
    }

    /// Load verifying key from bytes
    pub fn load_verifying_key(&self, key_data: Vec<u8>) -> Result<()> {
        let cursor = Cursor::new(key_data);
        let vk = Groth16VerifyingKey::<Bn254>::deserialize_compressed(cursor).map_err(|e| {
            ZkSnarkError::SerializationError(format!("Failed to deserialize verifying key: {}", e))
        })?;

        *self.verifying_key.write() = Some(vk);
        info!("Verifying key loaded successfully");
        Ok(())
    }

    /// Verify a single proof
    pub fn verify_proof(&self, proof: &Proof) -> Result<bool> {
        let vk_guard = self.verifying_key.read();
        if vk_guard.is_none() {
            return Err(ZkSnarkError::MissingVerifyingKey);
        }

        info!(
            "Verifying zk-SNARK proof for snapshot {}",
            proof.snapshot_number
        );

        let start = Instant::now();

        // Verify metadata first (quick check)
        self.verify_metadata(proof)?;

        // Verify the actual Groth16 proof
        let is_valid = self.verify_groth16_proof(proof)?;

        let verification_time = start.elapsed();
        info!("Proof verification completed in {:?}", verification_time);

        if !is_valid {
            error!(
                "Proof verification failed for snapshot {}",
                proof.snapshot_number
            );
            return Err(ZkSnarkError::VerificationFailed(format!(
                "Invalid proof for snapshot {}",
                proof.snapshot_number
            )));
        }

        Ok(true)
    }

    /// Verify a chain of proofs (for syncing)
    pub fn verify_proof_chain(&self, proofs: &[Proof]) -> Result<bool> {
        if proofs.is_empty() {
            return Ok(true);
        }

        info!("Verifying proof chain of {} proofs", proofs.len());

        // Verify each proof
        for (i, proof) in proofs.iter().enumerate() {
            if !self.verify_proof(proof)? {
                error!("Proof chain verification failed at index {}", i);
                return Ok(false);
            }

            // Verify that proofs are properly linked (except for genesis)
            if i > 0 {
                let prev_proof_hash = proofs[i - 1].hash();
                if prev_proof_hash != proof.previous_proof_hash {
                    error!("Proof chain broken at index {}: hash mismatch", i);
                    return Err(ZkSnarkError::VerificationFailed(format!(
                        "Proof chain broken at index {}",
                        i
                    )));
                }

                // Verify snapshot numbers are sequential
                if proof.snapshot_number != proofs[i - 1].snapshot_number + 1 {
                    error!(
                        "Proof chain broken at index {}: snapshot number mismatch",
                        i
                    );
                    return Err(ZkSnarkError::VerificationFailed(format!(
                        "Snapshot numbers not sequential at index {}",
                        i
                    )));
                }
            }
        }

        info!(
            "Proof chain verification successful for {} proofs",
            proofs.len()
        );
        Ok(true)
    }

    /// Verify a single Groth16 proof
    fn verify_groth16_proof(&self, proof: &Proof) -> Result<bool> {
        let vk_guard = self.verifying_key.read();
        let vk = vk_guard.as_ref().ok_or(ZkSnarkError::MissingVerifyingKey)?;

        // Deserialize the proof from bytes
        let cursor = Cursor::new(&proof.proof_data);
        let groth16_proof = Groth16Proof::<Bn254>::deserialize_compressed(cursor).map_err(|e| {
            ZkSnarkError::SerializationError(format!("Failed to deserialize proof: {}", e))
        })?;

        // Prepare public inputs for verification
        // Public inputs are: [previous_state_root, current_state_root, snapshot_number]
        let mut public_inputs = Vec::new();

        // Convert state roots to field elements
        for byte in &proof.state_root {
            public_inputs.push(Fr::from(*byte as u64));
        }

        for byte in &proof.previous_proof_hash {
            public_inputs.push(Fr::from(*byte as u64));
        }

        public_inputs.push(Fr::from(proof.snapshot_number));

        // Verify the proof
        let is_valid =
            Groth16::<Bn254>::verify(vk, &public_inputs, &groth16_proof).map_err(|e| {
                ZkSnarkError::VerificationFailed(format!("Groth16 verification error: {}", e))
            })?;

        Ok(is_valid)
    }

    /// Verify proof metadata
    pub fn verify_metadata(&self, proof: &Proof) -> Result<()> {
        // Check that metadata is reasonable
        if proof.metadata.transaction_count == 0 {
            return Err(ZkSnarkError::VerificationFailed(
                "Transaction count cannot be zero".to_string(),
            ));
        }

        if proof.metadata.transaction_count > 500 {
            return Err(ZkSnarkError::VerificationFailed(
                "Transaction count exceeds maximum (500)".to_string(),
            ));
        }

        if proof.metadata.generation_time_ms == 0 {
            return Err(ZkSnarkError::VerificationFailed(
                "Generation time cannot be zero".to_string(),
            ));
        }

        // Check that generation time is reasonable
        let max_time = if proof.metadata.gpu_accelerated {
            5000 // 5 seconds with GPU
        } else {
            30000 // 30 seconds without GPU
        };

        if proof.metadata.generation_time_ms > max_time {
            return Err(ZkSnarkError::VerificationFailed(format!(
                "Generation time {} exceeds maximum {}",
                proof.metadata.generation_time_ms, max_time
            )));
        }

        // Verify proof size is reasonable (Groth16 proofs are ~192 bytes)
        if proof.proof_data.len() < 100 || proof.proof_data.len() > 1000 {
            return Err(ZkSnarkError::InvalidProofFormat);
        }

        Ok(())
    }

    /// Verify that a proof is for a specific snapshot
    pub fn verify_snapshot_number(&self, proof: &Proof, expected_snapshot: u64) -> Result<()> {
        if proof.snapshot_number != expected_snapshot {
            return Err(ZkSnarkError::VerificationFailed(format!(
                "Snapshot number mismatch: expected {}, got {}",
                expected_snapshot, proof.snapshot_number
            )));
        }
        Ok(())
    }

    /// Verify that a proof has a specific state root
    pub fn verify_state_root(&self, proof: &Proof, expected_root: &[u8; 64]) -> Result<()> {
        if proof.state_root != *expected_root {
            return Err(ZkSnarkError::VerificationFailed(
                "State root mismatch".to_string(),
            ));
        }
        Ok(())
    }

    /// Check if verifying key is loaded
    pub fn has_verifying_key(&self) -> bool {
        self.verifying_key.read().is_some()
    }
}

impl Default for ProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}
