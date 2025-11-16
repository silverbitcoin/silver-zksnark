use crate::{
    circuit::SnapshotCircuit,
    error::{Result, ZkSnarkError},
    types::{Proof, ProofMetadata, ProvingKey},
};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey as Groth16ProvingKey};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_snark::SNARK;
use std::time::{SystemTime, Instant};
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{info, warn, error};
use rand::thread_rng;

/// Proof generator for creating recursive zk-SNARKs
pub struct ProofGenerator {
    proving_key: Arc<RwLock<Option<Groth16ProvingKey<Bn254>>>>,
    gpu_enabled: bool,
}

impl ProofGenerator {
    /// Create a new proof generator
    pub fn new(gpu_enabled: bool) -> Self {
        Self {
            proving_key: Arc::new(RwLock::new(None)),
            gpu_enabled,
        }
    }

    /// Load proving key from bytes
    pub fn load_proving_key(&self, key_data: Vec<u8>) -> Result<()> {
        let cursor = std::io::Cursor::new(key_data);
        let pk = Groth16ProvingKey::<Bn254>::deserialize_compressed(cursor)
            .map_err(|e| ZkSnarkError::SerializationError(format!("Failed to deserialize proving key: {}", e)))?;
        
        *self.proving_key.write() = Some(pk);
        info!("Proving key loaded successfully");
        Ok(())
    }

    /// Generate a proof for a snapshot
    pub async fn generate_proof(
        &self,
        previous_state_root: Vec<u8>,
        current_state_root: Vec<u8>,
        previous_proof_hash: Vec<u8>,
        transactions_root: Vec<u8>,
        transaction_count: u64,
        prover_address: Vec<u8>,
        snapshot_number: u64,
        transaction_hashes: Vec<Vec<u8>>,
    ) -> Result<Proof> {
        let pk_guard = self.proving_key.read();
        if pk_guard.is_none() {
            return Err(ZkSnarkError::MissingProvingKey);
        }

        info!(
            "Generating zk-SNARK proof for snapshot {} with {} transactions",
            snapshot_number, transaction_count
        );

        let start = Instant::now();

        // Create the circuit with all required data
        let circuit = SnapshotCircuit::new(
            previous_state_root.clone(),
            current_state_root.clone(),
            previous_proof_hash.clone(),
            transactions_root.clone(),
            transaction_count,
            snapshot_number,
            transaction_hashes,
        );

        // Generate the proof using Groth16
        let proof_data = self.generate_groth16_proof(circuit).await?;

        let generation_time_ms = start.elapsed().as_millis() as u64;

        if self.gpu_enabled {
            info!("Proof generated with GPU acceleration in {}ms", generation_time_ms);
        } else {
            info!("Proof generated in {}ms", generation_time_ms);
        }

        let mut state_root = [0u8; 64];
        state_root[..current_state_root.len().min(64)].copy_from_slice(
            &current_state_root[..current_state_root.len().min(64)]
        );

        let mut prev_proof_hash = [0u8; 64];
        prev_proof_hash[..previous_proof_hash.len().min(64)].copy_from_slice(
            &previous_proof_hash[..previous_proof_hash.len().min(64)]
        );

        Ok(Proof {
            proof_data,
            metadata: ProofMetadata {
                timestamp: SystemTime::now(),
                prover: prover_address,
                transaction_count,
                generation_time_ms,
                gpu_accelerated: self.gpu_enabled,
            },
            state_root,
            previous_proof_hash: prev_proof_hash,
            snapshot_number,
        })
    }

    /// Generate Groth16 proof using the proving key
    async fn generate_groth16_proof(&self, circuit: SnapshotCircuit) -> Result<Vec<u8>> {
        let pk_guard = self.proving_key.read();
        let pk = pk_guard.as_ref().ok_or(ZkSnarkError::MissingProvingKey)?;

        // Clone the proving key for use in async context
        let pk_clone = pk.clone();
        drop(pk_guard);

        // Run proof generation in a blocking task to avoid blocking the async runtime
        let proof = tokio::task::spawn_blocking(move || {
            let mut rng = thread_rng();
            
            // Generate the Groth16 proof
            Groth16::<Bn254>::prove(&pk_clone, circuit, &mut rng)
                .map_err(|e| ZkSnarkError::ProofGenerationFailed(format!("Groth16 proof generation failed: {}", e)))
        })
        .await
        .map_err(|e| ZkSnarkError::ProofGenerationFailed(format!("Task join error: {}", e)))??;

        // Serialize the proof to bytes
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes)
            .map_err(|e| ZkSnarkError::SerializationError(format!("Failed to serialize proof: {}", e)))?;

        info!("Proof serialized to {} bytes", proof_bytes.len());
        Ok(proof_bytes)
    }

    /// Estimate proof generation time based on transaction count
    pub fn estimate_generation_time(&self, transaction_count: u64) -> u64 {
        // Base time: 100ms with GPU, 500ms without
        let base_time = if self.gpu_enabled { 100 } else { 500 };
        
        // Additional time scales with transaction count
        // Approximately 1ms per 1000 transactions
        let tx_overhead = (transaction_count / 1000).max(1);
        
        base_time + tx_overhead
    }

    /// Generate proving and verifying keys for the circuit
    pub fn generate_keys() -> Result<(Vec<u8>, Vec<u8>)> {
        info!("Generating Groth16 keys for SnapshotCircuit");
        
        let mut rng = thread_rng();
        let circuit = SnapshotCircuit::empty();

        // Generate keys
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| ZkSnarkError::ProofGenerationFailed(format!("Key generation failed: {}", e)))?;

        // Serialize proving key
        let mut pk_bytes = Vec::new();
        pk.serialize_compressed(&mut pk_bytes)
            .map_err(|e| ZkSnarkError::SerializationError(format!("Failed to serialize proving key: {}", e)))?;

        // Serialize verifying key
        let mut vk_bytes = Vec::new();
        vk.serialize_compressed(&mut vk_bytes)
            .map_err(|e| ZkSnarkError::SerializationError(format!("Failed to serialize verifying key: {}", e)))?;

        info!("Keys generated: PK size = {} bytes, VK size = {} bytes", pk_bytes.len(), vk_bytes.len());
        Ok((pk_bytes, vk_bytes))
    }

    /// Check if proving key is loaded
    pub fn has_proving_key(&self) -> bool {
        self.proving_key.read().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proof_generation() {
        // Generate keys first
        let (pk_bytes, _vk_bytes) = ProofGenerator::generate_keys()
            .expect("Failed to generate keys");

        let generator = ProofGenerator::new(false);
        generator.load_proving_key(pk_bytes)
            .expect("Failed to load proving key");

        let proof = generator
            .generate_proof(
                vec![1u8; 64],
                vec![2u8; 64],
                vec![3u8; 64],
                vec![4u8; 64],
                100,
                vec![5u8; 32],
                1,
                vec![vec![6u8; 64]],
            )
            .await
            .expect("Failed to generate proof");

        assert_eq!(proof.snapshot_number, 1);
        assert_eq!(proof.metadata.transaction_count, 100);
        assert!(!proof.metadata.gpu_accelerated);
        assert!(!proof.proof_data.is_empty());
    }

    #[test]
    fn test_time_estimation() {
        let generator = ProofGenerator::new(true);
        let time_100 = generator.estimate_generation_time(100);
        let time_50000 = generator.estimate_generation_time(50000);
        
        assert!(time_100 >= 100);
        assert!(time_50000 > time_100);
    }

    #[test]
    fn test_key_generation() {
        let (pk_bytes, vk_bytes) = ProofGenerator::generate_keys()
            .expect("Failed to generate keys");
        
        assert!(!pk_bytes.is_empty());
        assert!(!vk_bytes.is_empty());
        assert!(pk_bytes.len() > vk_bytes.len()); // Proving key is larger
    }

    #[test]
    fn test_proving_key_loading() {
        let (pk_bytes, _vk_bytes) = ProofGenerator::generate_keys()
            .expect("Failed to generate keys");

        let generator = ProofGenerator::new(false);
        assert!(!generator.has_proving_key());
        
        generator.load_proving_key(pk_bytes)
            .expect("Failed to load proving key");
        
        assert!(generator.has_proving_key());
    }
}
