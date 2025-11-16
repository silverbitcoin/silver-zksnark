use serde::{Deserialize, Serialize, Serializer, Deserializer};
use std::time::SystemTime;

/// A recursive zk-SNARK proof that proves the validity of a blockchain snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// The actual Groth16 proof data
    pub proof_data: Vec<u8>,
    
    /// Metadata about the proof
    pub metadata: ProofMetadata,
    
    /// Hash of the current state root
    #[serde(serialize_with = "serialize_array", deserialize_with = "deserialize_array")]
    pub state_root: [u8; 64],
    
    /// Hash of the previous proof (for recursion)
    #[serde(serialize_with = "serialize_array", deserialize_with = "deserialize_array")]
    pub previous_proof_hash: [u8; 64],
    
    /// Snapshot number this proof corresponds to
    pub snapshot_number: u64,
}

/// Helper functions for serializing/deserializing fixed-size arrays
fn serialize_array<S>(arr: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(arr)
}

fn deserialize_array<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
where
    D: Deserializer<'de>,
{
    let vec: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
    if vec.len() != 64 {
        return Err(serde::de::Error::custom("Expected 64 bytes"));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&vec);
    Ok(arr)
}

/// Metadata about a proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// When the proof was generated
    pub timestamp: SystemTime,
    
    /// Who generated the proof (validator address)
    pub prover: Vec<u8>,
    
    /// Number of transactions included in this snapshot
    pub transaction_count: u64,
    
    /// Time taken to generate the proof (milliseconds)
    pub generation_time_ms: u64,
    
    /// Whether GPU acceleration was used
    pub gpu_accelerated: bool,
}

/// Proving key for generating proofs
#[derive(Clone)]
pub struct ProvingKey {
    pub key_data: Vec<u8>,
}

/// Verifying key for verifying proofs
#[derive(Clone, Serialize, Deserialize)]
pub struct VerifyingKey {
    pub key_data: Vec<u8>,
}

impl Proof {
    /// Calculate the hash of this proof for use in the next recursive proof
    pub fn hash(&self) -> [u8; 64] {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(&self.proof_data);
        hasher.update(&self.state_root);
        hasher.update(&self.previous_proof_hash);
        hasher.update(&self.snapshot_number.to_le_bytes());
        
        let hash = hasher.finalize();
        let mut result = [0u8; 64];
        result[..32].copy_from_slice(hash.as_bytes());
        // Extend to 512 bits by hashing again
        let mut hasher2 = Hasher::new();
        hasher2.update(hash.as_bytes());
        result[32..].copy_from_slice(hasher2.finalize().as_bytes());
        result
    }

    /// Get the size of the proof in bytes
    pub fn size(&self) -> usize {
        self.proof_data.len()
    }
}
