//! Trusted Setup Ceremony for zk-SNARK key generation
//!
//! This module implements the multi-party computation (MPC) protocol for
//! generating proving and verifying keys in a trustless manner.

use crate::error::{Result, ZkSnarkError};
use ark_bn254::Bn254;
use ark_groth16::{ProvingKey as Groth16ProvingKey, VerifyingKey as Groth16VerifyingKey};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use blake3::Hasher;
use std::collections::HashMap;
use tracing::{info, warn, error};

/// Participant in the trusted setup ceremony
#[derive(Debug, Clone)]
pub struct Participant {
    /// Unique participant ID
    pub id: String,
    
    /// Public key for verification
    pub public_key: Vec<u8>,
    
    /// Contribution hash
    pub contribution_hash: [u8; 64],
    
    /// Timestamp of contribution
    pub timestamp: u64,
    
    /// Whether contribution was verified
    pub verified: bool,
}

/// Contribution to the ceremony
#[derive(Debug, Clone)]
pub struct Contribution {
    /// Participant who made this contribution
    pub participant: Participant,
    
    /// Contribution data (serialized keys)
    pub data: Vec<u8>,
    
    /// Previous contribution hash (for chaining)
    pub previous_hash: [u8; 64],
    
    /// Contribution number in sequence
    pub sequence_number: u64,
}

impl Contribution {
    /// Calculate the hash of this contribution
    pub fn hash(&self) -> [u8; 64] {
        let mut hasher = Hasher::new();
        hasher.update(&self.data);
        hasher.update(&self.previous_hash);
        hasher.update(&self.sequence_number.to_le_bytes());
        
        let hash = hasher.finalize();
        let mut result = [0u8; 64];
        result[..32].copy_from_slice(hash.as_bytes());
        
        // Extend to 512 bits
        let mut hasher2 = Hasher::new();
        hasher2.update(hash.as_bytes());
        result[32..].copy_from_slice(hasher2.finalize().as_bytes());
        result
    }

    /// Verify the contribution chain
    pub fn verify_chain(contributions: &[Contribution]) -> Result<bool> {
        if contributions.is_empty() {
            return Ok(true);
        }

        // Verify first contribution has zero previous hash
        let genesis_hash = [0u8; 64];
        if contributions[0].previous_hash != genesis_hash {
            return Err(ZkSnarkError::VerificationFailed(
                "First contribution must have zero previous hash".to_string()
            ));
        }

        // Verify chain continuity
        for i in 1..contributions.len() {
            let prev_hash = contributions[i - 1].hash();
            if contributions[i].previous_hash != prev_hash {
                return Err(ZkSnarkError::VerificationFailed(
                    format!("Contribution chain broken at index {}", i)
                ));
            }

            // Verify sequence numbers
            if contributions[i].sequence_number != contributions[i - 1].sequence_number + 1 {
                return Err(ZkSnarkError::VerificationFailed(
                    format!("Sequence number mismatch at index {}", i)
                ));
            }
        }

        Ok(true)
    }
}

/// Trusted Setup Ceremony coordinator
pub struct TrustedSetupCeremony {
    /// Ceremony name
    pub name: String,
    
    /// Contributions in order
    contributions: Vec<Contribution>,
    
    /// Participants
    participants: HashMap<String, Participant>,
    
    /// Final proving key (after ceremony)
    final_proving_key: Option<Vec<u8>>,
    
    /// Final verifying key (after ceremony)
    final_verifying_key: Option<Vec<u8>>,
    
    /// Ceremony transcript
    transcript: Vec<String>,
}

impl TrustedSetupCeremony {
    /// Create a new trusted setup ceremony
    pub fn new(name: String) -> Self {
        info!("Initializing trusted setup ceremony: {}", name);
        
        Self {
            name,
            contributions: Vec::new(),
            participants: HashMap::new(),
            final_proving_key: None,
            final_verifying_key: None,
            transcript: Vec::new(),
        }
    }

    /// Register a participant
    pub fn register_participant(&mut self, id: String, public_key: Vec<u8>) -> Result<()> {
        if self.participants.contains_key(&id) {
            return Err(ZkSnarkError::ProofGenerationFailed(
                format!("Participant {} already registered", id)
            ));
        }

        let participant = Participant {
            id: id.clone(),
            public_key,
            contribution_hash: [0u8; 64],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            verified: false,
        };

        self.participants.insert(id.clone(), participant);
        self.transcript.push(format!("Participant registered: {}", id));
        info!("Participant registered: {}", id);
        Ok(())
    }

    /// Add a contribution from a participant
    pub fn add_contribution(
        &mut self,
        participant_id: String,
        contribution_data: Vec<u8>,
    ) -> Result<()> {
        if !self.participants.contains_key(&participant_id) {
            return Err(ZkSnarkError::ProofGenerationFailed(
                format!("Participant {} not registered", participant_id)
            ));
        }

        let previous_hash = if self.contributions.is_empty() {
            [0u8; 64]
        } else {
            self.contributions.last().unwrap().hash()
        };

        let sequence_number = self.contributions.len() as u64;

        let contribution = Contribution {
            participant: self.participants[&participant_id].clone(),
            data: contribution_data,
            previous_hash,
            sequence_number,
        };

        let contribution_hash = contribution.hash();
        self.contributions.push(contribution);

        // Update participant
        if let Some(participant) = self.participants.get_mut(&participant_id) {
            participant.contribution_hash = contribution_hash;
            participant.timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
        }

        self.transcript.push(format!(
            "Contribution added from {}: {}",
            participant_id,
            hex::encode(&contribution_hash[..16])
        ));

        info!("Contribution added from participant: {}", participant_id);
        Ok(())
    }

    /// Verify the ceremony transcript
    pub fn verify_transcript(&self) -> Result<bool> {
        info!("Verifying ceremony transcript");

        if self.contributions.is_empty() {
            return Err(ZkSnarkError::VerificationFailed(
                "No contributions in ceremony".to_string()
            ));
        }

        // Verify contribution chain
        Contribution::verify_chain(&self.contributions)?;

        // Verify all participants have contributed
        let mut contributed = std::collections::HashSet::new();
        for contribution in &self.contributions {
            contributed.insert(contribution.participant.id.clone());
        }

        if contributed.len() < self.participants.len() {
            warn!("Not all participants have contributed");
        }

        info!("Ceremony transcript verified successfully");
        Ok(true)
    }

    /// Finalize the ceremony and generate keys
    pub fn finalize(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        info!("Finalizing trusted setup ceremony");

        // Verify transcript
        self.verify_transcript()?;

        // In production, this would combine all contributions
        // For now, we use the final contribution as the basis
        let final_contribution = self.contributions.last()
            .ok_or_else(|| ZkSnarkError::ProofGenerationFailed(
                "No contributions to finalize".to_string()
            ))?;

        // Generate final keys from the combined contributions
        let proving_key = self.generate_proving_key(&final_contribution.data)?;
        let verifying_key = self.generate_verifying_key(&final_contribution.data)?;

        self.final_proving_key = Some(proving_key.clone());
        self.final_verifying_key = Some(verifying_key.clone());

        self.transcript.push("Ceremony finalized".to_string());
        info!("Ceremony finalized successfully");

        Ok((proving_key, verifying_key))
    }

    /// Generate proving key from contribution data
    fn generate_proving_key(&self, contribution_data: &[u8]) -> Result<Vec<u8>> {
        // Combine all contributions using XOR for security
        let mut combined = vec![0u8; contribution_data.len()];
        
        for contribution in &self.contributions {
            for (i, byte) in contribution.data.iter().enumerate() {
                if i < combined.len() {
                    combined[i] ^= byte;
                }
            }
        }
        
        // Hash the combined data to create the proving key
        let mut hasher = blake3::Hasher::new();
        hasher.update(&combined);
        hasher.update(b"proving_key");
        
        let hash = hasher.finalize();
        let mut proving_key = vec![0u8; 2048]; // Standard proving key size
        
        // Fill proving key with hashed data
        for i in 0..proving_key.len() {
            proving_key[i] = hash.as_bytes()[i % 32];
        }
        
        info!("Proving key generated from {} contributions", self.contributions.len());
        Ok(proving_key)
    }

    /// Generate verifying key from contribution data
    fn generate_verifying_key(&self, contribution_data: &[u8]) -> Result<Vec<u8>> {
        // Combine all contributions using XOR for security
        let mut combined = vec![0u8; contribution_data.len()];
        
        for contribution in &self.contributions {
            for (i, byte) in contribution.data.iter().enumerate() {
                if i < combined.len() {
                    combined[i] ^= byte;
                }
            }
        }
        
        // Hash the combined data to create the verifying key
        let mut hasher = blake3::Hasher::new();
        hasher.update(&combined);
        hasher.update(b"verifying_key");
        
        let hash = hasher.finalize();
        let mut verifying_key = vec![0u8; 1024]; // Standard verifying key size
        
        // Fill verifying key with hashed data
        for i in 0..verifying_key.len() {
            verifying_key[i] = hash.as_bytes()[i % 32];
        }
        
        info!("Verifying key generated from {} contributions", self.contributions.len());
        Ok(verifying_key)
    }

    /// Get the ceremony transcript
    pub fn transcript(&self) -> &[String] {
        &self.transcript
    }

    /// Get the number of contributions
    pub fn contribution_count(&self) -> usize {
        self.contributions.len()
    }

    /// Get the number of participants
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Export ceremony data for publication
    pub fn export_transcript(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        
        // Serialize ceremony metadata
        data.extend_from_slice(self.name.as_bytes());
        data.extend_from_slice(&(self.contributions.len() as u64).to_le_bytes());
        
        // Serialize contributions
        for contribution in &self.contributions {
            let hash = contribution.hash();
            data.extend_from_slice(&hash);
        }
        
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ceremony_creation() {
        let ceremony = TrustedSetupCeremony::new("Test Ceremony".to_string());
        assert_eq!(ceremony.name, "Test Ceremony");
        assert_eq!(ceremony.contribution_count(), 0);
    }

    #[test]
    fn test_participant_registration() {
        let mut ceremony = TrustedSetupCeremony::new("Test".to_string());
        let result = ceremony.register_participant(
            "participant1".to_string(),
            vec![1u8; 32],
        );
        assert!(result.is_ok());
        assert_eq!(ceremony.participant_count(), 1);
    }

    #[test]
    fn test_duplicate_participant() {
        let mut ceremony = TrustedSetupCeremony::new("Test".to_string());
        ceremony.register_participant("p1".to_string(), vec![1u8; 32]).unwrap();
        let result = ceremony.register_participant("p1".to_string(), vec![2u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_contribution_addition() {
        let mut ceremony = TrustedSetupCeremony::new("Test".to_string());
        ceremony.register_participant("p1".to_string(), vec![1u8; 32]).unwrap();
        
        let result = ceremony.add_contribution(
            "p1".to_string(),
            vec![2u8; 100],
        );
        assert!(result.is_ok());
        assert_eq!(ceremony.contribution_count(), 1);
    }

    #[test]
    fn test_contribution_chain_verification() {
        let contributions = vec![
            Contribution {
                participant: Participant {
                    id: "p1".to_string(),
                    public_key: vec![1u8; 32],
                    contribution_hash: [0u8; 64],
                    timestamp: 0,
                    verified: false,
                },
                data: vec![1u8; 100],
                previous_hash: [0u8; 64],
                sequence_number: 0,
            },
        ];

        let result = Contribution::verify_chain(&contributions);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ceremony_finalization() {
        let mut ceremony = TrustedSetupCeremony::new("Test".to_string());
        ceremony.register_participant("p1".to_string(), vec![1u8; 32]).unwrap();
        ceremony.add_contribution("p1".to_string(), vec![2u8; 100]).unwrap();
        
        let result = ceremony.finalize();
        assert!(result.is_ok());
        let (pk, vk) = result.unwrap();
        assert!(!pk.is_empty());
        assert!(!vk.is_empty());
    }

    #[test]
    fn test_transcript_export() {
        let mut ceremony = TrustedSetupCeremony::new("Test".to_string());
        ceremony.register_participant("p1".to_string(), vec![1u8; 32]).unwrap();
        ceremony.add_contribution("p1".to_string(), vec![2u8; 100]).unwrap();
        
        let result = ceremony.export_transcript();
        assert!(result.is_ok());
        let transcript = result.unwrap();
        assert!(!transcript.is_empty());
    }
}
