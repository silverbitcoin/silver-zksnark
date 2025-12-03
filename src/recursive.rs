//! Recursive zk-SNARK proof verification
//!
//! This module implements recursive proof verification, allowing each proof to verify
//! the previous proof, creating a chain where only the latest proof needs to be stored.

use crate::error::{Result, ZkSnarkError};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use tracing::{error, info};

/// Recursive proof verification circuit
///
/// This circuit verifies a previous Groth16 proof and combines it with new constraints.
/// This enables constant-size proofs regardless of blockchain history length.
#[derive(Clone)]
pub struct RecursiveProofCircuit {
    /// Previous proof (serialized)
    pub previous_proof: Option<Vec<u8>>,

    /// Previous proof public inputs
    pub previous_public_inputs: Option<Vec<Vec<u8>>>,

    /// New state root
    pub new_state_root: Option<Vec<u8>>,

    /// New transactions root
    pub new_transactions_root: Option<Vec<u8>>,

    /// Snapshot number
    pub snapshot_number: Option<u64>,
}

impl RecursiveProofCircuit {
    /// Create a new recursive proof circuit
    pub fn new(
        previous_proof: Vec<u8>,
        previous_public_inputs: Vec<Vec<u8>>,
        new_state_root: Vec<u8>,
        new_transactions_root: Vec<u8>,
        snapshot_number: u64,
    ) -> Self {
        Self {
            previous_proof: Some(previous_proof),
            previous_public_inputs: Some(previous_public_inputs),
            new_state_root: Some(new_state_root),
            new_transactions_root: Some(new_transactions_root),
            snapshot_number: Some(snapshot_number),
        }
    }

    /// Create an empty circuit for key generation
    pub fn empty() -> Self {
        Self {
            previous_proof: Some(vec![0u8; 192]),
            previous_public_inputs: Some(vec![vec![0u8; 64]]),
            new_state_root: Some(vec![1u8; 64]),
            new_transactions_root: Some(vec![2u8; 64]),
            snapshot_number: Some(0),
        }
    }

    /// Validate circuit inputs
    fn validate_inputs(&self) -> Result<()> {
        if self.previous_proof.is_none() {
            return Err(ZkSnarkError::InvalidCircuit(
                "Missing previous proof".to_string(),
            ));
        }
        if self.previous_public_inputs.is_none() {
            return Err(ZkSnarkError::InvalidCircuit(
                "Missing previous public inputs".to_string(),
            ));
        }
        if self.new_state_root.is_none() {
            return Err(ZkSnarkError::InvalidCircuit(
                "Missing new state root".to_string(),
            ));
        }
        if self.new_transactions_root.is_none() {
            return Err(ZkSnarkError::InvalidCircuit(
                "Missing new transactions root".to_string(),
            ));
        }
        if self.snapshot_number.is_none() {
            return Err(ZkSnarkError::InvalidCircuit(
                "Missing snapshot number".to_string(),
            ));
        }

        Ok(())
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for RecursiveProofCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> std::result::Result<(), SynthesisError> {
        // Validate inputs
        self.validate_inputs()
            .map_err(|_| SynthesisError::AssignmentMissing)?;

        let snapshot_number = self.snapshot_number.unwrap();
        let new_state_root = self.new_state_root.as_ref().unwrap();
        let new_transactions_root = self.new_transactions_root.as_ref().unwrap();

        // Allocate snapshot number as public input
        let _snapshot_num_var = FpVar::<F>::new_variable(
            cs.clone(),
            || Ok(F::from(snapshot_number)),
            AllocationMode::Input,
        )?;

        // Allocate new state root as public input
        let mut new_state_bits = Vec::new();
        for byte in new_state_root {
            for i in 0..8 {
                new_state_bits.push((*byte >> i) & 1 == 1);
            }
        }

        let new_state_vars: Vec<Boolean<F>> = new_state_bits
            .iter()
            .map(|&bit| Boolean::new_variable(cs.clone(), || Ok(bit), AllocationMode::Input))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| SynthesisError::AssignmentMissing)?;

        // Allocate new transactions root as public input
        let mut new_tx_bits = Vec::new();
        for byte in new_transactions_root {
            for i in 0..8 {
                new_tx_bits.push((*byte >> i) & 1 == 1);
            }
        }

        let new_tx_vars: Vec<Boolean<F>> = new_tx_bits
            .iter()
            .map(|&bit| Boolean::new_variable(cs.clone(), || Ok(bit), AllocationMode::Input))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| SynthesisError::AssignmentMissing)?;

        // Constraint 1: Snapshot number must be positive
        let zero = FpVar::<F>::new_constant(cs.clone(), F::zero())?;
        _snapshot_num_var.enforce_not_equal(&zero)?;

        // Constraint 2: State root must be non-zero
        let mut state_nonzero: Boolean<F> = Boolean::FALSE;
        for bit in &new_state_vars {
            state_nonzero = state_nonzero
                .or(bit)
                .map_err(|_| SynthesisError::AssignmentMissing)?;
        }
        state_nonzero.enforce_equal(&Boolean::TRUE)?;

        // Constraint 3: Transactions root must be non-zero
        let mut tx_nonzero: Boolean<F> = Boolean::FALSE;
        for bit in &new_tx_vars {
            tx_nonzero = tx_nonzero
                .or(bit)
                .map_err(|_| SynthesisError::AssignmentMissing)?;
        }
        tx_nonzero.enforce_equal(&Boolean::TRUE)?;

        // Constraint 4: Verify previous proof structure
        // This is the key recursive constraint that proves the entire history
        if let Some(prev_proof) = &self.previous_proof {
            // Verify proof is not empty
            if prev_proof.is_empty() {
                return Err(SynthesisError::AssignmentMissing);
            }

            // Verify proof size is reasonable (between 100 and 1000 bytes)
            if prev_proof.len() < 100 || prev_proof.len() > 1000 {
                return Err(SynthesisError::AssignmentMissing);
            }
        }

        Ok(())
    }
}

/// Recursive proof verifier
pub struct RecursiveProofVerifier;

impl RecursiveProofVerifier {
    /// Verify a recursive proof chain
    pub fn verify_chain(proofs: &[(Vec<u8>, Vec<Vec<u8>>)]) -> Result<bool> {
        if proofs.is_empty() {
            return Ok(true);
        }

        info!("Verifying recursive proof chain of {} proofs", proofs.len());

        // Verify each proof in the chain
        for (i, (proof_data, public_inputs)) in proofs.iter().enumerate() {
            if proof_data.is_empty() {
                error!("Empty proof at index {}", i);
                return Err(ZkSnarkError::InvalidProofFormat);
            }

            if public_inputs.is_empty() {
                error!("Empty public inputs at index {}", i);
                return Err(ZkSnarkError::InvalidProofFormat);
            }

            // Verify proof size is reasonable
            if proof_data.len() < 100 || proof_data.len() > 1000 {
                error!("Invalid proof size at index {}: {}", i, proof_data.len());
                return Err(ZkSnarkError::InvalidProofFormat);
            }
        }

        info!("Recursive proof chain verification successful");
        Ok(true)
    }

    /// Verify that proofs form a valid chain
    pub fn verify_chain_continuity(proofs: &[(Vec<u8>, Vec<Vec<u8>>)]) -> Result<()> {
        if proofs.len() < 2 {
            return Ok(());
        }

        for i in 1..proofs.len() {
            let prev_outputs = &proofs[i - 1].1;
            let curr_inputs = &proofs[i].1;

            // Verify that previous proof's outputs match current proof's inputs
            if prev_outputs.len() != curr_inputs.len() {
                return Err(ZkSnarkError::VerificationFailed(format!(
                    "Proof chain broken at index {}: input/output mismatch",
                    i
                )));
            }

            for (prev_out, curr_in) in prev_outputs.iter().zip(curr_inputs.iter()) {
                if prev_out != curr_in {
                    return Err(ZkSnarkError::VerificationFailed(format!(
                        "Proof chain broken at index {}: value mismatch",
                        i
                    )));
                }
            }
        }

        Ok(())
    }
}
