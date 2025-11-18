//! Merkle tree verification for transaction batches
//!
//! This module provides optimized Merkle tree operations for verifying
//! transaction batches in zk-SNARK circuits.

use crate::error::{Result, ZkSnarkError};
use blake3::Hasher;
use std::collections::HashMap;
use tracing::info;

/// Merkle tree node
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleNode {
    /// Hash of this node (64 bytes for Blake3-512)
    pub hash: [u8; 64],
    
    /// Left child hash (if internal node)
    pub left: Option<Box<MerkleNode>>,
    
    /// Right child hash (if internal node)
    pub right: Option<Box<MerkleNode>>,
    
    /// Whether this is a leaf node
    pub is_leaf: bool,
}

impl MerkleNode {
    /// Create a leaf node from data
    pub fn leaf(data: &[u8]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(data);
        let hash_result = hasher.finalize();
        
        let mut hash = [0u8; 64];
        hash[..32].copy_from_slice(hash_result.as_bytes());
        
        // Extend to 512 bits
        let mut hasher2 = Hasher::new();
        hasher2.update(hash_result.as_bytes());
        hash[32..].copy_from_slice(hasher2.finalize().as_bytes());
        
        Self {
            hash,
            left: None,
            right: None,
            is_leaf: true,
        }
    }

    /// Create an internal node from two children
    pub fn internal(left: MerkleNode, right: MerkleNode) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(&left.hash);
        hasher.update(&right.hash);
        let hash_result = hasher.finalize();
        
        let mut hash = [0u8; 64];
        hash[..32].copy_from_slice(hash_result.as_bytes());
        
        // Extend to 512 bits
        let mut hasher2 = Hasher::new();
        hasher2.update(hash_result.as_bytes());
        hash[32..].copy_from_slice(hasher2.finalize().as_bytes());
        
        Self {
            hash,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
            is_leaf: false,
        }
    }
}

/// Merkle tree for transaction batches
pub struct MerkleTree {
    /// Root node
    root: Option<MerkleNode>,
    
    /// Leaf nodes (for quick access)
    leaves: Vec<MerkleNode>,
    
    /// Cache of node hashes for performance
    hash_cache: HashMap<Vec<u8>, [u8; 64]>,
}

impl MerkleTree {
    /// Create a new Merkle tree from transaction hashes
    pub fn new(transaction_hashes: Vec<Vec<u8>>) -> Result<Self> {
        if transaction_hashes.is_empty() {
            return Err(ZkSnarkError::InvalidCircuit("Cannot create Merkle tree with no transactions".to_string()));
        }

        if transaction_hashes.len() > 500 {
            return Err(ZkSnarkError::InvalidCircuit("Too many transactions for Merkle tree".to_string()));
        }

        info!("Creating Merkle tree for {} transactions", transaction_hashes.len());

        // Create leaf nodes
        let mut leaves: Vec<MerkleNode> = transaction_hashes
            .iter()
            .map(|tx_hash| MerkleNode::leaf(tx_hash))
            .collect();

        // Build tree bottom-up
        while leaves.len() > 1 {
            let mut next_level = Vec::new();
            
            for i in (0..leaves.len()).step_by(2) {
                let left = leaves[i].clone();
                let right = if i + 1 < leaves.len() {
                    leaves[i + 1].clone()
                } else {
                    // Duplicate last node if odd number
                    left.clone()
                };
                
                next_level.push(MerkleNode::internal(left, right));
            }
            
            leaves = next_level;
        }

        let root = leaves.pop();

        Ok(Self {
            root,
            leaves: transaction_hashes
                .iter()
                .map(|tx_hash| MerkleNode::leaf(tx_hash))
                .collect(),
            hash_cache: HashMap::new(),
        })
    }

    /// Get the root hash
    pub fn root_hash(&self) -> Result<[u8; 64]> {
        self.root
            .as_ref()
            .map(|node| node.hash)
            .ok_or_else(|| ZkSnarkError::InvalidCircuit("No root node".to_string()))
    }

    /// Verify a transaction is in the tree
    pub fn verify_transaction(&self, transaction_hash: &[u8], proof_path: &[[u8; 64]]) -> Result<bool> {
        let leaf = MerkleNode::leaf(transaction_hash);
        let mut current_hash = leaf.hash;

        // Traverse up the tree using the proof path
        for proof_node_hash in proof_path {
            let mut hasher = Hasher::new();
            hasher.update(&current_hash);
            hasher.update(proof_node_hash);
            let hash_result = hasher.finalize();
            
            let mut new_hash = [0u8; 64];
            new_hash[..32].copy_from_slice(hash_result.as_bytes());
            
            let mut hasher2 = Hasher::new();
            hasher2.update(hash_result.as_bytes());
            new_hash[32..].copy_from_slice(hasher2.finalize().as_bytes());
            
            current_hash = new_hash;
        }

        // Verify we reached the root
        let root_hash = self.root_hash()?;
        Ok(current_hash == root_hash)
    }

    /// Get the proof path for a transaction
    pub fn get_proof_path(&self, transaction_index: usize) -> Result<Vec<[u8; 64]>> {
        if transaction_index >= self.leaves.len() {
            return Err(ZkSnarkError::InvalidCircuit("Transaction index out of bounds".to_string()));
        }

        let mut proof_path = Vec::new();
        let mut current_index = transaction_index;
        let mut level_size = self.leaves.len();

        // Traverse from leaf to root
        while level_size > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < level_size {
                let sibling_hash = self.leaves[sibling_index].hash;
                proof_path.push(sibling_hash);
            }

            current_index /= 2;
            level_size = (level_size + 1) / 2;
        }

        Ok(proof_path)
    }

    /// Get the number of leaves
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Get the tree depth
    pub fn depth(&self) -> usize {
        let mut depth = 0;
        let mut size = self.leaves.len();
        while size > 1 {
            size = (size + 1) / 2;
            depth += 1;
        }
        depth
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_creation() {
        let transactions = vec![
            vec![1u8; 32],
            vec![2u8; 32],
            vec![3u8; 32],
            vec![4u8; 32],
        ];

        let tree = MerkleTree::new(transactions).expect("Failed to create tree");
        assert_eq!(tree.leaf_count(), 4);
        assert!(tree.root_hash().is_ok());
    }

    #[test]
    fn test_merkle_tree_single_transaction() {
        let transactions = vec![vec![1u8; 32]];
        let tree = MerkleTree::new(transactions).expect("Failed to create tree");
        assert_eq!(tree.leaf_count(), 1);
    }

    #[test]
    fn test_merkle_tree_odd_transactions() {
        let transactions = vec![
            vec![1u8; 32],
            vec![2u8; 32],
            vec![3u8; 32],
        ];

        let tree = MerkleTree::new(transactions).expect("Failed to create tree");
        assert_eq!(tree.leaf_count(), 3);
    }

    #[test]
    fn test_merkle_tree_depth() {
        let transactions = vec![
            vec![1u8; 32],
            vec![2u8; 32],
            vec![3u8; 32],
            vec![4u8; 32],
        ];

        let tree = MerkleTree::new(transactions).expect("Failed to create tree");
        assert_eq!(tree.depth(), 2);
    }

    #[test]
    fn test_merkle_tree_empty() {
        let transactions: Vec<Vec<u8>> = vec![];
        let result = MerkleTree::new(transactions);
        assert!(result.is_err());
    }

    #[test]
    fn test_merkle_tree_too_many() {
        let transactions: Vec<Vec<u8>> = (0..501).map(|i| vec![i as u8; 32]).collect();
        let result = MerkleTree::new(transactions);
        assert!(result.is_err());
    }

    #[test]
    fn test_merkle_proof_path() {
        let transactions = vec![
            vec![1u8; 32],
            vec![2u8; 32],
            vec![3u8; 32],
            vec![4u8; 32],
        ];

        let tree = MerkleTree::new(transactions).expect("Failed to create tree");
        let proof = tree.get_proof_path(0).expect("Failed to get proof");
        assert!(!proof.is_empty());
    }

    #[test]
    fn test_merkle_verification() {
        let transactions = vec![
            vec![1u8; 32],
            vec![2u8; 32],
            vec![3u8; 32],
            vec![4u8; 32],
        ];

        let tree = MerkleTree::new(transactions.clone()).expect("Failed to create tree");
        let proof = tree.get_proof_path(0).expect("Failed to get proof");
        
        let result = tree.verify_transaction(&transactions[0], &proof);
        assert!(result.is_ok());
    }
}
