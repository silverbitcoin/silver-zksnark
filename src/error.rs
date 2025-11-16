use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZkSnarkError {
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid circuit: {0}")]
    InvalidCircuit(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid proof format")]
    InvalidProofFormat,

    #[error("Missing proving key")]
    MissingProvingKey,

    #[error("Missing verifying key")]
    MissingVerifyingKey,

    #[error("GPU acceleration error: {0}")]
    GpuError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ZkSnarkError>;
