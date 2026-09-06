use std::path::PathBuf;

/// Errors that can occur while splitting, encrypting, decrypting, or
/// reconstructing shards.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The private key bytes do not form a valid secp256k1 scalar.
    #[error("invalid private key: {0}")]
    InvalidKey(String),

    /// Invalid threshold/share-count combination.
    #[error("invalid secret-sharing parameters: {0}")]
    InvalidParams(String),

    /// Not enough valid shards to reconstruct the key.
    #[error("need {0} shards but only {1} were provided")]
    NotEnoughShares(usize, usize),

    /// Decryption failed; typically a wrong password or tampered file.
    #[error("failed to decrypt shard {id}: {reason}")]
    Decrypt { id: u8, reason: String },

    /// Password-based key derivation failed.
    #[error("key derivation failed: {0}")]
    Kdf(String),

    /// Authenticated encryption failed.
    #[error("authenticated encryption failed: {0}")]
    Aead(String),

    /// The shard file is not a valid horcrux shard.
    #[error("invalid shard file: {0}")]
    InvalidShardFile(String),

    /// Two shards from different splits were mixed together.
    #[error("shard {path:?} has different split parameters (t={t}, n={n})")]
    SplitMismatch { path: PathBuf, t: u8, n: u8 },

    /// A FROST share from a different group was mixed into the signing set.
    #[error("share {path:?} belongs to a different FROST group")]
    MpcGroupMismatch { path: PathBuf },

    /// A FROST (Mode B) operation failed.
    #[error("mpc error: {0}")]
    Mpc(String),

    /// An HX3 (air-gapped QR transport) frame was malformed or corrupt.
    #[error("hx3 frame error: {0}")]
    Hx3(String),

    /// A QR code image could not be encoded or decoded.
    #[error("qr transport error: {0}")]
    Qr(String),

    /// The underlying secret-sharing library failed.
    #[error("secret-sharing error: {0}")]
    Vsss(String),

    /// I/O error while reading or writing a shard file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to build, sign, or broadcast a Solana transaction.
    #[error("transaction error: {0}")]
    Tx(String),

    /// Failed to build or sign a Bitcoin (Taproot) transaction.
    #[error("bitcoin error: {0}")]
    Bitcoin(String),

    /// Failed to build or sign a Cosmos SDK transaction.
    #[error("cosmos error: {0}")]
    Cosmos(String),

    /// The audit layer refused the attempt before any key material was used.
    #[error("access audit blocked the attempt: {0}")]
    Blocked(String),

    /// The access log could not be read or written.
    #[error("audit log error: {0}")]
    Audit(String),
}
