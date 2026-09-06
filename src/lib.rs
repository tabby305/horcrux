//! horcrux — split an Ed25519 signing seed via Shamir's Secret Sharing (over the
//! secp256k1 field), encrypt the shares with per-shard guardian passwords
//! (Argon2id + AES-256-GCM), reconstruct the seed from any threshold subset of
//! shard files, and sign Solana, Bitcoin (Taproot), and Cosmos SDK
//! transactions. Mode B adds FROST threshold signatures (`src/mpc.rs`): the
//! same seed is dealer-split into key shares so signing never reconstructs the
//! key on any machine.

pub mod audit;
pub mod bitcoin;
pub mod chain;
pub mod cosmos;
pub mod crypto;
pub mod error;
pub mod mpc;
pub mod qr;
pub mod qr_mpc;
pub mod shard;
pub mod sss;
pub mod tx;
pub mod verify;

use crate::error::Error;
use crate::shard::{Shard, aad};
use crate::tx::{SignedTx, TxParams};
use k256::elliptic_curve::ff::PrimeField;
use k256::{Scalar, SecretKey};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

pub const SHARD_MAGIC: &[u8; 3] = b"HX1";
pub const SHARD_VERSION: u8 = 1;

/// KDF memory cost in KiB (Argon2id, OWASP interactive-class defaults).
pub const ARGON2_M_COST: u32 = 19 * 1024;
/// KDF time cost.
pub const ARGON2_T_COST: u32 = 2;
/// KDF parallelism.
pub const ARGON2_P_COST: u32 = 1;

/// Length of the per-shard Argon2id salt, in bytes.
pub const SALT_LEN: usize = 16;
/// Length of the AES-256-GCM nonce, in bytes.
pub const NONCE_LEN: usize = 12;
/// Length of the AES-256-GCM authentication tag, in bytes.
pub const TAG_LEN: usize = 16;
/// Length of a share value, in bytes (a secp256k1 scalar).
pub const SHARE_VALUE_LEN: usize = 32;

/// Split a private key into `share_count` encrypted shard files written to
/// `out_dir`, each bound to one of `passwords` (one guardian password per
/// shard, in the same order).
///
/// Returns the paths of the written shard files.
pub fn init_shards(
    key: &SecretKey,
    threshold: u8,
    share_count: u8,
    out_dir: &Path,
    passwords: &[String],
) -> Result<Vec<PathBuf>, Error> {
    if threshold == 0 || threshold > share_count {
        return Err(Error::InvalidParams(format!(
            "threshold ({threshold}) must be between 1 and share count ({share_count})"
        )));
    }
    if passwords.len() != share_count as usize {
        return Err(Error::InvalidParams(format!(
            "expected {share_count} passwords, got {}",
            passwords.len()
        )));
    }

    let shares = sss::split(key, threshold as usize, share_count as usize)?;
    fs::create_dir_all(out_dir)?;

    let mut paths = Vec::with_capacity(shares.len());
    for (i, share) in shares.iter().enumerate() {
        let id = share_id(share);
        let salt = crypto::random_salt();
        let nonce = crypto::random_nonce();
        let aad = aad(threshold, share_count, id);

        let mut value_bytes = Zeroizing::new(share.value.to_repr().to_vec());
        let sealed = crypto::seal(&value_bytes, &passwords[i], &salt, &nonce, &aad)?;
        value_bytes.zeroize();

        let mut sealed_arr = [0u8; SHARE_VALUE_LEN + TAG_LEN];
        sealed_arr.copy_from_slice(&sealed);

        let shard = Shard::new(threshold, share_count, id, salt, nonce, sealed_arr);
        let path = out_dir.join(format!("shard-{id}.hx"));
        shard.write(&path)?;
        paths.push(path);
    }
    Ok(paths)
}

/// Reconstruct a private key from shard files.
///
/// Each shard is decrypted with the guardian password at the corresponding
/// position in `passwords`. All shards must come from the same split (same
/// threshold and share count), and at least `threshold` of them must be
/// supplied.
///
/// Note: the reconstructed [`SecretKey`] is returned for the caller to use
/// and wipe; the intermediate share values are zeroized automatically.
pub fn reconstruct(shard_paths: &[PathBuf], passwords: &[String]) -> Result<SecretKey, Error> {
    reconstruct_inner(shard_paths, passwords, |_, _| {})
}

/// Reconstruct a private key from shard files, recording each shard's
/// decryption outcome in an [`audit::AccessLog`].
///
/// Logging is best-effort: a failure to write a log entry does not abort the
/// reconstruction. The caller is responsible for pre-flight scoring via
/// [`audit::Scorer`] before invoking this.
pub fn reconstruct_with_audit(
    shard_paths: &[PathBuf],
    passwords: &[String],
    log: &audit::AccessLog,
    attempt: u64,
) -> Result<SecretKey, Error> {
    let ts = audit::now_ms();
    reconstruct_inner(shard_paths, passwords, |id, ok| {
        let entry = if ok {
            audit::Entry::ok(ts, attempt, id)
        } else {
            audit::Entry::fail(ts, attempt, id)
        };
        let _ = log.append(&entry);
    })
}

/// Shared implementation of [`reconstruct`], invoking `on_shard` with the id
/// and outcome of each shard decryption.
fn reconstruct_inner(
    shard_paths: &[PathBuf],
    passwords: &[String],
    mut on_shard: impl FnMut(u8, bool),
) -> Result<SecretKey, Error> {
    if passwords.len() != shard_paths.len() {
        return Err(Error::InvalidParams(format!(
            "expected {} passwords, got {}",
            shard_paths.len(),
            passwords.len()
        )));
    }

    let shards: Vec<Shard> = shard_paths
        .iter()
        .map(|p| Shard::read(p))
        .collect::<Result<_, _>>()?;
    if shards.is_empty() {
        return Err(Error::InvalidParams("no shards provided".to_string()));
    }

    let threshold = shards[0].threshold;
    let share_count = shards[0].share_count;
    for (idx, shard) in shards.iter().enumerate() {
        if shard.threshold != threshold || shard.share_count != share_count {
            return Err(Error::SplitMismatch {
                path: shard_paths[idx].clone(),
                t: shard.threshold,
                n: shard.share_count,
            });
        }
    }
    if shards.len() < threshold as usize {
        return Err(Error::NotEnoughShares(threshold as usize, shards.len()));
    }

    let mut shares = Vec::with_capacity(shards.len());
    for (shard, password) in shards.iter().zip(passwords) {
        let value = match shard.decrypt(password) {
            Ok(v) => {
                on_shard(shard.id, true);
                v
            }
            Err(e) => {
                on_shard(shard.id, false);
                return Err(e);
            }
        };
        let value_bytes: [u8; SHARE_VALUE_LEN] = value
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidShardFile("decrypted share has wrong length".to_string()))?;
        shares.push(build_share(shard.id, &value_bytes)?);
    }
    sss::combine(&shares)
}

/// A signed transaction plus the metadata needed to broadcast or verify it.
#[derive(Debug, Clone)]
pub struct SignedOutput {
    /// Sender address (derived from the reconstructed key).
    pub from: solana_pubkey::Pubkey,
    /// Ed25519 signature (also the Solana transaction id).
    pub signature: solana_signature::Signature,
    /// Raw bincode transaction encoding as a base58 string.
    pub raw_base58: String,
}

impl From<SignedTx> for SignedOutput {
    fn from(signed: SignedTx) -> Self {
        Self {
            from: signed.from(),
            signature: signed.signature(),
            raw_base58: signed.raw_base58(),
        }
    }
}

/// Extract the 32-byte Ed25519 seed from a reconstructed key. The returned
/// buffer is wiped on drop.
pub fn key_seed(key: &SecretKey) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(key.to_bytes().into())
}

/// Reconstruct the key from shards and sign a transaction entirely offline
/// (Mode A).
///
/// The reconstructed key is moved straight into the signing context and
/// zeroized on drop; it never leaves memory in the clear.
pub fn sign_transaction_from_shards(
    shard_paths: &[PathBuf],
    passwords: &[String],
    params: TxParams,
) -> Result<SignedOutput, Error> {
    let key = reconstruct(shard_paths, passwords)?;
    let signed = tx::sign_transaction(*key_seed(&key), params)?;
    Ok(signed.into())
}

/// Sign a transaction with a threshold FROST subset of share files (Mode B),
/// without ever reconstructing the signing key.
///
/// The message is the bincode serialization of the transaction, exactly as
/// Mode A signs it. The aggregated signature verifies under plain Ed25519, so
/// the resulting transaction is indistinguishable from one signed by the full
/// key.
pub fn sign_transaction_from_mpc_shares(
    share_paths: &[PathBuf],
    passwords: &[String],
    group_pub_path: &Path,
    params: TxParams,
) -> Result<SignedOutput, Error> {
    let message = tx::transaction_message(&params);
    let mpc::MpcSignature {
        signature,
        verifying_key,
    } = mpc::mpc_sign(
        share_paths,
        passwords,
        group_pub_path,
        &message.serialize(),
        |_, _| {},
    )?;
    let signed = tx::sign_transaction_with_signature(params, signature, verifying_key)?;
    Ok(signed.into())
}

/// Reconstruct the key from shards and sign a Bitcoin Taproot transfer entirely
/// offline (Mode A).
pub fn sign_bitcoin_transaction_from_shards(
    shard_paths: &[PathBuf],
    passwords: &[String],
    params: bitcoin::BitcoinParams,
) -> Result<bitcoin::SignedBitcoinTx, Error> {
    let key = reconstruct(shard_paths, passwords)?;
    bitcoin::sign_transaction(*key_seed(&key), params)
}

/// Reconstruct the key from shards and sign a Cosmos `bank.MsgSend` entirely
/// offline (Mode A).
pub fn sign_cosmos_transaction_from_shards(
    shard_paths: &[PathBuf],
    passwords: &[String],
    params: cosmos::CosmosParams,
) -> Result<cosmos::SignedCosmosTx, Error> {
    let key = reconstruct(shard_paths, passwords)?;
    cosmos::sign_transaction(*key_seed(&key), params)
}

/// Extract the share identifier (x-coordinate) as a `u8`.
fn share_id(share: &sss::Share) -> u8 {
    share.identifier.to_repr()[31]
}

/// Rebuild a `Share` from its identifier and 32-byte scalar value.
fn build_share(id: u8, value_bytes: &[u8; SHARE_VALUE_LEN]) -> Result<sss::Share, Error> {
    use vsss_rs::{IdentifierPrimeField, ValuePrimeField};

    let value: Option<Scalar> = Scalar::from_repr((*value_bytes).into()).into();
    let value = value.ok_or_else(|| Error::InvalidShardFile("invalid share value".to_string()))?;

    Ok(sss::Share {
        identifier: IdentifierPrimeField::from(Scalar::from(u64::from(id))),
        value: ValuePrimeField::from(value),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::SecretKey;

    #[test]
    fn init_and_reconstruct_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = SecretKey::random(&mut rand::rngs::OsRng);
        let passwords = ["one".to_string(), "two".to_string(), "three".to_string()];

        let paths = init_shards(&key, 2, 3, dir.path(), &passwords).expect("init");
        assert_eq!(paths.len(), 3);

        let recovered = reconstruct(&paths[..2], &passwords[..2]).expect("reconstruct");
        assert_eq!(recovered.to_bytes(), key.to_bytes());
    }

    #[test]
    fn wrong_password_fails_cleanly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = SecretKey::random(&mut rand::rngs::OsRng);
        let passwords = ["one".to_string(), "two".to_string(), "three".to_string()];
        let paths = init_shards(&key, 2, 3, dir.path(), &passwords).expect("init");

        let bad = ["nope".to_string(), "two".to_string()];
        assert!(matches!(
            reconstruct(&paths[..2], &bad),
            Err(Error::Decrypt { .. })
        ));
    }

    #[test]
    fn too_few_shards_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = SecretKey::random(&mut rand::rngs::OsRng);
        let passwords = ["one".to_string(), "two".to_string(), "three".to_string()];
        let paths = init_shards(&key, 2, 3, dir.path(), &passwords).expect("init");

        assert!(matches!(
            reconstruct(&paths[..1], &passwords[..1]),
            Err(Error::NotEnoughShares(..))
        ));
    }

    #[test]
    fn shards_from_different_splits_rejected() {
        let dir_a = tempfile::tempdir().expect("tempdir a");
        let dir_b = tempfile::tempdir().expect("tempdir b");
        let key = SecretKey::random(&mut rand::rngs::OsRng);
        let passwords = ["one".to_string(), "two".to_string(), "three".to_string()];

        let set_a = init_shards(&key, 2, 3, dir_a.path(), &passwords).expect("init a");
        let set_b = init_shards(&key, 3, 3, dir_b.path(), &passwords).expect("init b");

        let mixed = vec![set_a[0].clone(), set_b[0].clone()];
        assert!(matches!(
            reconstruct(&mixed, &passwords[..2]),
            Err(Error::SplitMismatch { .. })
        ));
    }
}
