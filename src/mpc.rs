//! Mode B: FROST threshold signatures over Ed25519 (Phase 4).
//!
//! The Mode A signing seed is dealer-split with `frost-ed25519` (Zcash
//! Foundation, RFC 9591) into t-of-n key shares. Each participant only ever
//! holds an encrypted key share; the full signing key is never reconstructed
//! on any machine. Signing runs the two-round FROST protocol with one
//! in-process participant per share file: each contributes a nonce commitment
//! (round 1) and a signature share (round 2), and the shares aggregate into a
//! single Ed25519 signature that any RFC 8032 verifier — including Solana —
//! accepts.

use crate::crypto;
use crate::error::Error;
use crate::{NONCE_LEN, SALT_LEN, TAG_LEN};
use frost_ed25519 as frost;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// File magic distinguishing FROST share files from SSS shard files.
pub const FROST_MAGIC: &[u8; 3] = b"HX2";
/// Share file format version.
pub const FROST_VERSION: u8 = 1;
/// File name of the (non-secret) group public key package written by
/// [`mpc_split`], required to verify and aggregate signatures.
pub const GROUP_PUB_FILENAME: &str = "group.pub";

/// Fixed header length of a FROST share file (excluding the sealed payload).
pub const FROST_HEADER_LEN: usize = FROST_MAGIC.len()
    + 1 // version
    + 1 // min signers (threshold)
    + 1 // max signers (share count)
    + 1 // participant id
    + SALT_LEN
    + NONCE_LEN
    + 2; // sealed payload length, little-endian u16

/// An encrypted FROST key share on disk.
///
/// Layout: magic | version | min_signers | max_signers | id | salt | nonce |
/// sealed_len(u16 LE) | sealed (`KeyPackage` serialization || AES-GCM tag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostShare {
    /// Shares required to sign (threshold).
    pub min_signers: u8,
    /// Total number of shares in the group.
    pub max_signers: u8,
    /// Participant identifier (1-based, matching the default FROST split).
    pub id: u8,
    /// Argon2id salt.
    pub salt: [u8; SALT_LEN],
    /// AES-256-GCM nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Encrypted [`frost::keys::KeyPackage`] with appended authentication tag.
    pub sealed: Vec<u8>,
}

impl FrostShare {
    /// Write the share to `path`.
    pub fn write(&self, path: &Path) -> Result<(), Error> {
        fs::write(path, self.to_bytes()).map_err(Error::Io)
    }

    /// Read a share from `path`.
    pub fn read(path: &Path) -> Result<Self, Error> {
        let bytes = fs::read(path).map_err(Error::Io)?;
        Self::from_bytes(&bytes)
    }

    /// Serialize to the binary layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FROST_HEADER_LEN + self.sealed.len());
        out.extend_from_slice(FROST_MAGIC);
        out.push(FROST_VERSION);
        out.push(self.min_signers);
        out.push(self.max_signers);
        out.push(self.id);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.sealed.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.sealed);
        out
    }

    /// Deserialize from the binary layout, validating magic/version/length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < FROST_HEADER_LEN {
            return Err(Error::InvalidShardFile(format!(
                "expected at least {FROST_HEADER_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        if &bytes[..3] != FROST_MAGIC {
            return Err(Error::InvalidShardFile(
                "bad magic bytes; not a horcrux FROST share".to_string(),
            ));
        }
        if bytes[3] != FROST_VERSION {
            return Err(Error::InvalidShardFile(format!(
                "unsupported version {}",
                bytes[3]
            )));
        }

        let sealed_len =
            u16::from_le_bytes([bytes[FROST_HEADER_LEN - 2], bytes[FROST_HEADER_LEN - 1]]) as usize;
        if sealed_len < TAG_LEN || bytes.len() != FROST_HEADER_LEN + sealed_len {
            return Err(Error::InvalidShardFile(format!(
                "sealed payload is {sealed_len} bytes but file is {} bytes",
                bytes.len()
            )));
        }

        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        salt.copy_from_slice(&bytes[7..7 + SALT_LEN]);
        nonce.copy_from_slice(&bytes[7 + SALT_LEN..7 + SALT_LEN + NONCE_LEN]);

        Ok(Self {
            min_signers: bytes[4],
            max_signers: bytes[5],
            id: bytes[6],
            salt,
            nonce,
            sealed: bytes[FROST_HEADER_LEN..].to_vec(),
        })
    }

    /// Decrypt and deserialize the participant's [`frost::keys::KeyPackage`].
    ///
    /// A wrong password (or tampered file) is rejected by the AES-GCM tag
    /// check, which is bound to this share's (min, max, id) via the AAD.
    pub fn decrypt(&self, password: &str) -> Result<frost::keys::KeyPackage, Error> {
        let aad = [self.min_signers, self.max_signers, self.id];
        let payload =
            crypto::open(&self.sealed, password, &self.salt, &self.nonce, &aad).map_err(|e| {
                Error::Decrypt {
                    id: self.id,
                    reason: e.to_string(),
                }
            })?;
        frost::keys::KeyPackage::deserialize(&payload)
            .map_err(|e| Error::Mpc(format!("invalid share payload: {e}")))
    }
}

/// A Schnorr signature produced by aggregating FROST signature shares, plus
/// the group verifying key that validates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpcSignature {
    /// The 64-byte Ed25519 signature (R || S).
    pub signature: [u8; 64],
    /// The 32-byte group verifying key (the Mode A address bytes).
    pub verifying_key: [u8; 32],
}

/// Derive the FROST signing key for a Mode A Ed25519 seed. The FROST group
/// public key equals the Mode A address, so signatures produced by any
/// threshold subset are indistinguishable from ones made by the original key.
pub fn frost_signing_key(seed: &[u8; 32]) -> Result<frost::SigningKey, Error> {
    let dalek = ed25519_dalek::SigningKey::from_bytes(seed);
    frost::SigningKey::from_scalar(dalek.to_scalar())
        .map_err(|e| Error::Mpc(format!("invalid signing scalar: {e}")))
}

/// Dealer-split `key` into `share_count` encrypted FROST key shares written to
/// `out_dir`, requiring `threshold` of them to sign.
///
/// `passwords[i]` guards the share with participant id `i + 1` (written as
/// `mpc-{id}.hx`), mirroring the Mode A `init` convention. Returns the share
/// paths and the path of the non-secret group public key package.
pub fn mpc_split(
    key: &k256::SecretKey,
    threshold: u8,
    share_count: u8,
    out_dir: &Path,
    passwords: &[String],
) -> Result<(Vec<PathBuf>, PathBuf), Error> {
    if threshold < 2 {
        return Err(Error::InvalidParams(
            "FROST requires a threshold of at least 2".to_string(),
        ));
    }
    if threshold > share_count {
        return Err(Error::InvalidParams(format!(
            "threshold ({threshold}) must be at most share count ({share_count})"
        )));
    }
    if passwords.len() != share_count as usize {
        return Err(Error::InvalidParams(format!(
            "expected {share_count} passwords, got {}",
            passwords.len()
        )));
    }

    let seed: [u8; 32] = key.to_bytes().into();
    let signing_key = frost_signing_key(&seed)?;

    let mut rng = rand::rngs::OsRng;
    let (secret_shares, pubkey_package) = frost::keys::split(
        &signing_key,
        share_count as u16,
        threshold as u16,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .map_err(|e| Error::Mpc(e.to_string()))?;

    fs::create_dir_all(out_dir)?;

    let mut paths = Vec::with_capacity(secret_shares.len());
    for (i, (identifier, secret_share)) in secret_shares.iter().enumerate() {
        let id = share_id(identifier);
        let key_package = frost::keys::KeyPackage::try_from(secret_share.clone())
            .map_err(|e| Error::Mpc(e.to_string()))?;
        let payload = key_package
            .serialize()
            .map_err(|e| Error::Mpc(e.to_string()))?;
        let salt = crypto::random_salt();
        let nonce = crypto::random_nonce();
        let aad = [threshold, share_count, id];
        let sealed = crypto::seal(&payload, &passwords[i], &salt, &nonce, &aad)?;

        let share = FrostShare {
            min_signers: threshold,
            max_signers: share_count,
            id,
            salt,
            nonce,
            sealed,
        };
        let path = out_dir.join(format!("mpc-{id}.hx"));
        share.write(&path)?;
        paths.push(path);
    }

    let group_path = out_dir.join(GROUP_PUB_FILENAME);
    let group_bytes = pubkey_package
        .serialize()
        .map_err(|e| Error::Mpc(e.to_string()))?;
    fs::write(&group_path, group_bytes).map_err(Error::Io)?;

    Ok((paths, group_path))
}

/// Read the participant ids from FROST share files without decrypting
/// anything.
pub fn shard_ids(paths: &[PathBuf]) -> Result<Vec<u8>, Error> {
    paths.iter().map(|p| Ok(FrostShare::read(p)?.id)).collect()
}

/// Deserialize a group public key package, mapping errors to [`Error::Mpc`].
/// Used by both the in-process ([`mpc_sign`]) and air-gapped ([`crate::qr_mpc`])
/// paths, which must accept the same on-disk format.
pub fn deserialize_public_key_package(
    bytes: &[u8],
) -> Result<frost::keys::PublicKeyPackage, Error> {
    frost::keys::PublicKeyPackage::deserialize(bytes)
        .map_err(|e| Error::Mpc(format!("invalid group public package: {e}")))
}

/// Read the group verifying key (the Mode A address bytes) from a public key
/// package without touching any share files.
pub fn group_verifying_key(group_pub_path: &Path) -> Result<[u8; 32], Error> {
    let bytes = fs::read(group_pub_path).map_err(Error::Io)?;
    let group_pub = deserialize_public_key_package(&bytes)?;
    verifying_key_bytes(&group_pub)
}

/// FROST round 1: generate a nonce pair and its commitment for a participant,
/// in-process. Returns the participant's identifier, nonces (kept secret until
/// round 2) and commitment (sent to the coordinator).
pub fn participant_round1(
    key_package: &frost::keys::KeyPackage,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> (
    frost::Identifier,
    frost::round1::SigningNonces,
    frost::round1::SigningCommitments,
) {
    let (nonces, commitment) = frost::round1::commit(key_package.signing_share(), rng);
    (*key_package.identifier(), nonces, commitment)
}

/// Build the coordinator's signing package from the collected commitments and
/// the message to sign. The message is the same byte string every participant
/// later signs and the coordinator verifies.
pub fn build_signing_package(
    commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
    message: &[u8],
) -> frost::SigningPackage {
    frost::SigningPackage::new(commitments, message)
}

/// FROST round 2: produce one participant's signature share for the signing
/// package. Fails if the package lacks this participant's commitment or if the
/// nonces do not match it (frost-core enforces both).
pub fn participant_round2(
    signing_package: &frost::SigningPackage,
    nonces: &frost::round1::SigningNonces,
    key_package: &frost::keys::KeyPackage,
) -> Result<frost::round2::SignatureShare, Error> {
    frost::round2::sign(signing_package, nonces, key_package)
        .map_err(|e| Error::Mpc(format!("failed to produce signature share: {e}")))
}

/// Aggregate signature shares into a single Ed25519 signature and verify it
/// against the group verifying key before returning. A signature that fails
/// verification is never returned.
pub fn aggregate_signature(
    signing_package: &frost::SigningPackage,
    signature_shares: &BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
    group_pub: &frost::keys::PublicKeyPackage,
) -> Result<MpcSignature, Error> {
    let signature = frost::aggregate(signing_package, signature_shares, group_pub)
        .map_err(|e| Error::Mpc(format!("failed to aggregate signature: {e}")))?;

    if group_pub
        .verifying_key()
        .verify(signing_package.message(), &signature)
        .is_err()
    {
        return Err(Error::Mpc(
            "aggregated signature failed FROST verification".to_string(),
        ));
    }

    Ok(MpcSignature {
        signature: signature_bytes(&signature)?,
        verifying_key: verifying_key_bytes(group_pub)?,
    })
}

/// Serialize a FROST signature to its 64-byte Ed25519 form.
fn signature_bytes(signature: &frost::Signature) -> Result<[u8; 64], Error> {
    signature
        .serialize()
        .map_err(|e| Error::Mpc(e.to_string()))?
        .try_into()
        .map_err(|_| Error::Mpc("signature is not 64 bytes".to_string()))
}

/// Serialize a group verifying key to its 32-byte form.
fn verifying_key_bytes(group_pub: &frost::keys::PublicKeyPackage) -> Result<[u8; 32], Error> {
    group_pub
        .verifying_key()
        .serialize()
        .map_err(|e| Error::Mpc(e.to_string()))?
        .try_into()
        .map_err(|_| Error::Mpc("verifying key is not 32 bytes".to_string()))
}

/// Run the two-round FROST protocol over `message` with one in-process
/// participant per share file, and aggregate their signature shares.
///
/// `on_participant` is invoked with each share's id and whether its decryption
/// succeeded (used by the audit layer). The full signing key is never
/// reconstructed: only nonces, commitments, and signature shares exist.
pub fn mpc_sign(
    share_paths: &[PathBuf],
    passwords: &[String],
    group_pub_path: &Path,
    message: &[u8],
    mut on_participant: impl FnMut(u8, bool),
) -> Result<MpcSignature, Error> {
    if passwords.len() != share_paths.len() {
        return Err(Error::InvalidParams(format!(
            "expected {} passwords, got {}",
            share_paths.len(),
            passwords.len()
        )));
    }

    let group_bytes = fs::read(group_pub_path).map_err(Error::Io)?;
    let group_pub = deserialize_public_key_package(&group_bytes)?;
    let group_vk = *group_pub.verifying_key();

    let mut rng = rand::rngs::OsRng;
    let mut participants: Vec<(frost::keys::KeyPackage, frost::round1::SigningNonces)> = Vec::new();
    let mut commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments> =
        BTreeMap::new();

    for (path, password) in share_paths.iter().zip(passwords) {
        let share = FrostShare::read(path)?;
        let key_package = match share.decrypt(password) {
            Ok(kp) => {
                on_participant(share.id, true);
                kp
            }
            Err(e) => {
                on_participant(share.id, false);
                return Err(e);
            }
        };
        if key_package.verifying_key() != &group_vk {
            return Err(Error::MpcGroupMismatch { path: path.clone() });
        }

        let (identifier, nonces, commitment) = participant_round1(&key_package, &mut rng);
        commitments.insert(identifier, commitment);
        participants.push((key_package, nonces));
    }

    let min = group_pub.min_signers().unwrap_or_default() as usize;
    if participants.len() < min {
        return Err(Error::NotEnoughShares(min, participants.len()));
    }

    let signing_package = build_signing_package(commitments, message);
    let mut signature_shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare> =
        BTreeMap::new();
    for (key_package, nonces) in &participants {
        let share = participant_round2(&signing_package, nonces, key_package)?;
        signature_shares.insert(*key_package.identifier(), share);
    }

    aggregate_signature(&signing_package, &signature_shares, &group_pub)
}

/// Like [`mpc_sign`], recording each participant's decryption outcome and a
/// final `signed` entry in the access log.
pub fn mpc_sign_with_audit(
    share_paths: &[PathBuf],
    passwords: &[String],
    group_pub_path: &Path,
    message: &[u8],
    log: &crate::audit::AccessLog,
    attempt: u64,
) -> Result<MpcSignature, Error> {
    let ts = crate::audit::now_ms();
    let result = mpc_sign(share_paths, passwords, group_pub_path, message, |id, ok| {
        let entry = if ok {
            crate::audit::Entry::ok(ts, attempt, id)
        } else {
            crate::audit::Entry::fail(ts, attempt, id)
        };
        let _ = log.append(&entry);
    });
    if result.is_ok() {
        let _ = log.append(&crate::audit::Entry::signed(
            crate::audit::now_ms(),
            attempt,
        ));
    }
    result
}

/// The participant id as a `u8`. The default FROST split assigns the nonzero
/// identifiers `1..=n`; their little-endian scalar serialization starts with
/// the id byte.
pub(crate) fn share_id(identifier: &frost::Identifier) -> u8 {
    identifier.serialize()[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::derive_address;
    use ed25519_dalek::Verifier as _;
    use k256::SecretKey;

    fn key() -> SecretKey {
        SecretKey::random(&mut rand::rngs::OsRng)
    }

    fn passwords(n: usize, seed: &str) -> Vec<String> {
        (0..n).map(|i| format!("{seed}-{i}")).collect()
    }

    fn seed_of(key: &SecretKey) -> [u8; 32] {
        key.to_bytes().into()
    }

    fn verify_dalek(verifying_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(verifying_key).expect("valid vk");
        vk.verify(message, &ed25519_dalek::Signature::from_bytes(signature))
            .is_ok()
    }

    #[test]
    fn frost_group_key_matches_mode_a_address() {
        let key = key();
        let seed = seed_of(&key);
        let frost_key = frost_signing_key(&seed).expect("frost key");
        let frost_vk = frost::VerifyingKey::from(&frost_key);
        let vk_bytes = frost_vk.serialize().expect("serialize vk");
        assert_eq!(vk_bytes.as_slice(), &derive_address(&seed).to_bytes());
    }

    #[test]
    fn split_2_of_3_any_pair_signs_and_verifies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = key();
        let seed = seed_of(&key);
        let pws = passwords(3, "guardian");

        let (paths, group) = mpc_split(&key, 2, 3, dir.path(), &pws).expect("split");
        assert_eq!(paths.len(), 3);
        let message = b"pay Alice 1 SOL";

        for combo in [&[0usize, 1], &[0usize, 2], &[1usize, 2]] {
            let chosen: Vec<_> = combo.iter().map(|&i| paths[i].clone()).collect();
            let chosen_pws: Vec<_> = combo.iter().map(|&i| pws[i].clone()).collect();
            let sig = mpc_sign(&chosen, &chosen_pws, &group, message, |_, _| {}).expect("sign");
            assert_eq!(sig.verifying_key, derive_address(&seed).to_bytes());
            assert!(
                verify_dalek(&sig.verifying_key, message, &sig.signature),
                "aggregated signature must verify under plain Ed25519"
            );
        }
    }

    #[test]
    fn signatures_are_non_deterministic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = key();
        let pws = passwords(3, "guardian");
        let (paths, group) = mpc_split(&key, 2, 3, dir.path(), &pws).expect("split");
        let message = b"nonce per signing operation";
        let a = mpc_sign(&paths[..2], &pws[..2], &group, message, |_, _| {}).expect("sign a");
        let b = mpc_sign(&paths[..2], &pws[..2], &group, message, |_, _| {}).expect("sign b");
        assert_ne!(a.signature, b.signature);
    }

    #[test]
    fn single_share_is_not_enough() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = key();
        let pws = passwords(3, "guardian");
        let (paths, group) = mpc_split(&key, 2, 3, dir.path(), &pws).expect("split");
        assert!(matches!(
            mpc_sign(&paths[..1], &pws[..1], &group, b"msg", |_, _| {}),
            Err(Error::NotEnoughShares(..))
        ));
    }

    #[test]
    fn wrong_password_fails_cleanly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = key();
        let pws = passwords(3, "guardian");
        let (paths, group) = mpc_split(&key, 2, 3, dir.path(), &pws).expect("split");
        let bad = vec!["nope".to_string(), "guardian-1".to_string()];
        assert!(matches!(
            mpc_sign(&paths[..2], &bad, &group, b"msg", |_, _| {}),
            Err(Error::Decrypt { .. })
        ));
    }

    #[test]
    fn shares_from_different_groups_are_rejected() {
        let dir_a = tempfile::tempdir().expect("tempdir a");
        let dir_b = tempfile::tempdir().expect("tempdir b");
        let pws = passwords(3, "guardian");
        let (paths_a, group_a) = mpc_split(&key(), 2, 3, dir_a.path(), &pws).expect("split a");
        let (paths_b, _group_b) = mpc_split(&key(), 2, 3, dir_b.path(), &pws).expect("split b");

        let mixed = vec![paths_a[0].clone(), paths_b[1].clone()];
        let mixed_pws = vec![pws[0].clone(), pws[1].clone()];
        assert!(matches!(
            mpc_sign(&mixed, &mixed_pws, &group_a, b"msg", |_, _| {}),
            Err(Error::MpcGroupMismatch { .. })
        ));
    }

    #[test]
    fn share_file_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = key();
        let pws = passwords(3, "guardian");
        let (paths, _group) = mpc_split(&key, 2, 3, dir.path(), &pws).expect("split");
        for path in &paths {
            let read = FrostShare::read(path).expect("read");
            let bytes = read.to_bytes();
            assert_eq!(FrostShare::from_bytes(&bytes).expect("parse"), read);
        }
        assert_eq!(shard_ids(&paths).expect("ids"), vec![1, 2, 3]);
    }

    #[test]
    fn rejects_wrong_magic_and_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = key();
        let pws = passwords(3, "guardian");
        let (paths, _group) = mpc_split(&key, 2, 3, dir.path(), &pws).expect("split");
        let mut bytes = fs::read(&paths[0]).expect("read file");
        bytes[0] = b'X';
        assert!(matches!(
            FrostShare::from_bytes(&bytes),
            Err(Error::InvalidShardFile(_))
        ));
        let bytes = fs::read(&paths[0]).expect("read file");
        let mut bad_version = bytes;
        bad_version[3] = 99;
        assert!(matches!(
            FrostShare::from_bytes(&bad_version),
            Err(Error::InvalidShardFile(_))
        ));
    }

    #[test]
    fn sss_shard_rejected_as_frost_share() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = key();
        let pws = passwords(3, "guardian");
        let sss_paths = crate::init_shards(&key, 2, 3, dir.path(), &pws).expect("sss");
        assert!(matches!(
            FrostShare::read(&sss_paths[0]),
            Err(Error::InvalidShardFile(_))
        ));
    }

    #[test]
    fn frost_share_rejected_as_sss_shard() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = key();
        let pws = passwords(3, "guardian");
        let (paths, _group) = mpc_split(&key, 2, 3, dir.path(), &pws).expect("split");
        assert!(matches!(
            crate::shard::Shard::read(&paths[0]),
            Err(Error::InvalidShardFile(_))
        ));
    }
}
