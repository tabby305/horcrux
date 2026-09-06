//! Core air-gapped FROST protocol (Mode B over HX3 frames).
//!
//! The coordinator and participants exchange HX3 messages without sharing a
//! network. Every artifact is bound to a 16-byte session. This module contains
//! the cryptographic operations; [`crate::qr`] provides the transport of
//! frames as `.hx3` files, PNG QRs, and terminal output.
//!
//! Security invariants enforced here (the frame layer enforces structural ones
//! like magic/version/checksum/session consistency):
//! * a signing package only builds from commitments that (a) meet the
//!   threshold, (b) have distinct ids, and (c) are members of the group named
//!   in the request;
//! * a participant only produces a signature share if the signing package's
//!   message equals the request it accepted and the package contains exactly
//!   its own commitment;
//! * the aggregated signature is verified against the group verifying key and
//!   only then returned;
//! * signature shares are never combined with a package from a different
//!   signing attempt (the coordinator binds every input to one session).

use std::collections::BTreeMap;
use std::path::Path;

use frost_ed25519 as frost;

use crate::error::Error;
use crate::mpc;
use crate::qr::SESSION_LEN;

/// A signing request offered by the coordinator to the participants: the
/// message to sign, the group that must sign it, and the session binding every
/// artifact of this attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestData {
    /// Identifies this signing attempt; every frame of every related artifact
    /// carries it.
    pub session: [u8; SESSION_LEN],
    /// Serialized [`frost::keys::PublicKeyPackage`] (the non-secret `group.pub`).
    pub group_pub: Vec<u8>,
    /// The message participants are asked to sign.
    pub message: Vec<u8>,
}

impl RequestData {
    /// Serialize to the signing-request payload (framed by `MessageType::Request`).
    pub fn to_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.group_pub.len() + self.message.len());
        out.extend_from_slice(&(self.group_pub.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.group_pub);
        out.extend_from_slice(&(self.message.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.message);
        out
    }

    /// Parse a signing-request payload. `session` comes from the HX3 frames
    /// that carried the payload, so the two can never disagree.
    pub fn from_payload(session: [u8; SESSION_LEN], payload: &[u8]) -> Result<Self, Error> {
        if payload.len() < 8 {
            return Err(Error::Hx3("signing request payload is truncated".into()));
        }
        let group_len = u32::from_le_bytes(payload[..4].try_into().unwrap()) as usize;
        let group_end = 4usize
            .checked_add(group_len)
            .ok_or_else(|| Error::Hx3("group length overflow".into()))?;
        let message_start = group_end
            .checked_add(4)
            .ok_or_else(|| Error::Hx3("message length overflow".into()))?;
        if message_start > payload.len() {
            return Err(Error::Hx3("signing request payload is truncated".into()));
        }
        let message_len =
            u32::from_le_bytes(payload[group_end..message_start].try_into().unwrap()) as usize;
        let message_end = message_start
            .checked_add(message_len)
            .ok_or_else(|| Error::Hx3("message length overflow".into()))?;
        if message_end != payload.len() {
            return Err(Error::Hx3(format!(
                "signing request payload has {} trailing/truncated bytes",
                payload.len().abs_diff(message_end)
            )));
        }
        Ok(Self {
            session,
            group_pub: payload[4..group_end].to_vec(),
            message: payload[message_start..message_end].to_vec(),
        })
    }
}

/// A round-1 commitment from a participant ("I am willing to sign it").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentData {
    /// Participant id (1-based, matching the share-file id).
    pub participant_id: u8,
    /// Serialized [`frost::round1::SigningCommitments`].
    pub commitments: Vec<u8>,
}

impl CommitmentData {
    /// Serialize to the commitment payload (framed by `MessageType::Commitment`).
    pub fn to_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.commitments.len());
        out.push(self.participant_id);
        out.extend_from_slice(&(self.commitments.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.commitments);
        out
    }

    /// Parse a commitment payload.
    pub fn from_payload(payload: &[u8]) -> Result<Self, Error> {
        if payload.len() < 3 {
            return Err(Error::Hx3("commitment payload is truncated".into()));
        }
        let len = u16::from_le_bytes(payload[1..3].try_into().unwrap()) as usize;
        if payload.len() != 3 + len {
            return Err(Error::Hx3("commitment payload length mismatch".into()));
        }
        Ok(Self {
            participant_id: payload[0],
            commitments: payload[3..].to_vec(),
        })
    }
}

/// A round-2 signature share from a participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureShareData {
    /// Participant id (1-based, matching the share-file id).
    pub participant_id: u8,
    /// Serialized [`frost::round2::SignatureShare`].
    pub share: Vec<u8>,
}

impl SignatureShareData {
    /// Serialize to the signature-share payload (framed by `MessageType::SignatureShare`).
    pub fn to_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.share.len());
        out.push(self.participant_id);
        out.extend_from_slice(&(self.share.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.share);
        out
    }

    /// Parse a signature-share payload.
    pub fn from_payload(payload: &[u8]) -> Result<Self, Error> {
        if payload.len() < 3 {
            return Err(Error::Hx3("signature share payload is truncated".into()));
        }
        let len = u16::from_le_bytes(payload[1..3].try_into().unwrap()) as usize;
        if payload.len() != 3 + len {
            return Err(Error::Hx3("signature share payload length mismatch".into()));
        }
        Ok(Self {
            participant_id: payload[0],
            share: payload[3..].to_vec(),
        })
    }
}

/// Create a fresh 16-byte session for a signing attempt.
pub fn new_session() -> [u8; SESSION_LEN] {
    rand::random()
}

/// Build a signing request. Structurally validates the group package up front
/// so an unusable `group.pub` fails before it spreads.
pub fn mpc_sign_request(group_pub_bytes: &[u8], message: &[u8]) -> Result<RequestData, Error> {
    let _group = mpc::deserialize_public_key_package(group_pub_bytes)?;
    Ok(RequestData {
        session: new_session(),
        group_pub: group_pub_bytes.to_vec(),
        message: message.to_vec(),
    })
}

/// Coordinate round 1: assemble the signing package from the collected
/// commitments. Rejects any commitment that is not from a group member, any
/// duplicate participant, and any set below the group threshold.
pub fn mpc_sign_package(
    request: &RequestData,
    commitments: &[CommitmentData],
) -> Result<Vec<u8>, Error> {
    let group_pub = mpc::deserialize_public_key_package(&request.group_pub)?;
    let min = group_pub.min_signers().unwrap_or_default() as usize;
    if commitments.len() < min {
        return Err(Error::NotEnoughShares(min, commitments.len()));
    }

    let mut map: BTreeMap<frost::Identifier, frost::round1::SigningCommitments> = BTreeMap::new();
    for commitment in commitments {
        let id = identifier_from_u8(commitment.participant_id)?;
        if !group_pub.verifying_shares().contains_key(&id) {
            return Err(Error::Mpc(format!(
                "commitment from participant {} is not a member of this group",
                commitment.participant_id
            )));
        }
        if map.contains_key(&id) {
            return Err(Error::Mpc(format!(
                "duplicate commitment from participant {}",
                commitment.participant_id
            )));
        }
        let commitments = frost::round1::SigningCommitments::deserialize(&commitment.commitments)
            .map_err(|e| {
            Error::Mpc(format!(
                "invalid commitment from participant {}: {e}",
                commitment.participant_id
            ))
        })?;
        map.insert(id, commitments);
    }

    mpc::build_signing_package(map, &request.message)
        .serialize()
        .map_err(|e| Error::Mpc(format!("failed to serialize signing package: {e}")))
}

/// Combine the signature shares with the signing package into a single
/// Ed25519 signature. Verifies it against the group verifying key first; an
/// unverifiable or tampered aggregate is an error, never a returned signature.
pub fn finalize_signature(
    package_bytes: &[u8],
    shares: &[SignatureShareData],
    group_pub_bytes: &[u8],
) -> Result<mpc::MpcSignature, Error> {
    let package = frost::SigningPackage::deserialize(package_bytes)
        .map_err(|e| Error::Mpc(format!("invalid signing package: {e}")))?;
    let group_pub = mpc::deserialize_public_key_package(group_pub_bytes)?;

    let mut share_map: BTreeMap<frost::Identifier, frost::round2::SignatureShare> = BTreeMap::new();
    for share in shares {
        let id = identifier_from_u8(share.participant_id)?;
        if !group_pub.verifying_shares().contains_key(&id) {
            return Err(Error::Mpc(format!(
                "signature share from participant {} is not a member of this group",
                share.participant_id
            )));
        }
        if package.signing_commitment(&id).is_none() {
            return Err(Error::Mpc(format!(
                "signature share from participant {} has no commitment in the signing package",
                share.participant_id
            )));
        }
        if share_map.contains_key(&id) {
            return Err(Error::Mpc(format!(
                "duplicate signature share from participant {}",
                share.participant_id
            )));
        }
        let signature_share =
            frost::round2::SignatureShare::deserialize(&share.share).map_err(|e| {
                Error::Mpc(format!(
                    "invalid signature share from participant {}: {e}",
                    share.participant_id
                ))
            })?;
        share_map.insert(id, signature_share);
    }

    mpc::aggregate_signature(&package, &share_map, &group_pub)
}

/// A participant whose key share has been decrypted and checked against the
/// request's group for one signing session.
pub struct Participant {
    /// The participant's (secret) key package, held in memory for this session.
    pub key_package: frost::keys::KeyPackage,
    /// The session the participant is committing to.
    pub session: [u8; SESSION_LEN],
}

/// Load and decrypt a participant's share for the request. `on_decrypt(id, ok)`
/// reports the decryption outcome (for the audit layer). The share must belong
/// to the group named in the request, so a share/group mismatch fails before
/// any commitment is made.
pub fn load_participant(
    request: &RequestData,
    share_path: &Path,
    password: &str,
    mut on_decrypt: impl FnMut(u8, bool),
) -> Result<Participant, Error> {
    let share = mpc::FrostShare::read(share_path)?;
    let key_package = match share.decrypt(password) {
        Ok(key_package) => {
            on_decrypt(share.id, true);
            key_package
        }
        Err(e) => {
            on_decrypt(share.id, false);
            return Err(e);
        }
    };
    let group_pub = mpc::deserialize_public_key_package(&request.group_pub)?;
    if key_package.verifying_key() != group_pub.verifying_key() {
        return Err(Error::MpcGroupMismatch {
            path: share_path.to_path_buf(),
        });
    }
    Ok(Participant {
        key_package,
        session: request.session,
    })
}

/// FROST round 1 over the air gap: generate fresh nonces and the commitment
/// for a participant. Keeps the nonces for round 2: call
/// [`produce_signature_share`] in the same process while they are still in
/// memory (they are zeroized on drop).
pub fn produce_commitment(
    key_package: &frost::keys::KeyPackage,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<(CommitmentData, frost::round1::SigningNonces), Error> {
    let (identifier, nonces, commitment) = mpc::participant_round1(key_package, rng);
    let commitment_bytes = commitment
        .serialize()
        .map_err(|e| Error::Mpc(format!("failed to serialize commitment: {e}")))?;
    Ok((
        CommitmentData {
            participant_id: mpc::share_id(&identifier),
            commitments: commitment_bytes,
        },
        nonces,
    ))
}

/// FROST round 2 over the air gap: produce the participant's signature share
/// for the packaged request.
///
/// Guards enforced beyond frost-core's own checks:
/// * the package's message must equal the request this participant accepted;
/// * the package must contain exactly this participant's commitment.
pub fn produce_signature_share(
    request: &RequestData,
    package_bytes: &[u8],
    key_package: &frost::keys::KeyPackage,
    nonces: frost::round1::SigningNonces,
) -> Result<SignatureShareData, Error> {
    let package = frost::SigningPackage::deserialize(package_bytes)
        .map_err(|e| Error::Mpc(format!("invalid signing package: {e}")))?;
    if package.message() != &request.message {
        return Err(Error::Mpc(
            "signing package message does not match the accepted request".into(),
        ));
    }
    if package.signing_commitment(key_package.identifier()) != Some(*nonces.commitments()) {
        return Err(Error::Mpc(
            "signing package does not contain this participant's commitment".into(),
        ));
    }
    let share = mpc::participant_round2(&package, &nonces, key_package)?;
    Ok(SignatureShareData {
        participant_id: mpc::share_id(key_package.identifier()),
        share: share.serialize(),
    })
}

/// Map a `u8` participant id to the FROST identifier used by the default split
/// (the little-endian scalar `id`, matching `FrostShare.id`).
fn identifier_from_u8(id: u8) -> Result<frost::Identifier, Error> {
    if id == 0 {
        return Err(Error::Mpc(
            "participant id 0 is invalid (the default split uses 1..=n)".into(),
        ));
    }
    let mut bytes = [0u8; 32];
    bytes[0] = id;
    frost::Identifier::deserialize(&bytes)
        .map_err(|e| Error::Mpc(format!("invalid participant id {id}: {e}")))
}
