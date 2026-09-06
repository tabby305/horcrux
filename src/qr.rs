//! HX3: QR-code transport for air-gapped FROST signing (Mode B).
//!
//! Everything crossing the air gap is wrapped in a fixed "HX3" frame that the
//! receiver validates strictly before any key material is touched. Frames are
//! self-describing (magic, version, type, session, index, total, checksum) and
//! are moved:

use sha2::{Digest, Sha256};

use crate::Error;

/// Magic bytes identifying an HX3 frame ("Horcrux 3").
pub const HX3_MAGIC: &[u8] = b"HX3";

/// Current HX3 wire version. The receiver rejects any other version.
pub const HX3_VERSION: u8 = 1;

/// Length of the session identifier in bytes.
pub const SESSION_LEN: usize = 16;

/// Length of the fixed HX3 header in bytes.
pub const HEADER_LEN: usize = 3 + 1 + 1 + SESSION_LEN + 2 + 2 + 4 + 4;

/// Length of the trailing SHA-256 truncation checksum in bytes.
pub const CHECKSUM_LEN: usize = 4;

/// Maximum payload bytes carried by a single frame. Kept deliberately small so
/// every frame renders as a scannable QR code.
pub const MAX_FRAME_PAYLOAD: usize = 450;

/// Maximum number of frames per message (255 because frame index/total are u16,
/// and the air-gap UX collapses beyond a couple of frames anyway).
pub const MAX_FRAMES: u16 = 255;

/// Maximum payload bytes across all frames of one message.
pub const MAX_MESSAGE_PAYLOAD: usize = MAX_FRAME_PAYLOAD * MAX_FRAMES as usize;

/// The four HX3 message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Coordinator -> participants: "please sign this message".
    Request = 1,
    /// Participant -> coordinator: "I am willing to sign it" (round 1).
    Commitment = 2,
    /// Coordinator -> participants: the assembled signing package (round 2).
    SigningPackage = 3,
    /// Participant -> coordinator: the finished signature share (round 2).
    SignatureShare = 4,
}

impl MessageType {
    /// Parse a raw type byte, rejecting anything unknown.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(MessageType::Request),
            2 => Some(MessageType::Commitment),
            3 => Some(MessageType::SigningPackage),
            4 => Some(MessageType::SignatureShare),
            _ => None,
        }
    }

    /// The serialized type byte.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// A single self-contained HX3 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// What kind of message this frame belongs to.
    pub message_type: MessageType,
    /// 16-byte session identifier binding all frames of one signing attempt.
    pub session: [u8; SESSION_LEN],
    /// Zero-based position of this frame within the message.
    pub index: u16,
    /// Total number of frames in the message.
    pub total: u16,
    /// The chunk of payload carried by this frame.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Serialize to the full HX3 wire format (header + checksum + payload).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(HX3_MAGIC);
        out.push(HX3_VERSION);
        out.push(self.message_type.to_u8());
        out.extend_from_slice(&self.session);
        out.extend_from_slice(&self.index.to_le_bytes());
        out.extend_from_slice(&self.total.to_le_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&checksum(
            &self.session,
            self.index,
            self.total,
            &self.payload,
        ));
        out.extend_from_slice(&self.payload);
        out
    }

    /// Strictly parse one frame from the wire format. Any inconsistency
    /// (wrong magic, wrong version, unknown type, truncated fields, oversized
    /// payload, length/checksum mismatch) is rejected.
    pub fn from_bytes(bytes: &[u8]) -> Result<Frame, Error> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Hx3(format!(
                "frame is only {} bytes, need at least {HEADER_LEN}",
                bytes.len()
            )));
        }
        if &bytes[0..3] != HX3_MAGIC {
            return Err(Error::Hx3("bad magic, not an HX3 frame".into()));
        }
        if bytes[3] != HX3_VERSION {
            return Err(Error::Hx3(format!(
                "unsupported version {}, need {HX3_VERSION}",
                bytes[3]
            )));
        }
        let message_type = MessageType::from_u8(bytes[4])
            .ok_or_else(|| Error::Hx3(format!("unknown message type {}", bytes[4])))?;
        let session: [u8; SESSION_LEN] = bytes[5..5 + SESSION_LEN].try_into().unwrap();
        let index = u16::from_le_bytes(bytes[21..23].try_into().unwrap());
        let total = u16::from_le_bytes(bytes[23..25].try_into().unwrap());
        let payload_len = u32::from_le_bytes(bytes[25..29].try_into().unwrap()) as usize;

        if total == 0 {
            return Err(Error::Hx3("frame total is zero".into()));
        }
        if index >= total {
            return Err(Error::Hx3(format!(
                "frame index {index} out of range for total {total}"
            )));
        }
        if payload_len > MAX_FRAME_PAYLOAD {
            return Err(Error::Hx3(format!(
                "frame payload of {payload_len} bytes exceeds the limit of {MAX_FRAME_PAYLOAD}"
            )));
        }
        let header_end = HEADER_LEN;
        if bytes.len() != header_end + payload_len {
            return Err(Error::Hx3(format!(
                "declared payload of {payload_len} bytes but frame holds {}",
                bytes.len() - header_end
            )));
        }
        let stored_checksum: [u8; CHECKSUM_LEN] = bytes[29..29 + CHECKSUM_LEN].try_into().unwrap();
        let computed_checksum = checksum(&session, index, total, &bytes[header_end..]);
        if stored_checksum != computed_checksum {
            return Err(Error::Hx3(
                "frame checksum mismatch (corrupt or tampered data)".into(),
            ));
        }

        Ok(Frame {
            message_type,
            session,
            index,
            total,
            payload: bytes[header_end..].to_vec(),
        })
    }

    /// Render the frame as base58 text (compact, unambiguous characters) ready
    /// to be encoded into a QR code.
    pub fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    /// Parse a frame from its base58 text representation.
    pub fn from_base58(text: &str) -> Result<Frame, Error> {
        let bytes = bs58::decode(text)
            .into_vec()
            .map_err(|e| Error::Hx3(format!("invalid base58 frame: {e}")))?;
        Frame::from_bytes(&bytes)
    }
}

/// SHA-256 truncation checksum binding a frame's identity to its payload.
fn checksum(
    session: &[u8; SESSION_LEN],
    index: u16,
    total: u16,
    payload: &[u8],
) -> [u8; CHECKSUM_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(session);
    hasher.update(index.to_le_bytes());
    hasher.update(total.to_le_bytes());
    hasher.update((payload.len() as u32).to_le_bytes());
    hasher.update(payload);
    let digest = hasher.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

/// Split a payload into 0-based frames of at most `MAX_FRAME_PAYLOAD` bytes.
pub fn encode_message(
    message_type: MessageType,
    session: [u8; SESSION_LEN],
    payload: &[u8],
) -> Result<Vec<Frame>, Error> {
    if payload.len() > MAX_MESSAGE_PAYLOAD {
        return Err(Error::Hx3(format!(
            "message payload of {} bytes exceeds the limit of {MAX_MESSAGE_PAYLOAD}",
            payload.len()
        )));
    }
    let total = payload.len().div_ceil(MAX_FRAME_PAYLOAD);
    let total = u16::try_from(total).map_err(|_| Error::Hx3("too many frames".into()))?;
    let mut frames = Vec::with_capacity(total as usize);
    for (index, chunk) in payload.chunks(MAX_FRAME_PAYLOAD).enumerate() {
        frames.push(Frame {
            message_type,
            session,
            index: index as u16,
            total,
            payload: chunk.to_vec(),
        });
    }
    // A zero-length payload still produces one valid (empty) frame so the
    // message never disappears.
    if frames.is_empty() {
        frames.push(Frame {
            message_type,
            session,
            index: 0,
            total: 1,
            payload: Vec::new(),
        });
    }
    Ok(frames)
}

/// Concatenate frames into a `.hx3` file payload (header + checksum + payload
/// per frame, back to back).
pub fn serialize_frames(frames: &[Frame]) -> Vec<u8> {
    let mut out = Vec::new();
    for frame in frames {
        out.extend_from_slice(&frame.to_bytes());
    }
    out
}

/// Parse `.hx3` file bytes into a frame list, validating every frame.
pub fn deserialize_frames(bytes: &[u8]) -> Result<Vec<Frame>, Error> {
    let mut frames = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes.len() - offset < HEADER_LEN {
            return Err(Error::Hx3(format!(
                "trailing {} bytes too short for a frame header",
                bytes.len() - offset
            )));
        }
        if &bytes[offset..offset + 3] != HX3_MAGIC {
            return Err(Error::Hx3(
                "bad magic at frame start; not an HX3 frame set".into(),
            ));
        }
        if bytes[offset + 3] != HX3_VERSION {
            return Err(Error::Hx3("unsupported HX3 version in frame set".into()));
        }
        let payload_len =
            u32::from_le_bytes(bytes[offset + 25..offset + 29].try_into().unwrap()) as usize;
        if payload_len > MAX_FRAME_PAYLOAD {
            return Err(Error::Hx3(format!(
                "frame payload of {payload_len} bytes exceeds the limit of {MAX_FRAME_PAYLOAD}"
            )));
        }
        let frame_end = offset
            .checked_add(HEADER_LEN)
            .and_then(|end| end.checked_add(payload_len))
            .ok_or_else(|| Error::Hx3("frame set length overflow".into()))?;
        if frame_end > bytes.len() {
            return Err(Error::Hx3("truncated frame at end of file".into()));
        }
        let frame = Frame::from_bytes(&bytes[offset..frame_end])?;
        frames.push(frame);
        offset = frame_end;
    }
    Ok(frames)
}

/// Reassemble a complete message from its frames.
///
/// Requires:
/// * all frames share the same type, session and total;
/// * the set contains every index exactly once;
/// * no index is out of range.
///
/// Frame order is irrelevant (frames are positional by index).
pub fn assemble_message(
    frames: &[Frame],
) -> Result<(MessageType, [u8; SESSION_LEN], Vec<u8>), Error> {
    if frames.is_empty() {
        return Err(Error::Hx3("no frames to assemble".into()));
    }
    let message_type = frames[0].message_type;
    let session = frames[0].session;
    let total = frames[0].total as usize;
    if total == 0 {
        return Err(Error::Hx3("message total is zero".into()));
    }
    if frames.len() != total {
        return Err(Error::Hx3(format!(
            "incomplete message: have {} frames, expected {total}",
            frames.len()
        )));
    }
    let mut slots: Vec<Option<&[u8]>> = vec![None; total];
    let mut capacity = 0usize;
    for frame in frames {
        if frame.message_type != message_type {
            return Err(Error::Hx3("message mixes different frame types".into()));
        }
        if frame.session != session {
            return Err(Error::Hx3("message mixes different sessions".into()));
        }
        if frame.total as usize != total {
            return Err(Error::Hx3("frame disagree on message total".into()));
        }
        let index = frame.index as usize;
        if index >= total {
            return Err(Error::Hx3(format!(
                "frame index {index} out of range for total {total}"
            )));
        }
        if slots[index].is_some() {
            return Err(Error::Hx3(format!("duplicate frame index {index}")));
        }
        slots[index] = Some(&frame.payload);
        capacity += frame.payload.len();
    }
    let mut payload = Vec::with_capacity(capacity);
    for slot in &slots {
        payload.extend_from_slice(slot.expect("validated complete"));
    }
    Ok((message_type, session, payload))
}

/// Binary header of a PNG file, used to auto-detect QR images by content.
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

/// Encode a single frame as a PNG QR code saved to `path`.
///
/// The QR encodes the frame's base58 text (byte mode). `scale` is the pixel
/// size of each module, and a standard quiet zone of four modules is added.
pub fn write_qr_png(frame: &Frame, path: &std::path::Path, scale: u32) -> Result<(), Error> {
    let text = frame.to_base58();
    let code = qrcode::QrCode::new(text.as_bytes())
        .map_err(|e| Error::Qr(format!("failed to encode QR code: {e}")))?;
    let module_count = code.width() as u32;
    let quiet = 4u32;
    let size = module_count + quiet * 2;
    let pixels = size * scale;

    let mut img = image::GrayImage::from_pixel(pixels, pixels, image::Luma([255u8]));
    for (row, module_row) in code.to_colors().chunks_exact(code.width()).enumerate() {
        for (col, color) in module_row.iter().enumerate() {
            if color == &qrcode::Color::Dark {
                let x = (col as u32 + quiet) * scale;
                let y = row as u32 * scale;
                for dy in 0..scale {
                    for dx in 0..scale {
                        img.put_pixel(x + dx, y + dy, image::Luma([0u8]));
                    }
                }
            }
        }
    }
    img.save(path)
        .map_err(|e| Error::Qr(format!("failed to write QR image {}: {e}", path.display())))?;
    Ok(())
}

/// Decode a single frame from a PNG QR code image.
pub fn read_qr_png(path: &std::path::Path) -> Result<Frame, Error> {
    let img = image::open(path)
        .map_err(|e| Error::Qr(format!("failed to read image {}: {e}", path.display())))?
        .to_luma8();
    let (width, height) = (img.width() as usize, img.height() as usize);
    let mut grid = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| {
        img.get_pixel(x as u32, y as u32)[0]
    });
    let (_, text) = grid
        .detect_grids()
        .iter_mut()
        .find_map(|g| g.decode().ok())
        .ok_or_else(|| Error::Qr("no decodable QR code found in image".into()))?;
    Frame::from_base58(&text)
}

/// Render one frame as a printable QR code using unicode half-blocks. A quiet
/// zone of four light modules surrounds the symbol on every side. A code of
/// width `W` prints as `W + 8` columns and `(W + 8) / 2` lines; counting
/// half-blocks, that is exactly `W` modules wide and `W` modules tall, so it
/// scans like the underlying symbol.
pub fn terminal_qr(frame: &Frame) -> String {
    use qrcode::Color;

    let text = frame.to_base58();
    let code = qrcode::QrCode::new(text.as_bytes()).expect("frame base58 always fits a QR");
    let width = code.width() as i32;
    let quiet = 4i32;
    let colors = code.to_colors();

    let cell = |col: i32, row: i32| -> bool {
        if col < 0 || row < 0 || col >= width || row >= width {
            false
        } else {
            colors[row as usize * code.width() + col as usize] == Color::Dark
        }
    };

    let mut out = String::new();
    let total_columns = width + 2 * quiet;
    let mut module_row = -quiet;
    while module_row < width {
        for col in -quiet..total_columns - quiet {
            let top = cell(col, module_row);
            let bottom = cell(col, module_row + 1);
            let ch = match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            };
            out.push(ch);
        }
        out.push('\n');
        module_row += 2;
    }
    out
}

/// Write a complete message as a `.hx3` file and return the serialized bytes.
pub fn write_message_file(
    path: &std::path::Path,
    message_type: MessageType,
    session: [u8; SESSION_LEN],
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let frames = encode_message(message_type, session, payload)?;
    let bytes = serialize_frames(&frames);
    std::fs::write(path, &bytes).map_err(Error::Io)?;
    Ok(bytes)
}

/// Read a message file, auto-detecting a PNG QR image (single frame) or an
/// `.hx3` frame collection, then reassembling the full message.
pub fn read_message_file(
    path: &std::path::Path,
) -> Result<(MessageType, [u8; SESSION_LEN], Vec<u8>), Error> {
    if is_png_file(path) {
        let frame = read_qr_png(path)?;
        if frame.total != 1 {
            return Err(Error::Hx3(format!(
                "QR image carries frame {}/{}; multi-frame messages need a .hx3 file",
                frame.index + 1,
                frame.total
            )));
        }
        return Ok((frame.message_type, frame.session, frame.payload));
    }
    let bytes = std::fs::read(path).map_err(Error::Io)?;
    let frames = deserialize_frames(&bytes)?;
    assemble_message(&frames)
}

/// True if the file starts with a PNG signature.
fn is_png_file(path: &std::path::Path) -> bool {
    let Ok(head) = std::fs::read(path) else {
        return false;
    };
    head.len() >= PNG_MAGIC.len() && &head[..PNG_MAGIC.len()] == PNG_MAGIC
}
