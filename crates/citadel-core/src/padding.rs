//! Length-hiding application framing (ADR-0005 §3, PLAN §7 F4).
//!
//! This is **not** a crypto primitive (INV-10). It is deterministic, keyless
//! framing over plaintext: a length prefix plus a zero pad to the next size
//! bucket. It is applied to the plaintext **before** OpenMLS encrypt and
//! stripped **after** OpenMLS decrypt (pad-then-encrypt), so the delivery
//! service only ever sees ciphertext in a handful of uniform length classes.
//! OpenMLS owns all AEAD; this module owns no key, KDF, nonce, or MAC.
//!
//! Frame layout: `u32-BE content_length || content || zero-pad` up to the
//! smallest bucket `>= 4 + content_length`.

/// Padding buckets in bytes (ADR-0005 §3, PLAN §7 F4). A padded frame is always
/// exactly one of these lengths.
pub const BUCKETS: [usize; 4] = [256, 1024, 4096, 16384];

/// Length prefix width (`u32` big-endian).
const LEN_PREFIX: usize = 4;

/// Largest content that still fits a frame (largest bucket minus the prefix).
pub const MAX_CONTENT: usize = 16384 - LEN_PREFIX; // 16380

/// Errors from framing.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PadError {
    /// `4 + content_length` exceeds the largest bucket. M2 handles text DMs;
    /// larger payloads are attachments (M5), which carry their own keys in-band.
    #[error("content too large to pad: {0} bytes exceeds max {MAX_CONTENT}")]
    TooLarge(usize),
    /// A frame shorter than the length prefix, or whose declared length runs
    /// past the frame, or whose length is not exactly a bucket size.
    #[error("malformed padded frame")]
    Malformed,
    /// Pad bytes were not all zero (tamper or a non-conforming sender). MLS AEAD
    /// already guarantees integrity end to end; this is defense in depth.
    #[error("non-zero padding bytes")]
    NonZeroPadding,
}

/// The smallest bucket that holds `4 + content_len`, or `None` if too large.
fn bucket_for(framed_len: usize) -> Option<usize> {
    BUCKETS.into_iter().find(|&b| b >= framed_len)
}

/// Frame and pad `content` to the next bucket. The result length is always one
/// of [`BUCKETS`]. Call this on plaintext *before* MLS encrypt.
pub fn pad(content: &[u8]) -> Result<Vec<u8>, PadError> {
    let framed_len = LEN_PREFIX + content.len();
    let bucket = bucket_for(framed_len).ok_or(PadError::TooLarge(content.len()))?;
    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(&(content.len() as u32).to_be_bytes());
    out.extend_from_slice(content);
    out.resize(bucket, 0);
    Ok(out)
}

/// Strip a padded frame back to its content. Call this on decrypted plaintext
/// *after* MLS decrypt. Validates the frame is exactly a bucket size, the
/// declared length fits, and the pad is all zero.
pub fn unpad(frame: &[u8]) -> Result<Vec<u8>, PadError> {
    if !BUCKETS.contains(&frame.len()) {
        return Err(PadError::Malformed);
    }
    let len = u32::from_be_bytes(frame[..LEN_PREFIX].try_into().unwrap()) as usize;
    let end = LEN_PREFIX.checked_add(len).ok_or(PadError::Malformed)?;
    if end > frame.len() {
        return Err(PadError::Malformed);
    }
    if frame[end..].iter().any(|&b| b != 0) {
        return Err(PadError::NonZeroPadding);
    }
    Ok(frame[LEN_PREFIX..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_bucket_sizes_across_boundaries() {
        // Includes each bucket boundary and either side of it.
        let lengths = [
            0usize, 1, 251, 252, 253, 1019, 1020, 1021, 4091, 4092, 4093, 16379, 16380,
        ];
        for &n in &lengths {
            let content = vec![0xABu8; n];
            let padded = pad(&content).unwrap();
            assert!(
                BUCKETS.contains(&padded.len()),
                "len {n} padded to non-bucket size {}",
                padded.len()
            );
            assert_eq!(unpad(&padded).unwrap(), content, "roundtrip failed at {n}");
        }
    }

    #[test]
    fn oversize_rejected() {
        assert_eq!(
            pad(&vec![0u8; MAX_CONTENT + 1]),
            Err(PadError::TooLarge(MAX_CONTENT + 1))
        );
        // Exactly MAX_CONTENT fits the largest bucket.
        assert_eq!(pad(&vec![0u8; MAX_CONTENT]).unwrap().len(), 16384);
    }

    #[test]
    fn unpad_rejects_non_bucket_length() {
        assert_eq!(unpad(&[0u8; 100]), Err(PadError::Malformed));
    }

    #[test]
    fn unpad_rejects_length_running_past_frame() {
        let mut frame = vec![0u8; 256];
        frame[..4].copy_from_slice(&(1000u32).to_be_bytes()); // claims 1000 > 252
        assert_eq!(unpad(&frame), Err(PadError::Malformed));
    }

    #[test]
    fn unpad_rejects_nonzero_padding() {
        let mut padded = pad(b"hi").unwrap();
        *padded.last_mut().unwrap() = 1;
        assert_eq!(unpad(&padded), Err(PadError::NonZeroPadding));
    }

    #[test]
    fn distinct_lengths_in_same_bucket_are_indistinguishable_by_size() {
        // Length hiding: two very different plaintext sizes share a bucket.
        assert_eq!(pad(b"a").unwrap().len(), pad(&[0u8; 200]).unwrap().len());
    }
}
