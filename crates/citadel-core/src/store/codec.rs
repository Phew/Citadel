//! `citadel-openmls-json-v1`: the deterministic storage codec (ADR-0007 §1).
//!
//! Every OpenMLS storage value in the encrypted database is written by this
//! codec, and its identifier plus the OpenMLS version tuple it is bound to are
//! written to `citadel_store_meta` **before the first OpenMLS record**. An
//! unknown or newer identifier or tuple fails closed: there is no trial
//! decoding and no silent fallback between codecs.
//!
//! **This format is a compatibility format only.** It is never used as an
//! identifier, a signature input, or a hash input. The one place Citadel hashes
//! canonical JSON is the operation-request fingerprint in
//! [`crate::store::ledger`], which uses the same rules under its own domain
//! prefix and is likewise not a wire contract.
//!
//! Determinism comes from two pinned properties of `serde_json =1.0.150`:
//!
//! - `preserve_order` is **off**, so `serde_json::Map` is a `BTreeMap` and
//!   object keys are emitted in one fixed order regardless of struct field
//!   order or insertion order;
//! - the compact writer emits no whitespace, so there is one byte string per
//!   value.
//!
//! Serialization therefore converts to `serde_json::Value` first and only then
//! writes bytes, which is what forces every nested object through that ordered
//! map. Deserialization rejects malformed input **and trailing non-whitespace**,
//! so a value cannot be extended with an ignored suffix.

use openmls_sqlite_storage::Codec;
use serde::{de::DeserializeOwned, Serialize};

/// The codec identifier written to database metadata.
pub const CODEC_ID: &str = "citadel-openmls-json-v1";

/// The exact OpenMLS crate versions this codec identifier is bound to
/// (ADR-0007 §1). Changing any of them requires a **new** codec identifier and
/// a migration, even if the corpus happens to stay byte-identical, because the
/// identifier names a schema and not merely an encoding.
pub const CODEC_BOUND_VERSIONS: &str =
    "openmls=0.8.1;openmls_traits=0.5.0;openmls_sqlite_storage=0.2.0;provider_schema=1";

/// Encoding or decoding a stored OpenMLS value failed.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// The value could not be encoded, or bytes were malformed.
    #[error("citadel-openmls-json-v1: {0}")]
    Json(#[from] serde_json::Error),
    /// Bytes decoded, but non-whitespace input followed the value. Accepting a
    /// trailing suffix would let two different byte strings mean the same
    /// record, which is exactly what a deterministic format must not allow.
    #[error("citadel-openmls-json-v1: trailing input after the encoded value")]
    TrailingInput,
}

/// The private v1 codec. Public only as a type name so the provider can be
/// spelled out in signatures; its byte format is pinned by the committed golden
/// corpus in `store::tests`, not by this implementation being readable.
#[derive(Debug, Default, Clone, Copy)]
pub struct CitadelOpenMlsJsonCodecV1;

impl Codec for CitadelOpenMlsJsonCodecV1 {
    type Error = CodecError;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        // Two steps deliberately: `to_value` forces every nested object through
        // serde_json's ordered map before any bytes exist. Serializing straight
        // to bytes would emit struct fields in declaration order, which is a
        // property of the Rust type rather than of the format.
        let ordered = serde_json::to_value(value)?;
        Ok(serde_json::to_vec(&ordered)?)
    }

    fn from_slice<T: DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        let mut deserializer = serde_json::Deserializer::from_slice(slice);
        let value = T::deserialize(&mut deserializer)?;
        deserializer.end().map_err(|error| {
            if error.is_eof() || error.is_syntax() {
                CodecError::TrailingInput
            } else {
                CodecError::Json(error)
            }
        })?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Nested {
        zulu: u8,
        alpha: Vec<u8>,
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Sample {
        zebra: String,
        apple: Option<u64>,
        nested: Nested,
    }

    fn sample() -> Sample {
        Sample {
            zebra: "z".into(),
            apple: Some(7),
            nested: Nested {
                zulu: 1,
                alpha: vec![0, 255],
            },
        }
    }

    #[test]
    fn writes_one_pinned_byte_string_with_sorted_keys() {
        let bytes = CitadelOpenMlsJsonCodecV1::to_vec(&sample()).expect("encodes");
        // Field order in the Rust struct is zebra, apple, nested; the codec must
        // emit apple, nested, zebra. If this ever changes, the codec identifier
        // must change with it (ADR-0007 §1).
        assert_eq!(
            std::str::from_utf8(&bytes).expect("utf-8"),
            r#"{"apple":7,"nested":{"alpha":[0,255],"zulu":1},"zebra":"z"}"#
        );
    }

    #[test]
    fn roundtrips_through_the_pinned_bytes() {
        let bytes = CitadelOpenMlsJsonCodecV1::to_vec(&sample()).expect("encodes");
        let decoded: Sample = CitadelOpenMlsJsonCodecV1::from_slice(&bytes).expect("decodes");
        assert_eq!(decoded, sample());
    }

    #[test]
    fn rejects_trailing_non_whitespace() {
        let mut bytes = CitadelOpenMlsJsonCodecV1::to_vec(&sample()).expect("encodes");
        bytes.extend_from_slice(b"{}");
        let result: Result<Sample, _> = CitadelOpenMlsJsonCodecV1::from_slice(&bytes);
        assert!(
            matches!(result, Err(CodecError::TrailingInput)),
            "a trailing value must be rejected, got {result:?}"
        );
    }

    #[test]
    fn accepts_trailing_whitespace_only() {
        let mut bytes = CitadelOpenMlsJsonCodecV1::to_vec(&sample()).expect("encodes");
        bytes.extend_from_slice(b" \n\t");
        let decoded: Sample =
            CitadelOpenMlsJsonCodecV1::from_slice(&bytes).expect("whitespace is not input");
        assert_eq!(decoded, sample());
    }

    #[test]
    fn rejects_malformed_input() {
        let result: Result<Sample, _> = CitadelOpenMlsJsonCodecV1::from_slice(b"{\"apple\":");
        assert!(matches!(result, Err(CodecError::Json(_))), "{result:?}");
    }
}
