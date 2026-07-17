//! Serde helpers for byte fields on the wire.
//!
//! All opaque byte fields in JSON bodies are standard base64 strings.
//! Fixed 32-byte values (hashes, Ed25519 public keys, signature halves) use
//! [`b64fixed32`]; variable-length values use [`b64vec`]; 64-byte Ed25519
//! signatures use [`b64fixed64`].

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serializer};

/// Serialize/deserialize `Vec<u8>` as standard base64.
pub mod b64vec {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

/// Serialize/deserialize `[u8; 32]` as standard base64.
pub mod b64fixed32 {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
        })
    }
}

/// Serialize/deserialize `[u8; 64]` (Ed25519 signature) as standard base64.
pub mod b64fixed64 {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let v = B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 64 bytes, got {}", v.len()))
        })
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        #[serde(with = "super::b64fixed32")]
        h: [u8; 32],
        #[serde(with = "super::b64vec")]
        v: Vec<u8>,
    }

    #[test]
    fn roundtrip_and_length_enforcement() {
        let t = T {
            h: [7u8; 32],
            v: vec![1, 2, 3],
        };
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(serde_json::from_str::<T>(&json).unwrap(), t);

        // Wrong-length hash must be rejected, not truncated/padded.
        let bad = r#"{"h":"AQI=","v":""}"#;
        assert!(serde_json::from_str::<T>(bad).is_err());
    }
}
