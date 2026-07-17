//! Typed identifiers used on the wire and in local stores.
//!
//! Newtypes prevent accidental cross-use of UUID kinds at API boundaries.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! id_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            pub fn from_uuid(id: Uuid) -> Self {
                Self(id)
            }

            pub fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self(value)
            }
        }
    };
}

id_newtype!(
    /// Account identity (server-issued, bound to an identity pubkey).
    AccountId
);
id_newtype!(
    /// Device enrolled under an account (MLS leaf identity binding).
    DeviceId
);
id_newtype!(
    /// House (server / community).
    HouseId
);
id_newtype!(
    /// Channel within a house.
    ChannelId
);
id_newtype!(
    /// MLS group identifier (channel group or DM).
    GroupId
);
id_newtype!(
    /// Server-assigned message row id (ciphertext store).
    MessageId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_roundtrip_json() {
        let a = AccountId::new();
        let json = serde_json::to_string(&a).unwrap();
        let back: AccountId = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }
}
