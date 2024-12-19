//! UUID parsing and generation. This is used internally by the proc macros for parsing UUIDs from attributes.
//!
//! The UUIDs will then be converted to trouble-host UUIDs in the generated code.

use core::str::FromStr;

use darling::FromMeta;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Uuid {
    Uuid16(u16),
    Uuid128([u8; 16]),
}

impl FromMeta for Uuid {
    fn from_string(value: &str) -> darling::Result<Self> {
        if let Ok(u) = uuid::Uuid::from_str(value) {
            let mut bytes = u.as_bytes().to_owned();
            bytes.reverse(); // Little-endian, as per Bluetooth spec
            return Ok(Uuid::Uuid128(bytes));
        }

        if value.len() == 4 {
            if let Ok(u) = u16::from_str_radix(value, 16) {
                return Ok(Uuid::Uuid16(u));
            }
        }

        Err(darling::Error::custom(
            "Invalid UUID (must be a 16-bit or 128-bit UUID)",
        ))
    }
}

impl quote::ToTokens for Uuid {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        match self {
            Uuid::Uuid16(u) => tokens.extend(quote!(::trouble_host::types::uuid::Uuid::new_short(#u))),
            Uuid::Uuid128(u) => {
                let mut s = TokenStream2::new();
                for b in u {
                    s.extend(quote!(#b,))
                }
                tokens.extend(quote!(::trouble_host::types::uuid::Uuid::new_long([#s])));
            }
        }
    }
}
