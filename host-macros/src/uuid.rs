//! UUID parsing and generation. This is used internally by the proc macros for parsing UUIDs from attributes.
//!
//! The UUIDs will then be converted to trouble-host UUIDs in the generated code.

use core::str::FromStr;

use darling::{Error, FromMeta};
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::parse::Result;
use syn::spanned::Spanned;
use syn::Expr;

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

/// Parse the UUID argument of the service attribute.
///
/// The UUID can be specified as a string literal, an integer literal, or an expression that impl Into<Uuid>.
pub(crate) fn parse_arg_uuid(value: &Expr) -> Result<TokenStream2> {
    match value {
        Expr::Lit(lit) => {
            if let syn::Lit::Str(lit_str) = &lit.lit {
                let uuid_string = Uuid::from_string(&lit_str.value()).map_err(|_| {
                    Error::custom(
                        "Invalid UUID string.  Expect i.e. \"180f\" or \"0000180f-0000-1000-8000-00805f9b34fb\"",
                    )
                    .with_span(&lit.span())
                })?;
                Ok(quote::quote! {#uuid_string})
            } else if let syn::Lit::Int(lit_int) = &lit.lit {
                let uuid_string = Uuid::Uuid16(lit_int.base10_parse::<u16>().map_err(|_| {
                    Error::custom("Invalid 16bit UUID literal.  Expect i.e. \"0x180f\"").with_span(&lit.span())
                })?);
                Ok(quote::quote! {#uuid_string})
            } else {
                Err(Error::custom(
                    "Invalid UUID literal.  Expect i.e. \"180f\" or \"0000180f-0000-1000-8000-00805f9b34fb\"",
                )
                .with_span(&lit.span())
                .into())
            }
        }
        other => {
            let span = other.span(); // span will highlight if the value does not impl Into<Uuid>
            Ok(quote::quote_spanned! { span =>
                {
                    let uuid: trouble_host::types::uuid::Uuid = #other.into();
                    uuid
                }
            })
        }
    }
}

pub(crate) struct UuidArgs {
    pub uuid: proc_macro2::TokenStream,
}

impl syn::parse::Parse for UuidArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let expr = input.parse()?;
        let uuid = parse_arg_uuid(&expr)?;
        Ok(UuidArgs { uuid })
    }
}
