use crate::uuid::Uuid;
use darling::FromMeta;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote, quote_spanned};
use syn::meta::ParseNestedMeta;
use syn::parse::Result;
use syn::spanned::Spanned;
use syn::{Ident, LitStr};

pub(crate) struct ServerBuilder {
    server_props: syn::ItemStruct,
    name: Ident,
    uuid: Uuid,
    event_enum_name: Ident,
    code_impl: TokenStream2,
    code_build_chars: TokenStream2,
    code_struct_init: TokenStream2,
    code_on_write: TokenStream2,
    code_event_enum: TokenStream2,
    code_fields: TokenStream2,
}
