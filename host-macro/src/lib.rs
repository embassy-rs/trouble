extern crate proc_macro;

use darling::{Error, FromMeta};
use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote, quote_spanned, ToTokens};
use syn::spanned::Spanned;

use crate::ctxt::Ctxt;

mod ctxt;
mod uuid;

use crate::uuid::Uuid;

#[derive(Debug, FromMeta)]
struct ServiceArgs {
    uuid: Uuid,
}

#[derive(Debug, FromMeta)]
struct DescriptorArgs {
    uuid: Uuid,
    #[darling(default)]
    value: Option<syn::Expr>,
}

#[derive(Debug, FromMeta)]
struct CharacteristicArgs {
    uuid: Uuid,
    #[darling(default)]
    read: bool,
    #[darling(default)]
    write: bool,
    #[darling(default)]
    write_without_response: bool,
    #[darling(default)]
    notify: bool,
    #[darling(default)]
    indicate: bool,
    #[darling(default)]
    value: Option<syn::Expr>,
    #[darling(default, multiple)]
    descriptor: Vec<DescriptorArgs>,
}

#[proc_macro_attribute]
pub fn gatt_service(args: TokenStream, item: TokenStream) -> TokenStream {
    let args = syn::parse_macro_input!(args as syn::AttributeArgs);
    let mut struc = syn::parse_macro_input!(item as syn::ItemStruct);

    let ctxt = Ctxt::new();

    let args = match ServiceArgs::from_list(&args) {
        Ok(v) => v,
        Err(e) => {
            ctxt.error_spanned_by(e.write_errors(), "ServiceArgs Parsing failed");
            return ctxt.check().unwrap_err().into();
        }
    };

    let mut chars = Vec::new();

    let struct_vis = &struc.vis;
    let struct_fields = match &mut struc.fields {
        syn::Fields::Named(n) => n,
        _ => {
            let s = struc.ident;

            ctxt.error_spanned_by(s, "gatt_service structs must have named fields, not tuples.");

            return ctxt.check().unwrap_err().into();
        }
    };
    let mut fields = struct_fields.named.iter().cloned().collect::<Vec<syn::Field>>();
    let mut err: Option<Error> = None;
    fields.retain(|field| {
        if let Some(attr) = field
            .attrs
            .iter()
            .find(|attr| attr.path.segments.len() == 1 && attr.path.segments.first().unwrap().ident == "characteristic")
        {
            let args = attr.parse_meta().unwrap();

            let args = match CharacteristicArgs::from_meta(&args) {
                Ok(v) => v,
                Err(e) => {
                    err = Some(e);
                    return false;
                }
            };

            chars.push(Characteristic {
                name: field.ident.as_ref().unwrap().to_string(),
                ty: field.ty.clone(),
                args,
                span: field.ty.span(),
                vis: field.vis.clone(),
            });

            false
        } else {
            true
        }
    });

    if let Some(err) = err {
        let desc = err.to_string();
        ctxt.error_spanned_by(
            err.write_errors(),
            format!("Parsing characteristics was unsuccessful: {}", desc),
        );
        return ctxt.check().unwrap_err().into();
    }

    panic!("chars {:?}", chars);
}