extern crate proc_macro;


use darling::ast::NestedMeta;
use darling::util::parse_attribute_to_meta_list;
use darling::{Error, FromMeta};
use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote, quote_spanned, ToTokens};
use syn::meta::ParseNestedMeta;
use syn::parse::{Parse, ParseBuffer, Parser, Result};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{parse_macro_input, Ident, Lit, LitStr, Path, Token};

use crate::ctxt::Ctxt;

mod ctxt;
mod uuid;

use crate::uuid::Uuid;

#[derive(Debug, FromMeta, Default)]
struct ServiceArgs {
    uuid: String,
}

impl ServiceArgs {
    fn parse(&mut self, meta: ParseNestedMeta) -> Result<()> {
        if meta.path.is_ident("uuid") {
            let uuid_string: LitStr = meta.value()?.parse()?;
            self.uuid = uuid_string.value();
            Ok(())
        } else {
            Err(meta.error("Unsupported service property, 'uuid' is the only supported property"))
        }
    }
}

/// Descriptor attribute arguments.
///
/// Descriptors are optional and can be used to add additional metadata to the characteristic.
#[derive(Debug, FromMeta)]
struct DescriptorArgs {
    /// The UUID of the descriptor.
    uuid: Uuid,
    /// The value of the descriptor.
    #[darling(default)]
    value: Option<syn::Expr>,
}

/// Characteristic attribute arguments
#[derive(Debug, FromMeta, Default)]
struct CharacteristicArgs {
    /// The UUID of the characteristic.
    uuid: String,
    /// If true, the characteristic can be read.
    #[darling(default)]
    read: bool,
    /// If true, the characteristic can be written.
    #[darling(default)]
    write: bool,
    /// If true, the characteristic can be written without a response.
    #[darling(default)]
    write_without_response: bool,
    /// If true, the characteristic can send notifications.
    #[darling(default)]
    notify: bool,
    /// If true, the characteristic can send indications.
    #[darling(default)]
    indicate: bool,
    /// The initial value of the characteristic.
    /// This is optional and can be used to set the initial value of the characteristic.
    #[darling(default)]
    value: Option<syn::Expr>,
    // /// Descriptors for the characteristic.
    // /// Descriptors are optional and can be used to add additional metadata to the characteristic.
    // #[darling(default, multiple)]
    // descriptor: Vec<DescriptorArgs>,
}

#[derive(Debug)]
struct Characteristic {
    name: String,
    ty: syn::Type,
    args: CharacteristicArgs,
    span: Span,
    vis: syn::Visibility,
}

impl CharacteristicArgs {
    fn parse(&mut self, meta: ParseNestedMeta) -> Result<()> {
        let meta: Vec<NestedMeta> = {
            let val = Punctuated::<NestedMeta, Token![,]>::parse_terminated(meta.value()?)?;
            val.into_iter().collect()
        };
        
        let args = CharacteristicArgs::from_list(&meta)?;
        panic!("{args:?}");
        // if let Some(ident) = meta.path.get_ident() {
        //     match &*ident.to_string() {
        //         "uuid" => self.uuid = meta.value()?.to_string(),
        //         "read" => self.read = true,
        //         "write" => self.write = true,
        //         "write_without_response" => self.write_without_response = true,
        //         "notify" => self.notify = true,
        //         "indicate" => self.indicate = true,
        //         "value" => self.value = Some(meta.value()?.parse()?),
        //         other => return Err(meta.error(format!("Unsupported characteristic property: {other}"))),
        //     }
        // }
        Ok(())
    }
}

#[proc_macro_attribute]
/// Gatt Service attribute macro
///
/// # Example
///
/// ```rust
/// #[gatt_service(uuid = "7e701cf1-b1df-42a1-bb5f-6a1028c793b0")]
/// struct HeartRateService {
///    #[characteristic(uuid = "0x2A37", read, notify)]
///    #[descriptor(uuid = "0x2902", value = "heart rate in bpm")]
///    rate: f32,
///    #[characteristic(uuid = "0x2A38", read)]
///    #[descriptor(uuid = "0x2902", value = "body sensor location")]
///    location: f32,
///    #[characteristic(uuid = "0x2A39", write)]
///    #[descriptor(uuid = "0x2902", value = "heart rate control point")]
///    control: u8,
///    #[characteristic(uuid = "0x2A63", read, notify)]
///    #[descriptor(uuid = "0x2902", value = "energy expended")]
///    energy_expended: u16,
/// }
/// ```
pub fn gatt_service(args: TokenStream, item: TokenStream) -> TokenStream {
    let ctxt = Ctxt::new(); // error handling context
    
    // Get arguments from the gatt_service macro attribute (i.e. uuid)
    let service_attributes: ServiceArgs = {
        let mut attributes = ServiceArgs::default();
        let arg_parser = syn::meta::parser(|meta| attributes.parse(meta));
        parse_macro_input!(args with arg_parser);
        attributes
    };

    // Parse the contents of the struct
    let mut service_props = syn::parse_macro_input!(item as syn::ItemStruct);
    let struct_vis = &service_props.vis;

    let mut fields: Vec<syn::Field> = {
        let struct_fields = match &mut service_props.fields {
            syn::Fields::Named(n) => n,
            _ => {
                let s = service_props.ident;
                ctxt.error_spanned_by(s, "gatt_service structs must have named fields, not tuples.");
                return ctxt.check().unwrap_err().into();
            }
        };
        struct_fields.named.iter().cloned().collect()
    };

    // Parse characteristics, remove them from the fields and store them in a vector
    let mut characteristics: Vec<Characteristic> = Vec::new();
    let mut err: Option<syn::Error> = None;
    fields.retain(|field| {
        let Some(attr) = field
            .attrs
            .iter()
            .find(|attr| attr.path().segments.len() == 1 && attr.path().segments.first().unwrap().ident == "characteristic") else { 
                return true; 
        };
        let mut characteristic_args = CharacteristicArgs::default();
        if let Err(e) = attr.parse_nested_meta(|meta| {
            match meta.path.get_ident().ok_or(Error::custom("no ident"))?.to_string().as_str() {
                "uuid" => {
                    let value = meta.value()?;
                    characteristic_args.uuid = value.parse::<LitStr>()?.value()},
                "read" => characteristic_args.read = true,
                "write" => characteristic_args.write = true,
                "write_without_response" => characteristic_args.write_without_response = true,
                "notify" => characteristic_args.notify = true,
                "indicate" => characteristic_args.indicate = true,
                "value" => {
                    unimplemented!("default values aren't supported yet");
                    // let value = meta.value()?;
                    // characteristic_args.value = Some(value.parse()?)
                    },
                other => return Err(meta.error(format!("Unsupported characteristic property: {other}"))),
            }
            Ok(())
        }) {
            err = Some(e);
            return false;
        };
        // panic!("{characteristic_args:#?}");

        characteristics.push(Characteristic {
            name: field.ident.as_ref().unwrap().to_string(),
            ty: field.ty.clone(),
            args: characteristic_args,
            span: field.ty.span(),
            vis: field.vis.clone(),
        });

        false
        }
    );

    if let Some(err) = err {
        let desc = err.to_string();
        ctxt.error_spanned_by(
            err.into_compile_error(),
            format!("Parsing characteristics was unsuccessful: {}", desc),
        );
        return ctxt.check().unwrap_err().into();
    }

    panic!("chars {:#?}", characteristics);
}
