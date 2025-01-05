//! Procedural Macros for the `trouble_host` crate.
//!
//! This crate is enabled by the 'derive' feature of the `trouble_host` crate.
//! It adds helper macros to simplify the creation of GATT services and servers.

extern crate proc_macro;

mod characteristic;
mod ctxt;
mod server;
mod service;
mod uuid;

use characteristic::{Characteristic, CharacteristicArgs, DescriptorArgs};
use ctxt::Ctxt;
use proc_macro::TokenStream;
use server::{ServerArgs, ServerBuilder};
use service::{ServiceArgs, ServiceBuilder};
use syn::spanned::Spanned;
use syn::{parse_macro_input, Error};

/// Gatt Service attribute macro.
///
///
///
/// # Example
/// ```rust no_run
/// use trouble_host::prelude::*;
///
/// #[gatt_server]
/// struct MyGattServer {
///     hrs: HeartRateService,
///     bas: BatteryService,
/// }
///
/// ```
#[proc_macro_attribute]
pub fn gatt_server(args: TokenStream, item: TokenStream) -> TokenStream {
    let server_args = {
        let mut attributes = ServerArgs::default();
        let arg_parser = syn::meta::parser(|meta| attributes.parse(meta));

        syn::parse_macro_input!(args with arg_parser);
        attributes
    };
    let ctxt = Ctxt::new();
    let server_properties = syn::parse_macro_input!(item as syn::ItemStruct);

    let result = ServerBuilder::new(server_properties, server_args).build();

    match ctxt.check() {
        Ok(()) => result.into(),
        Err(e) => e.into(),
    }
}

/// Gatt Service attribute macro.
///
/// # Example
///
/// ```rust no_run
/// use trouble_host::prelude::*;
///
/// const DESCRIPTOR_VALUE: &str = "Can be specified from a const";
///
/// #[gatt_service(uuid = "7e701cf1-b1df-42a1-bb5f-6a1028c793b0")]
/// struct HeartRateService {
///    /// Docstrings can be
///    /// Multiple lines
///    #[descriptor(uuid = "2a21", read, value = [0x00,0x01,0x02,0x03])]
///    #[characteristic(uuid = characteristic::HEART_RATE_MEASUREMENT, read, notify, value = 3.14)]
///    rate: f32,
///    #[descriptor(uuid = descriptors::MEASUREMENT_DESCRIPTION, read, value = DESCRIPTOR_VALUE)]
///    #[characteristic(uuid = "2a28", read, write, notify, value = 42.0)]
///    /// Can be in any order
///    location: f32,
///    #[characteristic(uuid = "2a39", write)]
///    control: u8,
///    #[characteristic(uuid = "2a63", read, notify)]
///    energy_expended: u16,
/// }
/// ```
#[proc_macro_attribute]
pub fn gatt_service(args: TokenStream, item: TokenStream) -> TokenStream {
    // Get arguments from the gatt_service macro attribute
    let service_arguments = parse_macro_input!(args as ServiceArgs);

    // Parse the contents of the struct
    let mut service_props = parse_macro_input!(item as syn::ItemStruct);

    let ctxt = Ctxt::new(); // error handling context, must be initialized after parse_macro_input calls.

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

    // Parse fields tagged as characteristics, remove them from the fields vec and store them in a separate vec.
    let mut characteristics: Vec<Characteristic> = Vec::new();
    let mut err: Option<syn::Error> = None;
    fields.retain(|field| check_for_characteristic(field, &mut err, &mut characteristics));

    // If there was an error parsing the characteristics, return the error
    if let Some(err) = err {
        let desc = err.to_string();
        ctxt.error_spanned_by(
            err.into_compile_error(),
            format!("Parsing characteristics was unsuccessful:\n{}", desc),
        );
        return ctxt.check().unwrap_err().into();
    }

    // Build the service struct
    let result = ServiceBuilder::new(service_props, service_arguments)
        .process_characteristics_and_fields(fields, characteristics)
        .build();

    match ctxt.check() {
        Ok(()) => result.into(),
        Err(e) => e.into(),
    }
}

/// Check if a field has a characteristic attribute and parse it.
///
/// If so also check if that field has descriptors and/or docstrings.
///
/// # Example
///
/// ```rust
/// use trouble_host::prelude::*;
///
/// #[gatt_service(uuid = "180f")]
/// struct BatteryService {
///    /// Docstrings can be
///    /// Multiple lines
///    #[characteristic(uuid = "2a19", read, write, notify, value = 99)]
///    #[descriptor(uuid = "2a20", read, value = [0x00,0x01,0x02,0x03])]
///    #[descriptor(uuid = "2a20", read, value = "Demo description")]
///    level: u8,
///    #[descriptor(uuid = "2a21", read, value = VAL)]
///    #[characteristic(uuid = "2a22", read, write, notify, value = 42.0)]
///    /// Can be in any order
///    rate_of_discharge: f32,
///}
/// ```
fn check_for_characteristic(
    field: &syn::Field,
    err: &mut Option<syn::Error>,
    characteristics: &mut Vec<Characteristic>,
) -> bool {
    const RETAIN: bool = true;
    const REMOVE: bool = false;

    let Some(attr) = field.attrs.iter().find(|attr| attr.path().is_ident("characteristic")) else {
        return RETAIN; // If the field does not have a characteristic attribute, retain it.
    };
    let mut descriptors = Vec::new();
    let mut doc_string = String::new();
    let mut characteristic_checked = false;
    for attr in &field.attrs {
        if let Some(ident) = attr.path().get_ident() {
            match ident.to_string().as_str() {
                "doc" => {
                    if let Ok(meta_name_value) = attr.meta.require_name_value() {
                        if let syn::Expr::Lit(value) = &meta_name_value.value {
                            if let Some(text) = &value.lit.span().source_text() {
                                let text: Vec<&str> = text.split("///").collect();
                                if let Some(text) = text.get(1) {
                                    if !doc_string.is_empty() {
                                        doc_string.push('\n');
                                    }
                                    doc_string.push_str(text);
                                }
                            }
                        }
                    }
                }
                "descriptor" => match DescriptorArgs::parse(attr) {
                    Ok(args) => descriptors.push(args),
                    Err(e) => {
                        *err = Some(e);
                        return REMOVE; // If there was an error parsing the descriptor, remove the field.
                    }
                },
                "characteristic" => {
                    // make sure we only have one characteristic meta tag
                    if characteristic_checked {
                        *err = Some(Error::new(
                            attr.path().span(),
                            "only one characteristic tag should be applied per field",
                        ));
                        return REMOVE; // If there was an error parsing the descriptor, remove the field.
                    } else {
                        characteristic_checked = true;
                    }
                }
                "descriptors" => {
                    *err = Some(Error::new(
                        attr.path().span(),
                        "specify a descriptor like: #[descriptor(uuid = \"1234\", value = \"Hello World\", read, write, notify)]\nCan be specified multiple times.",
                    ));
                    return REMOVE; // If there was an error parsing the descriptor, remove the field.
                }
                _ => {
                    *err = Some(Error::new(
                        attr.path().span(),
                        "only doc (///), descriptor and characteristic tags are supported.",
                    ));
                    return REMOVE; // If there was an error parsing the descriptor, remove the field.
                }
            }
        }
    }
    let mut args = match CharacteristicArgs::parse(attr) {
        Ok(args) => args,
        Err(e) => {
            *err = Some(e);
            return REMOVE; // If there was an error parsing the characteristic, remove the field.
        }
    };
    args.doc_string = doc_string;
    args.descriptors = descriptors;
    characteristics.push(Characteristic::new(field, args));
    REMOVE // Successfully parsed, remove the field from the fields vec.
}
