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

use characteristic::{Characteristic, CharacteristicArgs};
use ctxt::Ctxt;
use proc_macro::TokenStream;
use server::{ServerArgs, ServerBuilder};
use service::{ServiceArgs, ServiceBuilder};
use syn::parse_macro_input;

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
/// ```rust
/// use trouble_host::prelude::*;
/// use trouble_host_macro::gatt_service;
///
/// #[gatt_service(uuid = "7e701cf1-b1df-42a1-bb5f-6a1028c793b0", on_read = service_on_read)]
/// struct HeartRateService {
///    #[characteristic(uuid = "0x2A37", read, notify, value = 3.14, on_read = rate_on_read)]
///    rate: f32,
///    #[characteristic(uuid = "0x2A38", read)]
///    location: f32,
///    #[characteristic(uuid = "0x2A39", write, on_write = control_on_write)]
///    control: u8,
///    #[characteristic(uuid = "0x2A63", read, notify)]
///    energy_expended: u16,
/// }
///
/// fn service_on_read(connection: &Connection) {
///     info!("Read callback triggered for {:?}", connection);
/// }
///
/// fn rate_on_read(connection: &Connection) {
///     info!("Heart rate read on {:?}", connection);
/// }
///
/// fn control_on_write(connection: &Connection, data: &[u8] -> Result<(), ()> {
///     info!("Write event on control attribute from {:?} with data {:?}", connectioni, data);
///     let control = u8::from_gatt(data).unwrap();
///     match control {
///         0 => info!("Control setting 0 selected"),
///         1 => info!("Control setting 1 selected"),
///         _ => {
///             warn!("Unsupported control setting! Rejecting write request.");
///             return Err(())
///         }
///     }
///     Ok(())
/// })
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
            format!("Parsing characteristics was unsuccessful: {}", desc),
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
fn check_for_characteristic(
    field: &syn::Field,
    err: &mut Option<syn::Error>,
    characteristics: &mut Vec<Characteristic>,
) -> bool {
    const RETAIN: bool = true;
    const REMOVE: bool = false;
    let Some(attr) = field.attrs.iter().find(|attr| {
        attr.path().segments.len() == 1 && attr.path().segments.first().unwrap().ident == "characteristic"
    }) else {
        return RETAIN; // If the field does not have a characteristic attribute, retain it.
    };
    let args = match CharacteristicArgs::parse(attr) {
        Ok(args) => args,
        Err(e) => {
            *err = Some(e);
            return REMOVE; // If there was an error parsing the characteristic, remove the field.
        }
    };
    characteristics.push(Characteristic::new(field, args));
    REMOVE // Successfully parsed, remove the field from the fields vec.
}
