extern crate proc_macro;

mod characteristic;
mod ctxt;
mod server;
mod service;
mod uuid;

use characteristic::{Characteristic, CharacteristicArgs};
use ctxt::Ctxt;
use proc_macro::TokenStream;
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
pub fn gatt_server(_args: TokenStream, item: TokenStream) -> TokenStream {
    let ctxt = Ctxt::new();
    let mut server_props = syn::parse_macro_input!(item as syn::ItemStruct);

    let visibility: &syn::Visibility = &server_props.vis;
    let struct_fields = match &mut server_props.fields {
        syn::Fields::Named(n) => n,
        _ => {
            let s = server_props.ident;
            ctxt.error_spanned_by(s, "gatt_server structs must have named fields, not tuples.");
            return TokenStream::new();
        }
    };
    let fields = struct_fields.named.iter().cloned().collect::<Vec<syn::Field>>();

    let server_name = server_props.ident.clone();

    let result: TokenStream = todo!();

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
/// use trouble_host_macro::gatt_service;
///
/// #[gatt_service(uuid = "7e701cf1-b1df-42a1-bb5f-6a1028c793b0")]
/// struct HeartRateService {
///    #[characteristic(uuid = "0x2A37", read, notify, value = 3.14)]
///    rate: f32,
///    #[characteristic(uuid = "0x2A38", read)]
///    location: f32,
///    #[characteristic(uuid = "0x2A39", write)]
///    control: u8,
///    #[characteristic(uuid = "0x2A63", read, notify)]
///    energy_expended: u16,
/// }
/// ```
#[proc_macro_attribute]
pub fn gatt_service(args: TokenStream, item: TokenStream) -> TokenStream {
    let service_uuid = {
        // Get arguments from the gatt_service macro attribute (i.e. uuid)
        let service_attributes: ServiceArgs = {
            let mut attributes = ServiceArgs::default();
            let arg_parser = syn::meta::parser(|meta| attributes.parse(meta));

            // TODO this currently gives a bad error message if the user passes in an invalid attribute
            parse_macro_input!(args with arg_parser);
            attributes
        };
        service_attributes.uuid
    }
    .expect("uuid is required for gatt_service");

    // Parse the contents of the struct
    let mut service_props = syn::parse_macro_input!(item as syn::ItemStruct);

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
    let result = ServiceBuilder::new(service_props, service_uuid)
        .re_add_fields(fields, &characteristics)
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
