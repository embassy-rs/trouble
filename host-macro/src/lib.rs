extern crate proc_macro;

use characteristic::{Characteristic, CharacteristicArgs};
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
use syn::{parse_macro_input, Ident, Lit, LitStr, Path, Token, Type};

use crate::ctxt::Ctxt;

mod characteristic;
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

/// Gatt Service attribute macro.
///
/// # Example
///
/// ```rust
/// use trouble_host_macro::gatt_service;
///
/// #[gatt_service(uuid = "7e701cf1-b1df-42a1-bb5f-6a1028c793b0")]
/// struct HeartRateService {
///    #[characteristic(uuid = "0x2A37", read, notify)]
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
    let ctxt = Ctxt::new(); // error handling context

    let service_uuid = {
        // Get arguments from the gatt_service macro attribute (i.e. uuid)
        let service_attributes: ServiceArgs = {
            let mut attributes = ServiceArgs::default();
            let arg_parser = syn::meta::parser(|meta| attributes.parse(meta));
            parse_macro_input!(args with arg_parser);
            attributes
        };
        service_attributes.uuid
    };

    // Parse the contents of the struct
    let mut service_props = syn::parse_macro_input!(item as syn::ItemStruct);

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
    let result = {
        let mut builder = ServiceBuilder::new(service_props);
        builder.re_add_fields(&mut fields, &characteristics);
        builder.build()
    };

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

struct ServiceBuilder {
    service_props: syn::ItemStruct,
    name: Ident,
    event_enum_name: Ident,
    code_impl: TokenStream2,
    code_build_chars: TokenStream2,
    code_struct_init: TokenStream2,
    code_on_write: TokenStream2,
    code_event_enum: TokenStream2,
    trouble: TokenStream2,
}

impl ServiceBuilder {
    fn new(props: syn::ItemStruct) -> Self {
        let name = props.ident.clone();
        Self {
            event_enum_name: format_ident!("{}Event", name),
            name,
            service_props: props,
            code_impl: TokenStream2::new(),
            code_build_chars: TokenStream2::new(),
            code_struct_init: TokenStream2::new(),
            code_on_write: TokenStream2::new(),
            code_event_enum: TokenStream2::new(),
            trouble: quote!(::trouble_host::prelude::*),
        }
    }

    fn build(self) -> TokenStream2 {
        let service_props = self.service_props;
        let visibility = service_props.vis.clone();
        let struct_name = self.name;
        let trouble = self.trouble;
        let code_struct_init = self.code_struct_init;
        let code_impl = self.code_impl;
        let event_enum_name = self.event_enum_name;
        let code_event_enum = self.code_event_enum;
        let code_build_chars = self.code_build_chars;
        let result = quote! {
            #service_props

            #[allow(unused)]
            impl #struct_name {
                #visibility fn new() -> Result<Self, #trouble::BleHostError>
                {
                    #code_build_chars

                    Ok(Self {
                        #code_struct_init
                    })
                }
                #code_impl
            }
            #[allow(unused)]
            #visibility enum #event_enum_name {
                #code_event_enum
            }
        };
        result
    }

    fn re_add_fields(&mut self, fields: &mut Vec<syn::Field>, characteristics: &Vec<Characteristic>) {
        let trouble = self.trouble.clone();
        let event_enum_name = self.event_enum_name.clone();
        for ch in characteristics {
            let name_pascal = inflector::cases::pascalcase::to_pascal_case(&ch.name);
            let char_name = format_ident!("{}", ch.name);
            let value_handle = format_ident!("{}_value_handle", ch.name);
            let cccd_handle = format_ident!("{}_cccd_handle", ch.name);
            let get_fn = format_ident!("{}_get", ch.name);
            let set_fn = format_ident!("{}_set", ch.name);
            let notify_fn = format_ident!("{}_notify", ch.name);
            let indicate_fn = format_ident!("{}_indicate", ch.name);
            let fn_vis = ch.vis.clone();

            let uuid = ch.args.uuid.clone();
            let read = ch.args.read;
            let write = ch.args.write;
            let write_without_response = ch.args.write_without_response;
            let notify = ch.args.notify;
            let indicate = ch.args.indicate;
            let ty = &ch.ty;
            // let ty = match &ch.ty {
            //     Type::Path(path) => &path.path,
            //     _ => panic!("unexpected type {:#?}", ch.ty),
            // };
            // let ty_as_val = quote!(<#ty as #trouble::Type>);
            // let value = match &ch.args.value {
            //     Some(v) => quote! { #v },
            //     None => quote! { [123u8; #ty_as_val::MIN_SIZE] },
            // };
            // panic!("value {:#?}", value);

            // add fields for each characteristic value handle
            fields.push(syn::Field {
                ident: Some(value_handle.clone()),
                ty: syn::Type::Verbatim(quote!(u16)),
                attrs: Vec::new(),
                colon_token: Default::default(),
                vis: syn::Visibility::Inherited,
                mutability: syn::FieldMutability::None,
            });

            self.code_struct_init.extend(quote_spanned!(ch.span=>
                #value_handle: #char_name.value_handle,
            ));

            if indicate || notify {
                fields.push(syn::Field {
                    ident: Some(cccd_handle.clone()),
                    ty: syn::Type::Verbatim(quote!(u16)),
                    attrs: Vec::new(),
                    colon_token: Default::default(),
                    vis: syn::Visibility::Inherited,
                    mutability: syn::FieldMutability::None,
                });
                self.code_struct_init.extend(quote_spanned!(ch.span=>
                    #cccd_handle: #char_name.cccd_handle,
                ));
            }

            if notify {
                self.code_impl.extend(quote_spanned!(ch.span=>
                    #fn_vis fn #notify_fn(
                        &self,
                        conn: &#trouble::Connection,
                        val: &#ty,
                    ) -> Result<(), #trouble::BleHostError> {
                        // let buf = #ty_as_val::to_gatt(val);
                        // #ble::gatt_server::notify_value(conn, self.#value_handle, buf)
                        unimplemented!("notify {val:?}")
                    }
                ));

                if !indicate {
                    let case_cccd_write = format_ident!("{}CccdWrite", name_pascal);

                    self.code_event_enum.extend(quote_spanned!(ch.span=>
                        #case_cccd_write{notifications: bool},
                    ));
                    self.code_on_write.extend(quote_spanned!(ch.span=>
                        if handle == self.#cccd_handle && !data.is_empty() {
                            match data[0] & 0x01 {
                                0x00 => return Some(#event_enum_name::#case_cccd_write{notifications: false}),
                                0x01 => return Some(#event_enum_name::#case_cccd_write{notifications: true}),
                                _ => {},
                            }
                        }
                    ));
                }
            }

            if indicate {
                self.code_impl.extend(quote_spanned!(ch.span=>
                    #fn_vis fn #indicate_fn(
                        &self,
                        conn: &#trouble::Connection,
                        val: &#ty,
                    ) -> Result<(), #trouble::BleHostError> {
                        // let buf = #ty_as_val::to_gatt(val);
                        // #ble::gatt_server::indicate_value(conn, self.#value_handle, buf)
                        unimplemented!("indicate {val:?}")
                    }
                ));

                if !notify {
                    let case_cccd_write = format_ident!("{}CccdWrite", name_pascal);

                    self.code_event_enum.extend(quote_spanned!(ch.span=>
                        #case_cccd_write{indications: bool},
                    ));
                    self.code_on_write.extend(quote_spanned!(ch.span=>
                        if handle == self.#cccd_handle && !data.is_empty() {
                            match data[0] & 0x02 {
                                0x00 => return Some(#event_enum_name::#case_cccd_write{indications: false}),
                                0x02 => return Some(#event_enum_name::#case_cccd_write{indications: true}),
                                _ => {},
                            }
                        }
                    ));
                }
            }

            if indicate && notify {
                let case_cccd_write = format_ident!("{}CccdWrite", name_pascal);

                self.code_event_enum.extend(quote_spanned!(ch.span=>
                    #case_cccd_write{indications: bool, notifications: bool},
                ));
                self.code_on_write.extend(quote_spanned!(ch.span=>
                if handle == self.#cccd_handle && !data.is_empty() {
                    match data[0] & 0x03 {
                        0x00 => return Some(#event_enum_name::#case_cccd_write{indications: false, notifications: false}),
                        0x01 => return Some(#event_enum_name::#case_cccd_write{indications: false, notifications: true}),
                        0x02 => return Some(#event_enum_name::#case_cccd_write{indications: true, notifications: false}),
                        0x03 => return Some(#event_enum_name::#case_cccd_write{indications: true, notifications: true}),
                        _ => {},
                    }
                }
            ));
            }
        }
    }
}
