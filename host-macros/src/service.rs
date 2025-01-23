//! Gatt Service Builder
//!
//! This module contains the ServiceBuilder struct which is used to construct a Gatt Service from a struct definition.
//! The struct definition is used to define the characteristics of the service, and the ServiceBuilder is used to
//! generate the code required to create the service.

use darling::{Error, FromMeta};
use inflector::cases::screamingsnakecase::to_screaming_snake_case;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote, quote_spanned, ToTokens};
use syn::parse::Result;
use syn::spanned::Spanned;
use syn::{Expr, Meta, Token};

use crate::characteristic::{AccessArgs, Characteristic};
use crate::uuid::Uuid;

#[derive(Debug)]
pub(crate) struct ServiceArgs {
    pub uuid: TokenStream2,
}

/// Parse the UUID argument of the service attribute.
///
/// The UUID can be specified as a string literal, an integer literal, or an expression that impl Into<Uuid>.
fn parse_arg_uuid(value: &Expr) -> Result<TokenStream2> {
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

impl syn::parse::Parse for ServiceArgs {
    fn parse(input: syn::parse::ParseStream) -> Result<Self> {
        let mut uuid: Option<_> = None;

        while !input.is_empty() {
            let meta = input.parse()?;

            match &meta {
                Meta::NameValue(name_value) => {
                    match name_value
                        .path
                        .get_ident()
                        .ok_or(Error::custom("Argument name is missing").with_span(&name_value.span()))?
                        .to_string()
                        .as_str()
                    {
                        "uuid" => {
                            if uuid.is_some() {
                                return Err(Error::custom("UUID cannot be specified more than once")
                                    .with_span(&name_value.span())
                                    .into());
                            }
                            uuid = Some(parse_arg_uuid(&name_value.value)?);
                        }
                        other => {
                            return Err(Error::unknown_field(&format!(
                                "Unsupported service property: '{other}'.\nSupported properties are: uuid"
                            ))
                            .with_span(&name_value.span())
                            .into())
                        }
                    }
                }
                _ => return Err(Error::custom("Unexpected argument").with_span(&meta.span()).into()),
            }
            let _ = input.parse::<Token![,]>();
        }

        Ok(Self {
            uuid: uuid.ok_or(Error::custom(
                "Service must have a UUID (i.e. `#[gatt_service(uuid = '1234')]` or `#[gatt_service(uuid = service::BATTERY)]`)",
            ))?,
        })
    }
}

pub(crate) struct ServiceBuilder {
    properties: syn::ItemStruct,
    args: ServiceArgs,
    attribute_count: usize,
    code_impl: TokenStream2,
    code_build_chars: TokenStream2,
    code_struct_init: TokenStream2,
    code_fields: TokenStream2,
}

impl ServiceBuilder {
    pub fn new(properties: syn::ItemStruct, args: ServiceArgs) -> Self {
        Self {
            properties,
            args,
            attribute_count: 1, // Service counts as an attribute
            code_struct_init: TokenStream2::new(),
            code_impl: TokenStream2::new(),
            code_fields: TokenStream2::new(),
            code_build_chars: TokenStream2::new(),
        }
    }
    /// Increment the number of access arguments required for this characteristic
    ///
    /// At least two attributes will be added to the attribute table for each characteristic:
    /// - The characteristic declaration
    /// - The characteristic's value declaration
    ///
    /// If the characteristic has either the notify or indicate property,
    /// a Client Characteristic Configuration Descriptor (CCCD) declaration will also be added.
    fn increment_attributes(&mut self, access: &AccessArgs) -> usize {
        self.attribute_count += if access.notify || access.indicate { 3 } else { 2 };
        self.attribute_count
    }
    /// Construct the macro blueprint for the service struct.
    pub fn build(self) -> TokenStream2 {
        let properties = self.properties;
        let visibility = &properties.vis;
        let struct_name = &properties.ident;
        let code_struct_init = self.code_struct_init;
        let code_impl = self.code_impl;
        let fields = self.code_fields;
        let code_build_chars = self.code_build_chars;
        let uuid = self.args.uuid;
        let attribute_count = self.attribute_count;
        quote! {
            #visibility struct #struct_name {
                #fields
                handle: u16,
            }

            #[allow(unused)]
            impl #struct_name {
                #visibility const ATTRIBUTE_COUNT: usize = #attribute_count;

                #visibility fn new<M, const MAX_ATTRIBUTES: usize>(table: &mut trouble_host::attribute::AttributeTable<'_, M, MAX_ATTRIBUTES>) -> Self
                where
                    M: embassy_sync::blocking_mutex::raw::RawMutex,
                {
                    let mut service = table.add_service(trouble_host::attribute::Service::new(#uuid));
                    #code_build_chars

                    Self {
                        handle: service.build(),
                        #code_struct_init
                    }
                }
                #code_impl
            }
        }
    }

    /// Construct instructions for adding a characteristic to the service, with static storage.
    fn construct_characteristic_static(&mut self, characteristic: Characteristic) {
        let (code_descriptors, named_descriptors) = self.build_descriptors(&characteristic);
        let name_screaming = format_ident!("{}", to_screaming_snake_case(characteristic.name.as_str()));
        let char_name = format_ident!("{}", characteristic.name);
        let ty = characteristic.ty;
        let access = &characteristic.args.access;
        let properties = set_access_properties(access);
        let uuid = characteristic.args.uuid;
        let default_value = match characteristic.args.default_value {
            Some(val) => quote!(#val),        // if set by user
            None => quote!(<#ty>::default()), // or default otherwise
        };

        self.code_build_chars.extend(quote_spanned! {characteristic.span=>
            let (#char_name, #(#named_descriptors),*) = {
                static #name_screaming: static_cell::StaticCell<[u8; <#ty as trouble_host::types::gatt_traits::ToGatt>::MAX_SIZE]> = static_cell::StaticCell::new();
                let mut val = <#ty>::default(); // constrain the type of the value here
                val = #default_value; // update the temporary value with our new default
                let store = #name_screaming.init([0; <#ty as trouble_host::types::gatt_traits::ToGatt>::MAX_SIZE]);
                let mut builder = service
                    .add_characteristic(#uuid, &[#(#properties),*], val, store);
                #code_descriptors

                (builder.build(), #(#named_descriptors),*)
            };
        });

        self.code_struct_init.extend(quote_spanned!(characteristic.span=>
            #char_name,
        ));
    }

    /// Consume the lists of fields and fields marked as characteristics and prepare the code to add them to the service
    /// by generating the macro blueprints for any methods, fields, and static storage required.
    pub fn process_characteristics_and_fields(
        mut self,
        mut fields: Vec<syn::Field>,
        characteristics: Vec<Characteristic>,
    ) -> Self {
        // Processing specific to non-characteristic fields
        let mut doc_strings: Vec<String> = Vec::new();
        for field in &fields {
            let ident = field.ident.as_ref().expect("All fields should have names");
            let ty = &field.ty;
            let vis = &field.vis;
            self.code_struct_init.extend(quote_spanned! {field.span() =>
                #vis #ident: #ty::default(),
            });
            doc_strings.push(String::new()); // not supporting docstrings here yet
        }
        // Process characteristic fields
        for ch in characteristics {
            let char_name = format_ident!("{}", ch.name);
            let ty = &ch.ty;
            // add fields for each characteristic value handle
            fields.push(syn::Field {
                ident: Some(char_name.clone()),
                ty: syn::Type::Verbatim(quote!(trouble_host::attribute::Characteristic<#ty>)),
                attrs: Vec::new(),
                colon_token: Default::default(),
                vis: ch.vis.clone(),
                mutability: syn::FieldMutability::None,
            });
            doc_strings.push(ch.args.doc_string.to_owned());

            self.increment_attributes(&ch.args.access);

            self.construct_characteristic_static(ch);
        }
        assert_eq!(fields.len(), doc_strings.len());
        // Processing common to all fields
        for (field, doc_string) in fields.iter().zip(doc_strings) {
            let docs: TokenStream2 = doc_string
                .lines()
                .map(|line| {
                    let span = field.span();
                    quote_spanned!(span=>
                        #[doc = #line]
                    )
                })
                .collect();
            let ident = field.ident.clone();
            let ty = field.ty.clone();
            let vis = &field.vis;
            self.code_fields.extend(quote_spanned! {field.span()=>
                #docs
                #vis #ident: #ty,
            })
        }
        self
    }

    /// Generate token stream for any descriptors tagged against this characteristic.
    fn build_descriptors(&mut self, characteristic: &Characteristic) -> (TokenStream2, Vec<TokenStream2>) {
        let mut named_descriptors = Vec::<TokenStream2>::new();
        (characteristic
                .args
                .descriptors
                .iter()
                .enumerate()
                .map(|(index, args)| {
                    let name_screaming =
                        format_ident!("DESC_{index}_{}", to_screaming_snake_case(characteristic.name.as_str()));
                    let identifier = args.name.as_ref().map(|name| format_ident!("{}_{}_descriptor", characteristic.name.as_str(), name.value()));
                    let access = &args.access;
                    let properties = set_access_properties(access);
                    let uuid = &args.uuid;
                    let default_value = match &args.default_value {
                        Some(val) => quote!(#val), // if set by user
                        None => quote!(""),
                    };
                    let capacity = match &args.capacity {
                        Some(cap) => quote!(#cap),
                        None => quote!(#default_value.len() as usize)
                    };

                    let mut identifier_assignment = None;
                    if let Some(name) = &identifier {
                        self.code_fields.extend(quote_spanned!{ identifier.span() =>
                            #name: trouble_host::attribute::Descriptor<&'static [u8]>,
                        });
                        self.code_struct_init.extend(quote_spanned! { identifier.span() =>
                            #name,
                        });
                        named_descriptors.push(name.to_token_stream());
                        identifier_assignment = Some(quote! { let #name = });
                    };

                    self.attribute_count += 1; // descriptors should always only be one attribute.

                    quote_spanned! {characteristic.span=>
                        #identifier_assignment {
                            let value = #default_value;
                            const CAPACITY: usize = if (#capacity) < 16 { 16 } else { #capacity }; // minimum capacity is 16 bytes
                            static #name_screaming: static_cell::StaticCell<[u8; CAPACITY]> = static_cell::StaticCell::new();
                            let store = #name_screaming.init([0; CAPACITY]);
                            let value = trouble_host::types::gatt_traits::ToGatt::to_gatt(&value);
                            store[..value.len()].copy_from_slice(value);
                            builder.add_descriptor::<&[u8], _>(
                                #uuid,
                                &[#(#properties),*],
                                store,
                            )
                        };
                    }
                })
                .collect(),
            named_descriptors)
    }
}

fn parse_property_into_list(property: bool, variant: TokenStream2, properties: &mut Vec<TokenStream2>) {
    if property {
        properties.push(variant);
    }
}

/// Parse the properties of a characteristic and return a list of properties
fn set_access_properties(args: &AccessArgs) -> Vec<TokenStream2> {
    let mut properties = Vec::new();
    parse_property_into_list(
        args.read,
        quote! {trouble_host::attribute::CharacteristicProp::Read},
        &mut properties,
    );
    parse_property_into_list(
        args.write,
        quote! {trouble_host::attribute::CharacteristicProp::Write},
        &mut properties,
    );
    parse_property_into_list(
        args.write_without_response,
        quote! {trouble_host::attribute::CharacteristicProp::WriteWithoutResponse},
        &mut properties,
    );
    parse_property_into_list(
        args.notify,
        quote! {trouble_host::attribute::CharacteristicProp::Notify},
        &mut properties,
    );
    parse_property_into_list(
        args.indicate,
        quote! {trouble_host::attribute::CharacteristicProp::Indicate},
        &mut properties,
    );
    properties
}
