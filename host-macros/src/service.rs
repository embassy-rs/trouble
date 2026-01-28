//! Gatt Service Builder
//!
//! This module contains the ServiceBuilder struct which is used to construct a Gatt Service from a struct definition.
//! The struct definition is used to define the characteristics of the service, and the ServiceBuilder is used to
//! generate the code required to create the service.

use convert_case::{Case, Casing};
use darling::Error;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote, quote_spanned, ToTokens};
use syn::parse::Result;
use syn::spanned::Spanned;
use syn::{Meta, Token};

use crate::characteristic::{AccessArgs, Characteristic};
use crate::uuid::parse_arg_uuid;

#[derive(Debug)]
pub(crate) struct ServiceArgs {
    pub uuid: TokenStream2,
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
    cccd_count: usize,
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
            cccd_count: 0,
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
        if access.notify || access.indicate {
            self.cccd_count += 1;
            self.attribute_count += 3;
        } else {
            self.attribute_count += 2;
        }
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
        let cccd_count = self.cccd_count;
        quote! {
            #visibility struct #struct_name {
                #fields
                handle: u16,
            }

            #[allow(unused)]
            impl #struct_name {
                #visibility const ATTRIBUTE_COUNT: usize = #attribute_count;
                #visibility const CCCD_COUNT: usize = #cccd_count;

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

                #visibility fn handle_range(&self) -> core::ops::Range<u16> {
                    self.handle..(self.handle + Self::ATTRIBUTE_COUNT as u16)
                }

                #code_impl
            }
        }
    }

    /// Construct instructions for adding a characteristic to the service, with static storage.
    fn construct_characteristic_static(&mut self, characteristic: Characteristic) {
        let (code_descriptors, named_descriptors) = self.build_descriptors(&characteristic);
        let name_screaming = format_ident!("{}_STORE", characteristic.name.as_str().to_case(Case::Constant));
        let char_name = format_ident!("{}", characteristic.name);
        let ty = characteristic.ty;
        let access = &characteristic.args.access;
        let properties = set_access_properties(access);
        let uuid = characteristic.args.uuid;
        let default_value = match characteristic.args.default_value {
            Some(val) => quote!(#val),                                       // if set by user
            None => quote_spanned!(characteristic.span => <#ty>::default()), // or default otherwise
        };

        let cfg_attr = characteristic.args.cfg.as_ref().into_iter();
        self.code_build_chars.extend(quote_spanned! {characteristic.span=>
            #(#cfg_attr)*
            let (#char_name, #(#named_descriptors),*) = {
                #[allow(clippy::absurd_extreme_comparisons)]
                let mut builder = if <#ty as trouble_host::types::gatt_traits::AsGatt>::MAX_SIZE <= 8 {
                    service.add_characteristic_small(#uuid, &[#(#properties),*], #default_value)
                } else {
                    static #name_screaming: static_cell::StaticCell<[u8; <#ty as trouble_host::types::gatt_traits::AsGatt>::MAX_SIZE]> = static_cell::StaticCell::new();
                    let store = #name_screaming.init([0; <#ty as trouble_host::types::gatt_traits::AsGatt>::MAX_SIZE]);
                    service
                        .add_characteristic(#uuid, &[#(#properties),*], #default_value, store)
                };
                #code_descriptors

                (builder.build(), #(#named_descriptors),*)
            };
        });

        let cfg_attr = characteristic.args.cfg.as_ref().into_iter();
        self.code_struct_init.extend(quote_spanned!(characteristic.span=>
            #(#cfg_attr)*
            #char_name,
        ));
    }

    /// Construct instructions for adding a read-only characteristic to the service.
    fn construct_characteristic_ro(&mut self, characteristic: Characteristic) {
        let (code_descriptors, named_descriptors) = self.build_descriptors(&characteristic);
        let char_name = format_ident!("{}", characteristic.name);
        let ty = characteristic.ty;
        let uuid = characteristic.args.uuid;
        let default_value = match characteristic.args.default_value {
            Some(val) => quote!(#val),                                       // if set by user
            None => quote_spanned!(characteristic.span => <#ty>::default()), // or default otherwise
        };

        self.code_build_chars.extend(quote_spanned! {characteristic.span=>
            let (#char_name, #(#named_descriptors),*) = {
                let mut builder = service.add_characteristic_ro(#uuid, #default_value);
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
        let mut attrs: Vec<Vec<syn::Attribute>> = Vec::new();
        for field in &fields {
            let ident = field.ident.as_ref().expect("All fields should have names");
            let ty = &field.ty;
            let cfg_attr = field.attrs.iter().find(|attr| attr.path().is_ident("cfg")).into_iter();
            self.code_struct_init.extend(quote_spanned! {field.span() =>
                #(#cfg_attr)*
                #ident: #ty::default(),
            });
            attrs.push(field.attrs.clone());
        }
        // Process characteristic fields
        for ch in characteristics {
            let char_name = format_ident!("{}", ch.name);

            let mut ty = &ch.ty;
            let mut ro = false;
            if let syn::Type::Reference(type_ref) = ty {
                if ch.args.access.is_read_only()
                    && type_ref.mutability.is_none()
                    && type_ref.lifetime.as_ref().is_some_and(|lt| lt.ident == "static")
                {
                    ty = &type_ref.elem;
                    ro = true;
                }
            }

            // add fields for each characteristic value handle
            fields.push(syn::Field {
                ident: Some(char_name.clone()),
                ty: syn::Type::Verbatim(quote!(trouble_host::attribute::Characteristic<#ty>)),
                attrs: Vec::new(),
                colon_token: Default::default(),
                vis: ch.vis.clone(),
                mutability: syn::FieldMutability::None,
            });

            let mut ch_attrs = ch.args.doc_string.clone();
            if let Some(cfg) = &ch.args.cfg {
                ch_attrs.push(cfg.clone());
            }
            attrs.push(ch_attrs);

            self.increment_attributes(&ch.args.access);

            if ro {
                self.construct_characteristic_ro(ch);
            } else {
                self.construct_characteristic_static(ch);
            }
        }
        assert_eq!(fields.len(), attrs.len());
        // Processing common to all fields
        for (field, attrs) in fields.iter().zip(attrs) {
            let ident = field.ident.clone();
            let ty = field.ty.clone();
            let vis = &field.vis;
            self.code_fields.extend(quote_spanned! {field.span()=>
                #(#attrs)*
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
                        format_ident!("DESC_{index}_{}_STORE", characteristic.name.as_str().to_case(Case::Constant));
                    let identifier = args.name.as_ref().map(|name| format_ident!("{}_{}_descriptor", characteristic.name.as_str(), name.value()));
                    let access = &args.access;
                    let properties = set_access_properties(access);
                    let uuid = &args.uuid;
                    let default_value = match &args.default_value {
                        Some(val) => quote!(#val), // if set by user
                        None => quote!(""),
                    };

                    let mut ty = args.ty.as_ref();
                    let mut ro = false;
                    if let Some(syn::Type::Reference(type_ref)) = args.ty.as_ref() {
                        if args.access.is_read_only()
                            && type_ref.mutability.is_none()
                            && type_ref.lifetime.as_ref().is_some_and(|lt| lt.ident == "static")
                        {
                            ty = Some(&type_ref.elem);
                            ro = true;
                        }
                    }

                    let mut identifier_assignment = None;
                    if let Some(name) = &identifier {
                        let ty = ty.unwrap(); // The type is required for named descriptors
                        let cfg_attr = characteristic.args.cfg.as_ref().into_iter();
                        self.code_fields.extend(quote_spanned!{ identifier.span() =>
                            #(#cfg_attr)*
                            #name: trouble_host::attribute::Descriptor<#ty>,
                        });
                        let cfg_attr = characteristic.args.cfg.as_ref().into_iter();
                        self.code_struct_init.extend(quote_spanned! { identifier.span() =>
                            #(#cfg_attr)*
                            #name,
                        });
                        named_descriptors.push(name.to_token_stream());
                        identifier_assignment = Some(quote! { let #name = });
                    };

                    self.attribute_count += 1; // descriptors should always only be one attribute.

                    if ro {
                        quote_spanned! {characteristic.span=>
                            #identifier_assignment builder.add_descriptor_ro(#uuid, #default_value);
                        }
                    } else {
                        let capacity = match ty {
                            Some(ty) => quote!(<#ty as trouble_host::types::gatt_traits::AsGatt>::MAX_SIZE),
                            None => quote!(#default_value.len() as usize),
                        };
                        let capacity_screaming =
                            format_ident!("DESC_{index}_{}_CAPACITY", characteristic.name.as_str().to_case(Case::Constant));

                        quote_spanned! {characteristic.span=>
                            #identifier_assignment {
                                const #capacity_screaming: usize = #capacity;
                                #[allow(clippy::absurd_extreme_comparisons)]
                                if #capacity_screaming <= 8 {
                                    builder.add_descriptor_small(
                                        #uuid,
                                        &[#(#properties),*],
                                        #default_value,
                                    )
                                } else {
                                    static #name_screaming: static_cell::StaticCell<[u8; #capacity_screaming]> = static_cell::StaticCell::new();
                                    let store = #name_screaming.init([0; #capacity]);
                                    builder.add_descriptor(
                                        #uuid,
                                        &[#(#properties),*],
                                        #default_value,
                                        store,
                                    )
                                }
                            };
                        }
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
