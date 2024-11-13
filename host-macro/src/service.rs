//! Gatt Service Builder
//!
//! This module contains the ServiceBuilder struct which is used to construct a Gatt Service from a struct definition.
//! The struct definition is used to define the characteristics of the service, and the ServiceBuilder is used to
//! generate the code required to create the service.

use crate::characteristic::{Characteristic, CharacteristicArgs};
use crate::uuid::Uuid;
use darling::{Error, FromMeta};
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote, quote_spanned};
use syn::parse::Result;
use syn::spanned::Spanned;
use syn::{Meta, Token};

#[derive(Debug)]
pub(crate) struct ServiceArgs {
    pub uuid: Uuid,
    pub on_read: Option<syn::Ident>,
}

impl syn::parse::Parse for ServiceArgs {
    fn parse(input: syn::parse::ParseStream) -> Result<Self> {
        let mut uuid = None;
        let mut on_read = None;

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
                        "uuid" => uuid = Some(Uuid::from_meta(&meta)?),
                        "on_read" => on_read = Some(syn::Ident::from_meta(&meta)?),
                        other => {
                            return Err(Error::unknown_field(&format!(
                                "Unsupported service property: '{other}'.\nSupported properties are uuid, on_read"
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
                "Service must have a UUID (i.e. `#[gatt_service(uuid = '1234')]`)",
            ))?,
            on_read,
        })
    }
}

pub(crate) struct ServiceBuilder {
    properties: syn::ItemStruct,
    args: ServiceArgs,
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
            code_struct_init: TokenStream2::new(),
            code_impl: TokenStream2::new(),
            code_fields: TokenStream2::new(),
            code_build_chars: TokenStream2::new(),
        }
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
        let read_callback = self
            .args
            .on_read
            .map(|callback| quote!(service.set_read_callback(#callback);));

        quote! {
            #visibility struct #struct_name {
                handle: AttributeHandle,
                #fields
            }

            #[allow(unused)]
            impl #struct_name {
                #visibility fn new<M, const MAX_ATTRIBUTES: usize>(table: &mut AttributeTable<'_, M, MAX_ATTRIBUTES>) -> Self
                where
                    M: embassy_sync::blocking_mutex::raw::RawMutex,
                {
                    let mut service = table.add_service(Service::new(#uuid));
                    #read_callback
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
        let name_screaming = format_ident!(
            "{}",
            inflector::cases::screamingsnakecase::to_screaming_snake_case(characteristic.name.as_str())
        );
        let char_name = format_ident!("{}", characteristic.name);
        let ty = characteristic.ty;
        let properties = set_access_properties(&characteristic.args);
        let uuid = characteristic.args.uuid;
        let read_callback = characteristic
            .args
            .on_read
            .as_ref()
            .map(|callback| quote!(builder.set_read_callback(#callback);));
        let write_callback = characteristic
            .args
            .on_write
            .as_ref()
            .map(|callback| quote!(builder.set_write_callback(#callback);));

        self.code_build_chars.extend(quote_spanned! {characteristic.span=>
            let #char_name = {
                static #name_screaming: static_cell::StaticCell<[u8; size_of::<#ty>()]> = static_cell::StaticCell::new();
                let store = #name_screaming.init([0; size_of::<#ty>()]);
                let mut builder = service.add_characteristic(#uuid, &[#(#properties),*], store);
                #read_callback
                #write_callback

                // TODO: Descriptors

                builder.build()
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
        for field in &fields {
            let ident = field.ident.as_ref().expect("All fields should have names");
            let ty = &field.ty;
            self.code_struct_init.extend(quote_spanned! {field.span() =>
                #ident: #ty::default(),
            })
        }

        // Process characteristic fields
        for ch in characteristics {
            let char_name = format_ident!("{}", ch.name);
            let ty = &ch.ty;

            // add fields for each characteristic value handle
            fields.push(syn::Field {
                ident: Some(char_name.clone()),
                ty: syn::Type::Verbatim(quote!(Characteristic<#ty>)),
                attrs: Vec::new(),
                colon_token: Default::default(),
                vis: ch.vis.clone(),
                mutability: syn::FieldMutability::None,
            });

            self.construct_characteristic_static(ch);
        }

        // Processing common to all fields
        for field in fields {
            let ident = field.ident.clone();
            let ty = field.ty.clone();
            let vis = &field.vis;
            self.code_fields.extend(quote_spanned! {field.span()=>
                #vis #ident: #ty,
            })
        }
        self
    }
}

fn parse_property_into_list(property: bool, variant: TokenStream2, properties: &mut Vec<TokenStream2>) {
    if property {
        properties.push(variant);
    }
}

/// Parse the properties of a characteristic and return a list of properties
fn set_access_properties(args: &CharacteristicArgs) -> Vec<TokenStream2> {
    let mut properties = Vec::new();
    parse_property_into_list(args.read, quote! {CharacteristicProp::Read}, &mut properties);
    parse_property_into_list(args.write, quote! {CharacteristicProp::Write}, &mut properties);
    parse_property_into_list(
        args.write_without_response,
        quote! {CharacteristicProp::WriteWithoutResponse},
        &mut properties,
    );
    parse_property_into_list(args.notify, quote! {CharacteristicProp::Notify}, &mut properties);
    parse_property_into_list(args.indicate, quote! {CharacteristicProp::Indicate}, &mut properties);
    properties
}
