//! Gatt Service Builder
//!
//! This module contains the ServiceBuilder struct which is used to construct a Gatt Service from a struct definition.
//! The struct definition is used to define the characteristics of the service, and the ServiceBuilder is used to
//! generate the code required to create the service.

use crate::characteristic::{Characteristic, CharacteristicArgs};
use crate::uuid::Uuid;
use darling::FromMeta;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote, quote_spanned};
use syn::meta::ParseNestedMeta;
use syn::parse::Result;
use syn::spanned::Spanned;
use syn::{Ident, LitStr};

#[derive(Debug, Default)]
pub(crate) struct ServiceArgs {
    pub uuid: Option<Uuid>,
}

impl ServiceArgs {
    pub fn parse(&mut self, meta: ParseNestedMeta) -> Result<()> {
        if meta.path.is_ident("uuid") {
            let uuid_string: LitStr = meta.value()?.parse()?;
            self.uuid = Some(Uuid::from_string(uuid_string.value().as_str())?);
            Ok(())
        } else {
            Err(meta.error("Unsupported service property, 'uuid' is the only supported property"))
        }
    }
}

pub(crate) struct ServiceBuilder {
    service_props: syn::ItemStruct,
    name: Ident,
    uuid: Uuid,
    code_impl: TokenStream2,
    code_build_chars: TokenStream2,
    code_struct_init: TokenStream2,
    code_fields: TokenStream2,
}

impl ServiceBuilder {
    pub fn new(props: syn::ItemStruct, uuid: Uuid) -> Self {
        let name = props.ident.clone();
        Self {
            name,
            uuid,
            service_props: props,
            code_impl: TokenStream2::new(),
            code_build_chars: TokenStream2::new(),
            code_struct_init: TokenStream2::new(),
            code_fields: TokenStream2::new(),
        }
    }

    pub fn build(self) -> TokenStream2 {
        let service_props = self.service_props;
        let visibility = service_props.vis.clone();
        let struct_name = self.name;
        let code_struct_init = self.code_struct_init;
        let code_impl = self.code_impl;
        let code_build_chars = self.code_build_chars;
        let fields = self.code_fields;
        let uuid = self.uuid;
        let result = quote! {
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
                    #code_build_chars

                    Self {
                        handle: service.build(),
                        #code_struct_init
                    }
                }
                #code_impl
            }
        };
        result
    }

    /// Construct instructions for adding a characteristic to the service, with static storage.
    fn construct_characteristic_static(
        &mut self,
        name: &str,
        span: Span,
        ty: &syn::Type,
        properties: &Vec<TokenStream2>,
        uuid: Option<Uuid>,
    ) {
        let name_screaming = format_ident!(
            "{}",
            inflector::cases::screamingsnakecase::to_screaming_snake_case(name)
        );
        let char_name = format_ident!("{}", name);
        self.code_build_chars.extend(quote_spanned! {span=>
            let #char_name = {
                static #name_screaming: static_cell::StaticCell<[u8; size_of::<#ty>()]> = static_cell::StaticCell::new();
                let store = #name_screaming.init([0; size_of::<#ty>()]);
                let builder = service.add_characteristic(#uuid, &[#(#properties),*], store);

                // TODO: Descriptors

                builder.build()
            };
        });

        self.code_struct_init.extend(quote_spanned!(span=>
            #char_name,
        ));
    }

    /// Consume the lists of fields and fields marked as characteristics and prepare the code to add them to the service
    /// by generating the macro blueprints for any methods, fields, and static storage required.
    pub fn add_characteristic_fields(
        mut self,
        mut fields: Vec<syn::Field>,
        characteristics: Vec<Characteristic>,
    ) -> Self {
        for ch in characteristics {
            let char_name = format_ident!("{}", ch.name);
            let _get_fn = format_ident!("{}_get", ch.name);
            let _set_fn = format_ident!("{}_set", ch.name);
            let _notify_fn = format_ident!("{}_notify", ch.name);
            let _indicate_fn = format_ident!("{}_indicate", ch.name);
            let _fn_vis = ch.vis.clone();

            let uuid = ch.args.uuid;
            let _notify = ch.args.notify;
            let _indicate = ch.args.indicate;

            let ty = &ch.ty;

            let properties = set_access_properties(&ch.args);

            // add fields for each characteristic value handle
            fields.push(syn::Field {
                ident: Some(char_name.clone()),
                ty: syn::Type::Verbatim(quote!(Characteristic)),
                attrs: Vec::new(),
                colon_token: Default::default(),
                vis: syn::Visibility::Inherited,
                mutability: syn::FieldMutability::None,
            });

            self.construct_characteristic_static(&ch.name, ch.span, ty, &properties, uuid);
        }
        for field in fields {
            let ident = field.ident.clone();
            let ty = field.ty.clone();
            self.code_fields.extend(quote_spanned! {field.span()=>
                #ident: #ty,
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
