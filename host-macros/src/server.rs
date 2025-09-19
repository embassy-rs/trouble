//! Gatt Server Builder
//!
//! This module is responsible for generating the Gatt Server struct and its implementation.
//! It should contain one or more Gatt Services, which are decorated with the `#[gatt_service(uuid = "...")]` attribute.

use darling::Error;
use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, quote_spanned};
use syn::meta::ParseNestedMeta;
use syn::spanned::Spanned;
use syn::{parse_quote, Expr, Result};

#[derive(Default)]
pub(crate) struct ServerArgs {
    mutex_type: Option<syn::Type>,
    packet_type: Option<syn::Type>,
    attribute_table_size: Option<Expr>,
    cccd_table_size: Option<Expr>,
    connections_max: Option<Expr>,
}

impl ServerArgs {
    pub fn parse(&mut self, meta: ParseNestedMeta) -> Result<()> {
        match meta
            .path
            .get_ident()
            .ok_or(Error::custom("no ident"))?
            .to_string()
            .as_str()
        {
            "mutex_type" => {
                let buffer = meta.value().map_err(|_| {
                    Error::custom(
                        "mutex_type must be followed by `= [type]`. e.g. mutex_type = NoopRawMutex".to_string(),
                    )
                })?;
                self.mutex_type = Some(buffer.parse()?);
            }
            "packet_type" => {
                let buffer = meta.value().map_err(|_| {
                    Error::custom(
                        "packet_type must be followed by `= [type]`. e.g. packet_type = MyPool".to_string(),
                    )
                })?;
                self.packet_type = Some(buffer.parse()?);
            }
            "attribute_table_size" => {
                let buffer = meta.value().map_err(|_| {
                    Error::custom(
                        "attribute_table_size must be followed by `= [size]`. e.g. attribute_table_size = 32"
                            .to_string(),
                    )
                })?;
                self.attribute_table_size = Some(buffer.parse()?);
            }
            "cccd_table_size" => {
                let buffer = meta.value().map_err(|_| {
                    Error::custom("cccd_table_size must be followed by `= [size]`. e.g. cccd_table_size = 4".to_string())
                })?;
                self.cccd_table_size = Some(buffer.parse()?);
            }
            "connections_max" => {
                let buffer = meta.value().map_err(|_| {
                    Error::custom("connections_max must be followed by `= [size]`. e.g. connections_max = 1".to_string())
                })?;
                self.connections_max = Some(buffer.parse()?);
            }
            other => return Err(meta.error(format!(
                "Unsupported server property: '{other}'.\nSupported properties are: mutex_type, packet_type, attribute_table_size, cccd_table_size, connections_max"
            ))),
        }
        Ok(())
    }
}

pub(crate) struct ServerBuilder {
    properties: syn::ItemStruct,
    arguments: ServerArgs,
}

impl ServerBuilder {
    pub fn new(properties: syn::ItemStruct, arguments: ServerArgs) -> Self {
        Self { properties, arguments }
    }

    /// Construct the macro blueprint for the server struct.
    pub fn build(self) -> TokenStream2 {
        let name = &self.properties.ident;
        let visibility = &self.properties.vis;

        let mutex_type = self.arguments.mutex_type.unwrap_or(syn::Type::Verbatim(quote!(
            embassy_sync::blocking_mutex::raw::NoopRawMutex
        )));

        let packet_type = self
            .arguments
            .packet_type
            .unwrap_or(syn::Type::Verbatim(quote!(trouble_host::prelude::DefaultPacketPool)));

        let mut code_service_definition = TokenStream2::new();
        let mut code_service_init = TokenStream2::new();
        let mut code_server_populate = TokenStream2::new();
        let mut code_attribute_summation = TokenStream2::new();
        let mut code_cccd_summation = TokenStream2::new();
        for service in &self.properties.fields {
            let vis = &service.vis;
            let service_span = service.span();
            let service_name = service.ident.as_ref().expect("All fields should have names");
            let service_type = &service.ty;

            code_service_definition.extend(quote_spanned! {service_span=>
                #vis #service_name: #service_type,
            });

            code_service_init.extend(quote_spanned! {service_span=>
                let #service_name = #service_type::new(&mut table);
            });

            code_server_populate.extend(quote_spanned! {service_span=>
                #service_name,
            });

            code_attribute_summation.extend(quote_spanned! {service_span=>
               + #service_type::ATTRIBUTE_COUNT
            });

            code_cccd_summation.extend(quote_spanned! {service_span=>
               + #service_type::CCCD_COUNT
            })
        }

        let attribute_table_size = if let Some(value) = self.arguments.attribute_table_size {
            value
        } else {
            parse_quote!(trouble_host::gap::GAP_SERVICE_ATTRIBUTE_COUNT #code_attribute_summation)
        };

        let cccd_table_size = if let Some(value) = self.arguments.cccd_table_size {
            value
        } else {
            parse_quote!(0 #code_cccd_summation)
        };

        let connections_max = if let Some(value) = self.arguments.connections_max {
            value
        } else {
            parse_quote!(1)
        };

        quote! {
            const _ATTRIBUTE_TABLE_SIZE: usize = #attribute_table_size;
            // This pattern causes the assertion to happen at compile time
            const _: () = {
                core::assert!(_ATTRIBUTE_TABLE_SIZE >= trouble_host::gap::GAP_SERVICE_ATTRIBUTE_COUNT #code_attribute_summation, "Specified attribute table size is insufficient. Please increase attribute_table_size or remove the argument entirely to allow automatic sizing of the attribute table.");
            };
            const _CCCD_TABLE_SIZE: usize = #cccd_table_size;
            const _CONNECTIONS_MAX: usize = #connections_max;

            #visibility struct #name<'values>
            {
                pub server: trouble_host::prelude::AttributeServer<'values, #mutex_type, #packet_type, _ATTRIBUTE_TABLE_SIZE, _CCCD_TABLE_SIZE, _CONNECTIONS_MAX>,
                #code_service_definition
            }

            impl<'values> #name<'values>
            {
                /// Create a new Gatt Server instance.
                ///
                /// Requires you to add your own GAP Service.  Use `new_default(name)` or `new_with_config(name, gap_config)` if you want to add a GAP Service.
                #visibility fn new(mut table: trouble_host::attribute::AttributeTable<'values, #mutex_type, _ATTRIBUTE_TABLE_SIZE>) -> Self {

                    #code_service_init

                    Self {
                        server: trouble_host::prelude::AttributeServer::new(table),
                        #code_server_populate
                    }
                }
                /// Create a new Gatt Server instance.
                ///
                /// This function will add a Generic GAP Service with the given name.
                /// The maximum length which the name can be is 22 bytes (limited by the size of the advertising packet).
                /// If a name longer than this is passed, Err() is returned.
                #visibility fn new_default(name: &'values str) -> Result<Self, &'static str> {
                    let mut table: trouble_host::attribute::AttributeTable<'_, #mutex_type, _ATTRIBUTE_TABLE_SIZE> = trouble_host::attribute::AttributeTable::new();

                    trouble_host::gap::GapConfig::default(name).build(&mut table)?;

                    #code_service_init

                    Ok(Self {
                        server: trouble_host::prelude::AttributeServer::new(table),
                        #code_server_populate
                    })
                }

                /// Create a new Gatt Server instance.
                ///
                /// This function will add a GAP Service.
                /// The maximum length which the device name can be is 22 bytes (limited by the size of the advertising packet).
                /// If a name longer than this is passed, Err() is returned.
                #visibility fn new_with_config(gap: trouble_host::gap::GapConfig<'values>) -> Result<Self, &'static str> {
                    let mut table: trouble_host::attribute::AttributeTable<'_, #mutex_type, _ATTRIBUTE_TABLE_SIZE> = trouble_host::attribute::AttributeTable::new();

                    gap.build(&mut table)?;

                    #code_service_init

                    Ok(Self {
                        server: trouble_host::prelude::AttributeServer::new(table),
                        #code_server_populate
                    })
                }

                #visibility fn get<T: trouble_host::attribute::AttributeHandle<Value = V>, V: FromGatt>(&self, attribute_handle: &T) -> Result<T::Value, trouble_host::Error> {
                    self.server.table().get(attribute_handle)
                }

                #visibility fn set<T: trouble_host::attribute::AttributeHandle>(&self, attribute_handle: &T, input: &T::Value) -> Result<(), trouble_host::Error> {
                    self.server.table().set(attribute_handle, input)
                }

                #visibility fn get_cccd_table(&self, connection: &trouble_host::connection::Connection<'_, #packet_type>) -> Option<trouble_host::prelude::CccdTable<_CCCD_TABLE_SIZE>> {
                    self.server.get_cccd_table(connection)
                }

                #visibility fn set_cccd_table(&self, connection: &trouble_host::connection::Connection<'_, #packet_type>, table: trouble_host::prelude::CccdTable<_CCCD_TABLE_SIZE>) {
                    self.server.set_cccd_table(connection, table);
                }
            }

            impl<'values> core::ops::Deref for #name<'values>
            {
                type Target = trouble_host::prelude::AttributeServer<'values, #mutex_type, #packet_type, _ATTRIBUTE_TABLE_SIZE, _CCCD_TABLE_SIZE, _CONNECTIONS_MAX>;

                fn deref(&self) -> &Self::Target {
                    &self.server
                }
            }

        }
    }
}
