//! Gatt Server Builder
//!
//! This module is responsible for generating the Gatt Server struct and its implementation.
//! It should contain one or more Gatt Services, which are decorated with the `#[gatt_service(uuid = "...")]` attribute.

use darling::Error;
use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, quote_spanned};
use syn::{meta::ParseNestedMeta, spanned::Spanned, LitInt, Result};

/// Default size for the memory block storing attribute data in bytes
const DEFAULT_ATTRIBUTE_DATA_SIZE: usize = 32;
/// MTU for a legacy BLE packet
const LEGACY_BLE_MTU: usize = 27;

#[derive(Default)]
pub(crate) struct ServerArgs {
    mutex_type: Option<syn::Type>,
    attribute_data_size: Option<usize>,
    mtu: Option<usize>,
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
                let buffer = meta.value().map_err(|_| Error::custom("mutex_type must be followed by `= [type]`. e.g. mutex_type = NoopRawMutex".to_string()))?;
                self.mutex_type = Some(buffer.parse()?);
            }
            "attribute_data_size" => {
                let buffer = meta.value().map_err(|_| Error::custom("attribute_data_size msut be followed by `= [size]`. e.g. attribute_data_size = 32".to_string()))?;
                let value: LitInt = buffer.parse()?;
                self.attribute_data_size = Some(value.base10_parse()?);
            }
            "mtu" => {
                let buffer = meta.value().map_err(|_| Error::custom("mtu must be followed by `= [size]`. e.g. mtu = 27".to_string()))?;
                let value: LitInt = buffer.parse()?;
                self.mtu = Some(value.base10_parse()?);
            }
            other => return Err(meta.error(format!("Unsupported server property: '{other}'.\nSupported properties are: mutex_type, attribute_data_size, mtu"))),
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
        let attribute_data_size = self
            .arguments
            .attribute_data_size
            .unwrap_or(DEFAULT_ATTRIBUTE_DATA_SIZE);
        let mtu = self.arguments.mtu.unwrap_or(LEGACY_BLE_MTU);

        let mut code_service_definition = TokenStream2::new();
        let mut code_service_init = TokenStream2::new();
        let mut code_server_populate = TokenStream2::new();
        for service in &self.properties.fields {
            let vis = &service.vis;
            let service_span = service.span();
            let service_name = service.ident.as_ref().expect("All fields should have names");
            let service_type = &service.ty;

            code_service_definition.extend(quote_spanned! {service_span=>
                #vis #service_name: #service_type,
            });

            code_service_init.extend(quote_spanned! {service_span=>
                let #service_name = #service_type::new(table);
            });

            code_server_populate.extend(quote_spanned! {service_span=>
                #service_name,
            });
        }

        quote! {
            #visibility struct #name<'reference, C: Controller>
            {
                server: GattServer<'reference, 'static, C, #mutex_type, #attribute_data_size, #mtu>,
                #code_service_definition
            }

            impl<'reference, C: Controller> #name<'reference, C>
            {
                /// Create a new Gatt Server (BLE Peripheral) instance.
                ///
                /// Requires you to add your own GAP Service.  Use `new_default(name)` or `new_with_config(name, gap_config)` if you want to add a GAP Service.
                #visibility fn new(stack: Stack<'reference, C>, table: &'reference mut AttributeTable<'static, #mutex_type, #attribute_data_size>) -> Self {

                    #code_service_init

                    Self {
                        server: GattServer::new(stack, table),
                        #code_server_populate
                    }
                }
                /// Create a new Gatt Server (BLE Peripheral) instance.
                ///
                /// This function will add a Generic GAP Service with the given name.
                #visibility fn new_default(stack: Stack<'reference, C>, name: &'static str) -> Self {
                    static TABLE: static_cell::StaticCell<AttributeTable<'static, #mutex_type, #attribute_data_size>> = static_cell::StaticCell::new();
                    let table = TABLE.init(AttributeTable::new());

                    GapConfig::default(name).build(table);

                    #code_service_init

                    Self {
                        server: GattServer::new(stack, table),
                        #code_server_populate
                    }
                }

                /// Create a new Gatt Server (BLE Peripheral) instance.
                ///
                /// This function will add a GAP Service.
                #visibility fn new_with_config(stack: Stack<'reference, C>, gap: GapConfig) -> Self {
                    static TABLE: static_cell::StaticCell<AttributeTable<'static, #mutex_type, #attribute_data_size>> = static_cell::StaticCell::new();
                    let table = TABLE.init(AttributeTable::new());

                    gap.build(table);

                    #code_service_init

                    Self {
                        server: GattServer::new(stack, table),
                        #code_server_populate
                    }
                }

                #visibility fn get<F: FnMut(&[u8]) -> T, T>(&self, handle: Characteristic, mut f: F) -> Result<T, Error> {
                    self.server.server().table().get(handle, f)
                }

                #visibility fn set(&self, handle: Characteristic, input: &[u8]) -> Result<(), Error> {
                    self.server.server().table().set(handle, input)
                }
            }

            impl<'reference, C: Controller> core::ops::Deref for #name<'reference, C>
            {
                type Target = GattServer<'reference, 'static, C, #mutex_type, #attribute_data_size, #mtu>;

                fn deref(&self) -> &Self::Target {
                    &self.server
                }
            }

        }
    }
}
