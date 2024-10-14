//! Gatt Server Builder
//!
//! This module is responsible for generating the Gatt Server struct and its implementation.
//! It should contain one or more Gatt Services, which are decorated with the `#[gatt_service(uuid = "...")]` attribute.

use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;

pub(crate) struct ServerBuilder {
    properties: syn::ItemStruct,
}

impl ServerBuilder {
    pub fn new(properties: syn::ItemStruct) -> Self {
        Self { properties }
    }

    /// Construct the macro blueprint for the server struct.
    pub fn build(self) -> TokenStream2 {
        let name = &self.properties.ident;
        let visibility = &self.properties.vis;

        let mut code_service_definition = TokenStream2::new();
        let mut code_service_init = TokenStream2::new();
        let mut code_server_populate = TokenStream2::new();
        for service in &self.properties.fields {
            let service_span = service.span();
            let service_name = service.ident.as_ref().expect("All fields should have names");
            let service_type = &service.ty;

            code_service_definition.extend(quote_spanned! {service_span=>
                #service_name: #service_type,
            });

            code_service_init.extend(quote_spanned! {service_span=>
                let #service_name = #service_type::new(table);
            });

            code_server_populate.extend(quote_spanned! {service_span=>
                #service_name,
            });
        }

        quote! {
            #visibility struct #name<'reference, 'values, C, M, const MAX: usize, const L2CAP_MTU: usize>
            where
                C: Controller,
                M: embassy_sync::blocking_mutex::raw::RawMutex,
            {
                server: GattServer<'reference, 'values, C, M, MAX, L2CAP_MTU>,
                #code_service_definition
            }

            impl<'reference, 'values, C, M, const MAX: usize, const L2CAP_MTU: usize> #name<'reference, 'values, C, M, MAX, L2CAP_MTU>
            where
                C: Controller,
                M: embassy_sync::blocking_mutex::raw::RawMutex,
            {
                #visibility fn new(stack: Stack<'reference, C>, table: &'reference mut AttributeTable<'values, M, MAX>) -> Self {

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

            impl<'reference, 'values, C, M, const MAX: usize, const L2CAP_MTU: usize> core::ops::Deref for #name<'reference, 'values, C, M, MAX, L2CAP_MTU>
            where
                C: Controller,
                M: embassy_sync::blocking_mutex::raw::RawMutex
            {
                type Target = GattServer<'reference, 'values, C, M, MAX, L2CAP_MTU>;

                fn deref(&self) -> &Self::Target {
                    &self.server
                }
            }

        }
    }
}
