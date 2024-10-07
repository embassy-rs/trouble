use crate::uuid::Uuid;
use darling::FromMeta;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote, quote_spanned};
use syn::meta::ParseNestedMeta;
use syn::parse::Result;
use syn::spanned::Spanned;
use syn::{Ident, LitStr};

pub(crate) struct ServerBuilder {
    properties: syn::ItemStruct,
    // event_enum_name: Ident,
    // code_impl: TokenStream2,
    // code_build_chars: TokenStream2,
    // code_struct_init: TokenStream2,
    // code_on_write: TokenStream2,
    // code_event_enum: TokenStream2,
    // code_fields: TokenStream2,
}

impl ServerBuilder {
    pub fn new(properties: syn::ItemStruct) -> Self {
        Self { properties }
    }

    pub fn build(self) -> TokenStream2 {
        let properties = &self.properties;
        let name = &self.properties.ident;
        let visibility = &self.properties.vis;
        // let visibility = self.properties.vis;
        // let name = self.properties.ident;

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
                let #service_name = #service_type::new(&mut server.server.table);
            });

            code_server_populate.extend(quote_spanned! {service_span=>
                #service_name,
            })
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
                 #visibility fn new(stack: Stack<'reference, C>, id: &'reference [u8], appearance: &'reference [u8]) -> Self {
                     let server = GattServer::new(stack);

                     // Generic access service (mandatory)
                     let mut generic_access_service = server.server.table.add_service(Service::new(0x1800));
                     let _ = generic_access_service.add_characteristic_ro(0x2a00, id);
                     let _ = generic_access_service.add_characteristic_ro(0x2a01, appearance);
                     generic_access_service.build();

                     // Generic attribute service (mandatory)
                     server.server.table.add_service(Service::new(0x1801));

                     #code_service_init

                     Self {
                         server: GattServer::new(stack),
                         #code_server_populate
                     }
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
