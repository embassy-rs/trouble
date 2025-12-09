//! Callback-based GATT service macro implementation
//!
//! This module implements a method-based approach to GATT services where
//! each characteristic is represented by an async method that handles read/write
//! requests through a GattRequest enum.
//!
//! # Design
//!
//! Input:
//! ```ignore
//! #[gatt_service(uuid = service::BATTERY)]
//! struct BatteryService {
//!     battery_level: u8,
//! }
//!
//! impl BatteryService {
//!     #[descriptor(uuid = descriptors::VALID_RANGE, read, value = [0, 100])]
//!     #[characteristic(uuid = characteristic::BATTERY_LEVEL, read, notify)]
//!     async fn level(&self, req: GattRequest) -> Result<(), AttErrorCode> {
//!         match req {
//!             GattRequest::Read(resp) => resp.write(&[self.battery_level]),
//!             _ => Err(AttErrorCode::WRITE_NOT_PERMITTED)
//!         }
//!     }
//! }
//! ```
//!
//! The macro generates:
//! 1. An attribute table implementation for the service
//! 2. Handle constants for each attribute
//! 3. Attribute implementations that route to the methods
//! 4. Iterator for all attributes

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    Attribute, Error, Expr, Ident, ImplItem, ItemImpl, ItemStruct, LitStr, Meta, Path, Result, Token,
};

/// Arguments for the #[gatt_service] attribute
pub struct ServiceArgs {
    pub uuid: Expr,
}

impl Parse for ServiceArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let content;
        syn::parenthesized!(content in input);

        // Parse "uuid = ..."
        let name: Ident = content.parse()?;
        if name != "uuid" {
            return Err(Error::new(name.span(), "expected 'uuid'"));
        }
        content.parse::<Token![=]>()?;
        let uuid: Expr = content.parse()?;

        Ok(ServiceArgs { uuid })
    }
}

/// Arguments for the #[characteristic] attribute
pub struct CharacteristicArgs {
    pub uuid: Expr,
    pub read: bool,
    pub write: bool,
    pub write_without_response: bool,
    pub notify: bool,
    pub indicate: bool,
}

impl CharacteristicArgs {
    fn parse_meta(&mut self, meta: &Meta) -> Result<()> {
        match meta {
            Meta::Path(path) => {
                if path.is_ident("read") {
                    self.read = true;
                } else if path.is_ident("write") {
                    self.write = true;
                } else if path.is_ident("write_without_response") {
                    self.write_without_response = true;
                } else if path.is_ident("notify") {
                    self.notify = true;
                } else if path.is_ident("indicate") {
                    self.indicate = true;
                }
                Ok(())
            }
            Meta::NameValue(nv) => {
                if nv.path.is_ident("uuid") {
                    // uuid is already parsed
                    Ok(())
                } else {
                    Err(Error::new_spanned(nv, "unexpected attribute"))
                }
            }
            _ => Err(Error::new_spanned(meta, "unexpected attribute format")),
        }
    }
}

/// Arguments for the #[descriptor] attribute
pub struct DescriptorArgs {
    pub uuid: Expr,
    pub read: bool,
    pub write: bool,
    pub value: Option<Expr>,
    pub name: Option<LitStr>,
}

/// Information about a characteristic method
struct CharacteristicMethod {
    method_name: Ident,
    char_args: CharacteristicArgs,
    descriptors: Vec<DescriptorArgs>,
}

/// Builder for generating the service implementation
pub struct CallbackServiceBuilder {
    service_struct: ItemStruct,
    service_uuid: Expr,
    impl_block: ItemImpl,
    characteristics: Vec<CharacteristicMethod>,
}

impl CallbackServiceBuilder {
    pub fn new(service_struct: ItemStruct, service_uuid: Expr, impl_block: ItemImpl) -> Self {
        Self {
            service_struct,
            service_uuid,
            impl_block,
            characteristics: Vec::new(),
        }
    }

    /// Parse the impl block to extract characteristics
    pub fn parse_impl(&mut self) -> Result<()> {
        for item in &self.impl_block.items {
            if let ImplItem::Fn(method) = item {
                // Check if this method has #[characteristic] attribute
                let mut char_args: Option<CharacteristicArgs> = None;
                let mut descriptors: Vec<DescriptorArgs> = Vec::new();

                for attr in &method.attrs {
                    if attr.path().is_ident("characteristic") {
                        // Parse characteristic arguments
                        char_args = Some(self.parse_characteristic_attr(attr)?);
                    } else if attr.path().is_ident("descriptor") {
                        // Parse descriptor arguments
                        descriptors.push(self.parse_descriptor_attr(attr)?);
                    }
                }

                if let Some(args) = char_args {
                    self.characteristics.push(CharacteristicMethod {
                        method_name: method.sig.ident.clone(),
                        char_args: args,
                        descriptors,
                    });
                }
            }
        }
        Ok(())
    }

    fn parse_characteristic_attr(&self, attr: &Attribute) -> Result<CharacteristicArgs> {
        let mut args = CharacteristicArgs {
            uuid: syn::parse_quote!(0u16),
            read: false,
            write: false,
            write_without_response: false,
            notify: false,
            indicate: false,
        };

        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("uuid") {
                args.uuid = meta.value()?.parse()?;
                Ok(())
            } else {
                args.parse_meta(&Meta::Path(meta.path))
            }
        })?;

        Ok(args)
    }

    fn parse_descriptor_attr(&self, attr: &Attribute) -> Result<DescriptorArgs> {
        let mut args = DescriptorArgs {
            uuid: syn::parse_quote!(0u16),
            read: false,
            write: false,
            value: None,
            name: None,
        };

        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("uuid") {
                args.uuid = meta.value()?.parse()?;
            } else if meta.path.is_ident("value") {
                args.value = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("name") {
                args.name = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("read") {
                args.read = true;
            } else if meta.path.is_ident("write") {
                args.write = true;
            }
            Ok(())
        })?;

        Ok(args)
    }

    /// Generate the complete implementation
    pub fn build(mut self) -> Result<TokenStream> {
        self.parse_impl()?;

        let struct_name = &self.service_struct.ident;
        let service_uuid = &self.service_uuid;
        let struct_def = &self.service_struct;
        let impl_block = &self.impl_block;

        // Generate handle constants
        let handle_constants = self.generate_handle_constants(struct_name);

        // Generate attribute enum
        let attribute_enum = self.generate_attribute_enum(struct_name);

        // Generate Attribute trait impl
        let attribute_impl = self.generate_attribute_impl(struct_name);

        // Generate iterator
        let iterator = self.generate_iterator(struct_name);

        // Generate AttributeTable impl
        let attribute_table_impl = self.generate_attribute_table_impl(struct_name);

        Ok(quote! {
            #struct_def

            #handle_constants

            #attribute_enum

            #attribute_impl

            #iterator

            #attribute_table_impl

            // Keep original impl block
            #impl_block
        })
    }

    fn generate_handle_constants(&self, struct_name: &Ident) -> TokenStream {
        let mod_name = Ident::new(
            &format!("{}_handles", struct_name.to_string().to_lowercase()),
            Span::call_site(),
        );

        let mut handle = 1u16;
        let mut constants = Vec::new();

        // Service declaration
        constants.push(quote! {
            pub const SERVICE_DECL: u16 = #handle;
        });
        handle += 1;

        // For each characteristic
        for ch in &self.characteristics {
            let ch_name_upper = ch.method_name.to_string().to_uppercase();

            // Characteristic declaration
            let decl_name = Ident::new(&format!("{}_DECL", ch_name_upper), Span::call_site());
            constants.push(quote! {
                pub const #decl_name: u16 = #handle;
            });
            handle += 1;

            // Characteristic value
            let value_name = Ident::new(&format!("{}_VALUE", ch_name_upper), Span::call_site());
            constants.push(quote! {
                pub const #value_name: u16 = #handle;
            });
            handle += 1;

            // Descriptors
            for (i, _desc) in ch.descriptors.iter().enumerate() {
                let desc_name = Ident::new(
                    &format!("{}_DESC_{}", ch_name_upper, i),
                    Span::call_site(),
                );
                constants.push(quote! {
                    pub const #desc_name: u16 = #handle;
                });
                handle += 1;
            }

            // CCCD if notify or indicate
            if ch.char_args.notify || ch.char_args.indicate {
                let cccd_name = Ident::new(&format!("{}_CCCD", ch_name_upper), Span::call_site());
                constants.push(quote! {
                    pub const #cccd_name: u16 = #handle;
                });
                handle += 1;
            }
        }

        // End handle
        let end_handle = handle - 1;
        constants.push(quote! {
            pub const END_HANDLE: u16 = #end_handle;
        });

        quote! {
            mod #mod_name {
                #(#constants)*
            }
        }
    }

    fn generate_attribute_enum(&self, struct_name: &Ident) -> TokenStream {
        let enum_name = Ident::new(&format!("{}Attribute", struct_name), Span::call_site());

        let mut variants = vec![
            quote! { ServiceDeclaration }
        ];

        for ch in &self.characteristics {
            let ch_name = &ch.method_name;
            let ch_name_pascal = Self::to_pascal_case(&ch_name.to_string());

            // Declaration variant
            let decl_variant = Ident::new(&format!("{}Declaration", ch_name_pascal), Span::call_site());
            variants.push(quote! { #decl_variant });

            // Value variant (holds reference to service)
            let value_variant = Ident::new(&format!("{}Value", ch_name_pascal), Span::call_site());
            variants.push(quote! { #value_variant(&'a #struct_name) });

            // Descriptor variants
            for (i, _desc) in ch.descriptors.iter().enumerate() {
                let desc_variant = Ident::new(
                    &format!("{}Descriptor{}", ch_name_pascal, i),
                    Span::call_site(),
                );
                variants.push(quote! { #desc_variant });
            }

            // CCCD variant
            if ch.char_args.notify || ch.char_args.indicate {
                let cccd_variant = Ident::new(&format!("{}Cccd", ch_name_pascal), Span::call_site());
                variants.push(quote! { #cccd_variant(&'a #struct_name) });
            }
        }

        quote! {
            enum #enum_name<'a> {
                #(#variants),*
            }
        }
    }

    fn generate_attribute_impl(&self, struct_name: &Ident) -> TokenStream {
        let enum_name = Ident::new(&format!("{}Attribute", struct_name), Span::call_site());
        let mod_name = Ident::new(
            &format!("{}_handles", struct_name.to_string().to_lowercase()),
            Span::call_site(),
        );
        let service_uuid = &self.service_uuid;

        // Generate handle() match arms
        let mut handle_arms = vec![
            quote! { Self::ServiceDeclaration => #mod_name::SERVICE_DECL }
        ];

        // Generate uuid() match arms
        let mut uuid_arms = vec![
            quote! {
                Self::ServiceDeclaration => ::trouble_host::types::uuid::Uuid::from(
                    ::trouble_host::types::uuid::declarations::PRIMARY_SERVICE
                )
            }
        ];

        // Generate kind() match arms
        let mut kind_arms = vec![
            quote! { Self::ServiceDeclaration => ::trouble_host::gatt::AttributeKind::Service }
        ];

        // Generate read() match arms
        let mut read_arms = vec![
            quote! {
                Self::ServiceDeclaration => {
                    let uuid = #service_uuid.as_le_bytes();
                    let offset = offset as usize;
                    if offset >= uuid.len() {
                        return Ok(0);
                    }
                    let len = (uuid.len() - offset).min(output.len());
                    output[..len].copy_from_slice(&uuid[offset..offset + len]);
                    Ok(len)
                }
            }
        ];

        // Generate write() match arms
        let mut write_arms = Vec::new();

        for ch in &self.characteristics {
            let ch_name = &ch.method_name;
            let ch_name_pascal = Self::to_pascal_case(&ch_name.to_string());
            let ch_name_upper = ch_name.to_string().to_uppercase();
            let char_uuid = &ch.char_args.uuid;

            // Properties byte
            let mut properties = 0u8;
            if ch.char_args.read { properties |= 0x02; }
            if ch.char_args.write { properties |= 0x08; }
            if ch.char_args.write_without_response { properties |= 0x04; }
            if ch.char_args.notify { properties |= 0x10; }
            if ch.char_args.indicate { properties |= 0x20; }

            // Declaration
            let decl_variant = Ident::new(&format!("{}Declaration", ch_name_pascal), Span::call_site());
            let decl_handle = Ident::new(&format!("{}_DECL", ch_name_upper), Span::call_site());
            let value_handle = Ident::new(&format!("{}_VALUE", ch_name_upper), Span::call_site());

            handle_arms.push(quote! { Self::#decl_variant => #mod_name::#decl_handle });
            uuid_arms.push(quote! {
                Self::#decl_variant => ::trouble_host::types::uuid::Uuid::from(
                    ::trouble_host::types::uuid::declarations::CHARACTERISTIC
                )
            });
            kind_arms.push(quote! { Self::#decl_variant => ::trouble_host::gatt::AttributeKind::Declaration });
            read_arms.push(quote! {
                Self::#decl_variant => {
                    let properties = #properties;
                    let handle = #mod_name::#value_handle;
                    let uuid = #char_uuid.as_le_bytes();

                    let mut data = [0u8; 19];
                    data[0] = properties;
                    data[1..3].copy_from_slice(&handle.to_le_bytes());
                    data[3..3 + uuid.len()].copy_from_slice(uuid);
                    let total_len = 3 + uuid.len();

                    let offset = offset as usize;
                    if offset >= total_len {
                        return Ok(0);
                    }
                    let len = (total_len - offset).min(output.len());
                    output[..len].copy_from_slice(&data[offset..offset + len]);
                    Ok(len)
                }
            });

            // Value
            let value_variant = Ident::new(&format!("{}Value", ch_name_pascal), Span::call_site());

            handle_arms.push(quote! { Self::#value_variant(_) => #mod_name::#value_handle });
            uuid_arms.push(quote! { Self::#value_variant(_) => ::trouble_host::types::uuid::Uuid::from(#char_uuid) });
            kind_arms.push(quote! { Self::#value_variant(_) => ::trouble_host::gatt::AttributeKind::Data });

            // Read implementation - calls the method
            if ch.char_args.read {
                read_arms.push(quote! {
                    Self::#value_variant(service) => {
                        service.#ch_name(::trouble_host::gatt::GattRequest::Read { offset, output }).await?;
                        Ok(output.len())
                    }
                });
            } else {
                read_arms.push(quote! {
                    Self::#value_variant(_) => Err(::trouble_host::att::AttErrorCode::READ_NOT_PERMITTED)
                });
            }

            // Write implementation - calls the method
            if ch.char_args.write || ch.char_args.write_without_response {
                write_arms.push(quote! {
                    Self::#value_variant(service) => {
                        service.#ch_name(::trouble_host::gatt::GattRequest::Write { offset, input }).await
                    }
                });
            } else {
                write_arms.push(quote! {
                    Self::#value_variant(_) => Err(::trouble_host::att::AttErrorCode::WRITE_NOT_PERMITTED)
                });
            }

            // Descriptors
            for (i, desc) in ch.descriptors.iter().enumerate() {
                let desc_variant = Ident::new(&format!("{}Descriptor{}", ch_name_pascal, i), Span::call_site());
                let desc_handle = Ident::new(&format!("{}_DESC_{}", ch_name_upper, i), Span::call_site());
                let desc_uuid = &desc.uuid;

                handle_arms.push(quote! { Self::#desc_variant => #mod_name::#desc_handle });
                uuid_arms.push(quote! { Self::#desc_variant => ::trouble_host::types::uuid::Uuid::from(#desc_uuid) });
                kind_arms.push(quote! { Self::#desc_variant => ::trouble_host::gatt::AttributeKind::Data });

                if let Some(value) = &desc.value {
                    read_arms.push(quote! {
                        Self::#desc_variant => {
                            let data = #value;
                            let offset = offset as usize;
                            if offset >= data.len() {
                                return Ok(0);
                            }
                            let len = (data.len() - offset).min(output.len());
                            output[..len].copy_from_slice(&data[offset..offset + len]);
                            Ok(len)
                        }
                    });
                }
            }

            // CCCD
            if ch.char_args.notify || ch.char_args.indicate {
                let cccd_variant = Ident::new(&format!("{}Cccd", ch_name_pascal), Span::call_site());
                let cccd_handle = Ident::new(&format!("{}_CCCD", ch_name_upper), Span::call_site());

                handle_arms.push(quote! { Self::#cccd_variant(_) => #mod_name::#cccd_handle });
                uuid_arms.push(quote! {
                    Self::#cccd_variant(_) => ::trouble_host::types::uuid::Uuid::from(
                        ::trouble_host::types::uuid::descriptors::CLIENT_CHARACTERISTIC_CONFIGURATION
                    )
                });
                kind_arms.push(quote! { Self::#cccd_variant(_) => ::trouble_host::gatt::AttributeKind::Cccd });

                read_arms.push(quote! {
                    Self::#cccd_variant(_service) => {
                        // TODO: Read CCCD state from peer state
                        let value = 0u16;
                        if offset > 0 {
                            return Ok(0);
                        }
                        if output.len() < 2 {
                            return Ok(0);
                        }
                        output[0..2].copy_from_slice(&value.to_le_bytes());
                        Ok(2)
                    }
                });

                write_arms.push(quote! {
                    Self::#cccd_variant(_service) => {
                        // TODO: Write CCCD state to peer state
                        Ok(())
                    }
                });
            }
        }

        quote! {
            impl<'a> ::trouble_host::gatt::Attribute for #enum_name<'a> {
                type Error = ::trouble_host::att::AttErrorCode;

                fn handle(&self) -> u16 {
                    match self {
                        #(#handle_arms),*
                    }
                }

                fn uuid(&self) -> ::trouble_host::types::uuid::Uuid {
                    match self {
                        #(#uuid_arms),*
                    }
                }

                fn last(&self) -> u16 {
                    #mod_name::END_HANDLE
                }

                fn kind(&self) -> ::trouble_host::gatt::AttributeKind {
                    match self {
                        #(#kind_arms),*
                    }
                }

                async fn read(&self, offset: u16, output: &mut [u8]) -> Result<usize, Self::Error> {
                    match self {
                        #(#read_arms),*
                        #[allow(unreachable_patterns)]
                        _ => Err(::trouble_host::att::AttErrorCode::READ_NOT_PERMITTED)
                    }
                }

                async fn write(&self, offset: u16, input: &[u8]) -> Result<(), Self::Error> {
                    match self {
                        #(#write_arms),*
                        #[allow(unreachable_patterns)]
                        _ => Err(::trouble_host::att::AttErrorCode::WRITE_NOT_PERMITTED)
                    }
                }
            }
        }
    }

    fn generate_iterator(&self, struct_name: &Ident) -> TokenStream {
        let iter_name = Ident::new(&format!("{}Iterator", struct_name), Span::call_site());
        let enum_name = Ident::new(&format!("{}Attribute", struct_name), Span::call_site());

        let mut match_arms = vec![
            quote! { 0 => Some(#enum_name::ServiceDeclaration) }
        ];

        let mut index = 1;
        for ch in &self.characteristics {
            let ch_name_pascal = Self::to_pascal_case(&ch.method_name.to_string());

            // Declaration
            let decl_variant = Ident::new(&format!("{}Declaration", ch_name_pascal), Span::call_site());
            match_arms.push(quote! { #index => Some(#enum_name::#decl_variant) });
            index += 1;

            // Value
            let value_variant = Ident::new(&format!("{}Value", ch_name_pascal), Span::call_site());
            match_arms.push(quote! { #index => Some(#enum_name::#value_variant(self.service)) });
            index += 1;

            // Descriptors
            for (i, _desc) in ch.descriptors.iter().enumerate() {
                let desc_variant = Ident::new(&format!("{}Descriptor{}", ch_name_pascal, i), Span::call_site());
                match_arms.push(quote! { #index => Some(#enum_name::#desc_variant) });
                index += 1;
            }

            // CCCD
            if ch.char_args.notify || ch.char_args.indicate {
                let cccd_variant = Ident::new(&format!("{}Cccd", ch_name_pascal), Span::call_site());
                match_arms.push(quote! { #index => Some(#enum_name::#cccd_variant(self.service)) });
                index += 1;
            }
        }

        match_arms.push(quote! { _ => None });

        quote! {
            struct #iter_name<'a> {
                service: &'a #struct_name,
                index: usize,
            }

            impl<'a> Iterator for #iter_name<'a> {
                type Item = #enum_name<'a>;

                fn next(&mut self) -> Option<Self::Item> {
                    let item = match self.index {
                        #(#match_arms),*
                    };
                    self.index += 1;
                    item
                }
            }
        }
    }

    fn generate_attribute_table_impl(&self, struct_name: &Ident) -> TokenStream {
        let iter_name = Ident::new(&format!("{}Iterator", struct_name), Span::call_site());
        let enum_name = Ident::new(&format!("{}Attribute", struct_name), Span::call_site());

        quote! {
            impl<'a> ::trouble_host::gatt::AttributeTable for &'a #struct_name {
                type Attribute = #enum_name<'a>;
                type Iterator = #iter_name<'a>;

                fn iter(&self) -> Self::Iterator {
                    #iter_name {
                        service: self,
                        index: 0,
                    }
                }
            }
        }
    }

    fn to_pascal_case(s: &str) -> String {
        s.split('_')
            .map(|word| {
                let mut chars = word.chars();
                match chars.next() {
                    None => String::new(),
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                }
            })
            .collect()
    }
}
