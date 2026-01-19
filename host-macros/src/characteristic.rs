//! Characteristic attribute parsing and handling.
//!
//! This module contains the parsing and handling of the characteristic attribute.
//! The characteristic attribute is used to define a characteristic in a service.
//! A characteristic is a data value that can be accessed from a connected client.

use darling::{Error, FromMeta};
use proc_macro2::{Span, TokenStream};
use quote::{quote, ToTokens, TokenStreamExt};
use syn::meta::ParseNestedMeta;
use syn::parse::Result;
use syn::spanned::Spanned;
use syn::{Field, LitStr};

use crate::uuid::Uuid;

#[derive(Debug)]
pub struct Characteristic {
    pub name: String,
    pub ty: syn::Type,
    pub args: CharacteristicArgs,
    pub span: Span,
    pub vis: syn::Visibility,
}

impl Characteristic {
    pub fn new(field: &Field, args: CharacteristicArgs) -> Self {
        Self {
            name: field.ident.as_ref().expect("Field had no Identity").to_string(),
            ty: field.ty.clone(),
            args,
            span: field.ty.span(),
            vis: field.vis.clone(),
        }
    }
}

#[derive(Debug, Default)]
pub struct PropertiesArgs {
    /// If true, the characteristic can be written.
    pub read: bool,
    /// If true, the characteristic can be written.
    pub write: bool,
    /// If true, the characteristic can be written without a response.
    pub write_without_response: bool,
    /// If true, the characteristic can send notifications.
    pub notify: bool,
    /// If true, the characteristic can send indications.
    pub indicate: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PermissionLevel {
    #[default]
    Allowed,
    EncryptionRequired,
    AuthenticationRequired,
    NotAllowed,
}

impl PermissionLevel {
    fn parse(meta: &ParseNestedMeta) -> Result<Self> {
        match meta.value() {
            Ok(value) => {
                let value: syn::Ident = value.parse()?;
                if value == "encrypted" {
                    Ok(PermissionLevel::EncryptionRequired)
                } else if value == "authenticated" {
                    Ok(PermissionLevel::AuthenticationRequired)
                } else {
                    Err(meta.error(format!(
                        "Unsupported security property: '{value}'.\nSupported values are: encrypted and authenticated\n"
                    )))
                }
            }
            Err(_) => Ok(PermissionLevel::Allowed),
        }
    }
}

impl ToTokens for PermissionLevel {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let variant = match self {
            PermissionLevel::Allowed => {
                quote! { trouble_host::attribute::PermissionLevel::Allowed }
            }
            PermissionLevel::EncryptionRequired => {
                quote! { trouble_host::attribute::PermissionLevel::EncryptionRequired }
            }
            PermissionLevel::AuthenticationRequired => {
                quote! { trouble_host::attribute::PermissionLevel::AuthenticationRequired }
            }
            PermissionLevel::NotAllowed => {
                quote! { trouble_host::attribute::PermissionLevel::NotAllowed }
            }
        };
        tokens.append_all(variant);
    }
}

#[derive(Debug, Default)]
pub struct PermissionArgs {
    pub read: PermissionLevel,
    pub write: PermissionLevel,
    pub cccd: PermissionLevel,
}

impl PermissionArgs {
    fn apply_properties(mut self, properties: &PropertiesArgs, attribute: &syn::Attribute) -> Result<Self> {
        if !properties.read {
            self.read = PermissionLevel::NotAllowed;
        } else if self.read == PermissionLevel::NotAllowed {
            return Err(syn::Error::new_spanned(
                attribute,
                "Characteristic has the read property but reading is not allowed",
            ));
        }

        if !(properties.write || properties.write_without_response) {
            self.write = PermissionLevel::NotAllowed;
        } else if self.write == PermissionLevel::NotAllowed {
            return Err(syn::Error::new_spanned(
                attribute,
                "Characteristic has the write and/or write_without_response properties but writing is not allowed",
            ));
        }

        if !(properties.notify || properties.indicate) {
            self.cccd = PermissionLevel::NotAllowed;
        } else if self.cccd == PermissionLevel::NotAllowed {
            return Err(syn::Error::new_spanned(
                attribute,
                "Characteristic has the notify and/or indicate properties but writing to the CCCD is not allowed",
            ));
        }

        Ok(self)
    }

    pub fn is_read_only(&self) -> bool {
        self.read != PermissionLevel::NotAllowed
            && self.write == PermissionLevel::NotAllowed
            && self.cccd == PermissionLevel::NotAllowed
    }

    fn parse(meta: &ParseNestedMeta) -> Result<Self> {
        let mut base = None;
        let mut read = None;
        let mut write = None;
        let mut cccd = None;

        meta.parse_nested_meta(|meta| {
            match meta.path.get_ident().ok_or(meta.error("no ident"))?.to_string().as_str() {
                "encrypted" => {
                    check_multi(&mut base, "encrypted/authenticated", &meta, PermissionLevel::EncryptionRequired)?;
                }
                "authenticated" => {
                    check_multi(&mut base, "encrypted/authenticated", &meta, PermissionLevel::AuthenticationRequired)?;
                }
                "read" => {
                    let level = PermissionLevel::parse(&meta)?;
                    check_multi(&mut read, "read", &meta, level)?;
                }
                "write" => {
                    let level = PermissionLevel::parse(&meta)?;
                    check_multi(&mut write, "write", &meta, level)?;
                }
                "cccd" => {
                    let level = PermissionLevel::parse(&meta)?;
                    check_multi(&mut cccd, "cccd", &meta, level)?;
                }
                other => return Err(
                    meta.error(
                        format!(
                            "Unsupported security property: '{other}'.\nSupported properties are:\nread, write, cccd, encrypted, or authenticated\n"
                        ))),
            }
            Ok(())
        })?;

        let base = base.unwrap_or(PermissionLevel::NotAllowed);
        Ok(Self {
            read: read.unwrap_or(base),
            write: write.unwrap_or(base),
            cccd: cccd.unwrap_or(base),
        })
    }
}

impl ToTokens for PermissionArgs {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let read = &self.read;
        let write = &self.write;
        let cccd = &self.cccd;

        if self.read != PermissionLevel::Allowed && self.read != PermissionLevel::NotAllowed {
            tokens.append_all(quote! { .read_permission(#read) });
        }
        if self.write != PermissionLevel::Allowed && self.write != PermissionLevel::NotAllowed {
            tokens.append_all(quote! { .write_permission(#write) });
        }
        if self.cccd != PermissionLevel::Allowed && self.cccd != PermissionLevel::NotAllowed {
            tokens.append_all(quote! { .cccd_permission(#cccd) });
        }
    }
}

/// Descriptor attribute arguments.
///
/// Descriptors are optional and can be used to add additional metadata to the characteristic.
#[derive(Debug)]
pub struct DescriptorArgs {
    /// The UUID of the descriptor.
    pub uuid: TokenStream,
    /// The name which will be used to identify the descriptor when accessing its attribute handle
    pub name: Option<LitStr>,
    /// The initial value of the descriptor (&str).
    /// This is optional and can be used to set the initial value of the descriptor.
    pub default_value: Option<syn::Expr>,
    pub ty: Option<syn::Type>,
    pub permissions: PermissionArgs,
}

/// Characteristic attribute arguments
#[derive(Debug)]
pub struct CharacteristicArgs {
    /// The UUID of the characteristic.
    pub uuid: TokenStream,
    /// Starting value for this characteristic.
    pub default_value: Option<syn::Expr>,
    /// Descriptors for the characteristic.
    /// Descriptors are optional and can be used to add additional metadata to the characteristic.
    /// Parsed in super::check_for_characteristic.
    pub descriptors: Vec<DescriptorArgs>,
    /// Any '///' comments on each field, parsed in super::check_for_characteristic.
    pub doc_string: Vec<syn::Attribute>,
    pub cfg: Option<syn::Attribute>,
    pub properties: PropertiesArgs,
    pub permissions: PermissionArgs,
}

/// Check if this bool type has been specified more than once.
fn check_multi<T>(arg: &mut Option<T>, name: &str, meta: &ParseNestedMeta<'_>, value: T) -> Result<()> {
    if arg.is_none() {
        *arg = Some(value);
        Ok(())
    } else {
        Err(meta.error(format!("'{name}' should not be specified more than once")))
    }
}

pub fn parse_uuid(meta: &ParseNestedMeta<'_>) -> Result<TokenStream> {
    let parser = meta.value().map_err(|_| {
        meta.error(
            "uuid must be followed by '= [data]'.  i.e. uuid = \"2a37\" or \"0000180f-0000-1000-8000-00805f9b34fb\"",
        )
    })?;
    if let Ok(uuid_string) = parser.parse::<LitStr>() {
        // Check if it's a valid UUID from a string before running the code
        let uuid = Uuid::from_string(uuid_string.value().as_str()).map_err(|_| {
            meta.error("Invalid UUID string.  Expect i.e. \"180f\" or \"0000180f-0000-1000-8000-00805f9b34fb\"")
        })?;
        Ok(quote::quote! { #uuid })
    } else {
        let expr: syn::Expr = parser.parse()?;
        let span = expr.span(); // span will highlight if the value does not impl Into<Uuid>
        Ok(quote::quote_spanned! { span =>
            {
                let uuid: trouble_host::types::uuid::Uuid = #expr.into();
                uuid
            }
        })
    }
}

impl CharacteristicArgs {
    /// Parse the arguments of a characteristic attribute
    pub fn parse(attribute: &syn::Attribute) -> Result<Self> {
        let mut uuid: Option<_> = None;
        let mut read: Option<bool> = None;
        let mut write: Option<bool> = None;
        let mut notify: Option<bool> = None;
        let mut indicate: Option<bool> = None;
        let mut permissions: Option<PermissionArgs> = None;
        let mut default_value: Option<syn::Expr> = None;
        let mut write_without_response: Option<bool> = None;
        attribute.parse_nested_meta(|meta| {
            match meta.path.get_ident().ok_or(meta.error("no ident"))?.to_string().as_str() {
                "uuid" => check_multi(&mut uuid, "uuid", &meta, parse_uuid(&meta)?)?,
                "read" => check_multi(&mut read, "read", &meta, true)?,
                "write" => check_multi(&mut write, "write", &meta, true)?,
                "notify" => check_multi(&mut notify, "notify", &meta, true)?,
                "indicate" => check_multi(&mut indicate, "indicate", &meta, true)?,
                "write_without_response" => check_multi(&mut write_without_response, "write_without_response", &meta, true)?,
                "value" => {
                    let value = meta
                        .value()
                        .map_err(|_| meta.error("'value' must be followed by '= [data]'.  i.e. value = \"42\""))?;
                    check_multi(&mut default_value, "value", &meta, value.parse()?)?
                }
                "permissions" => {
                    let value = PermissionArgs::parse(&meta)?;
                    check_multi(&mut permissions, "permissions", &meta, value)?;
                }
                "default_value" => return Err(meta.error("Use 'value' for default value")),
                "descriptor" => return Err(meta.error("Descriptors are added as separate tags i.e. #[descriptor(uuid = \"1234\", value = 42, read, write, notify, indicate)]")),
                other => return Err(
                    meta.error(
                        format!(
                            "Unsupported characteristic property: '{other}'.\nSupported properties are:\nuuid, read, write, write_without_response, notify, indicate, value, or permissions\n"
                        ))),
            };
            Ok(())
        })?;

        let properties = PropertiesArgs {
            read: read.unwrap_or_default(),
            write: write.unwrap_or_default(),
            write_without_response: write_without_response.unwrap_or_default(),
            notify: notify.unwrap_or_default(),
            indicate: indicate.unwrap_or_default(),
        };

        let permissions = permissions
            .unwrap_or_default()
            .apply_properties(&properties, attribute)?;

        Ok(Self {
            uuid: uuid.ok_or(Error::custom("Characteristic must have a UUID"))?,
            doc_string: Vec::new(),
            cfg: None,
            descriptors: Vec::new(),
            default_value,
            properties,
            permissions,
        })
    }
}

impl DescriptorArgs {
    pub fn parse(attribute: &syn::Attribute) -> Result<Self> {
        let mut uuid: Option<_> = None;
        let mut name: Option<LitStr> = None;
        let mut read: Option<PermissionLevel> = None;
        let mut write: Option<PermissionLevel> = None;
        let mut default_value: Option<syn::Expr> = None;
        let mut ty: Option<syn::Type> = None;
        attribute.parse_nested_meta(|meta| {
            match meta
                .path
                .get_ident()
                .ok_or(meta.error("no ident"))?
                .to_string()
                .as_str()
            {
                "uuid" => check_multi(&mut uuid, "uuid", &meta, parse_uuid(&meta)?)?,
                "name" => {
                    let value = meta
                        .value()
                        .map_err(|_| meta.error("'name' must be followed by '= [name]'. i.e. name = \"units\""))?;
                    check_multi(&mut name, "name", &meta, value.parse()?)?
                }
                "read" => {
                    let level = PermissionLevel::parse(&meta)?;
                    check_multi(&mut read, "read", &meta, level)?;
                }
                "write" => {
                    let level = PermissionLevel::parse(&meta)?;
                    check_multi(&mut write, "write", &meta, level)?;
                }
                "value" => {
                    let value = meta.value().map_err(|_| {
                        meta.error("'value' must be followed by '= [data]'.  i.e. value = \"Hello World\"")
                    })?;
                    check_multi(&mut default_value, "value", &meta, value.parse()?)?
                }
                "type" => {
                    let value = meta
                        .value()
                        .map_err(|_| meta.error("'type' must be followed by '= [type]'. i.e. type = &'static str"))?;
                    check_multi(&mut ty, "type", &meta, value.parse()?)?
                }
                "default_value" => return Err(meta.error("use 'value' for default value")),
                other => {
                    return Err(meta.error(format!(
                        "Unsupported descriptor property: '{other}'.\nSupported properties are: uuid, name, read, write, value, type"
                    )));
                }
            };
            Ok(())
        })?;

        if name.is_some() && ty.is_none() {
            return Err(syn::Error::new_spanned(
                attribute,
                "Descriptor type is required for named descriptors.",
            ));
        }

        let permissions = PermissionArgs {
            read: read.unwrap_or(PermissionLevel::NotAllowed),
            write: write.unwrap_or(PermissionLevel::NotAllowed),
            cccd: PermissionLevel::NotAllowed,
        };
        if permissions.read == PermissionLevel::NotAllowed && permissions.write == PermissionLevel::NotAllowed {
            return Err(syn::Error::new_spanned(
                attribute,
                "At least one of read or write is required for descriptor",
            ));
        }

        Ok(Self {
            uuid: uuid.ok_or(Error::custom("Descriptor must have a UUID"))?,
            name,
            default_value,
            ty,
            permissions,
        })
    }
}
