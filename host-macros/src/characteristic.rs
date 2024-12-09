//! Characteristic attribute parsing and handling.
//!
//! This module contains the parsing and handling of the characteristic attribute.
//! The characteristic attribute is used to define a characteristic in a service.
//! A characteristic is a data value that can be read, written, or notified.

use crate::uuid::Uuid;
use darling::Error;
use darling::FromMeta;
use proc_macro2::Span;
use syn::parse::Result;
use syn::spanned::Spanned;
use syn::Field;
use syn::Ident;
use syn::LitStr;

#[derive(Debug)]
pub(crate) struct Characteristic {
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

/// Descriptor attribute arguments.
///
/// Descriptors are optional and can be used to add additional metadata to the characteristic.
#[derive(Debug, FromMeta)]
pub(crate) struct DescriptorArgs {
    /// The UUID of the descriptor.
    _uuid: Uuid,
    /// The value of the descriptor.
    #[darling(default)]
    _value: Option<syn::Expr>,
}

/// Characteristic attribute arguments
#[derive(Debug, FromMeta)]
pub(crate) struct CharacteristicArgs {
    /// The UUID of the characteristic.
    pub uuid: Uuid,
    /// If true, the characteristic can be read.
    #[darling(default)]
    pub read: bool,
    /// If true, the characteristic can be written.
    #[darling(default)]
    pub write: bool,
    /// If true, the characteristic can be written without a response.
    #[darling(default)]
    pub write_without_response: bool,
    /// If true, the characteristic can send notifications.
    #[darling(default)]
    pub notify: bool,
    /// If true, the characteristic can send indications.
    #[darling(default)]
    pub indicate: bool,
    /// Optional callback to be triggered on a read event
    #[darling(default)]
    pub on_read: Option<Ident>,
    /// Optional callback to be triggered on a write event
    #[darling(default)]
    pub on_write: Option<Ident>,
    /// The initial value of the characteristic.
    /// This is optional and can be used to set the initial value of the characteristic.
    #[darling(default)]
    pub default_value: Option<syn::Expr>,
    // /// Descriptors for the characteristic.
    // /// Descriptors are optional and can be used to add additional metadata to the characteristic.
    #[darling(default, multiple)]
    pub _descriptors: Vec<DescriptorArgs>,
}

impl CharacteristicArgs {
    /// Parse the arguments of a characteristic attribute
    pub fn parse(attribute: &syn::Attribute) -> Result<Self> {
        let mut uuid: Option<Uuid> = None;
        let mut read = false;
        let mut write = false;
        let mut write_without_response = false;
        let mut notify = false;
        let mut indicate = false;
        let mut on_read = None;
        let mut on_write = None;
        let mut default_value: Option<syn::Expr> = None;
        let descriptors: Vec<DescriptorArgs> = Vec::new();
        attribute.parse_nested_meta(|meta| {
            match meta.path.get_ident().ok_or(Error::custom("no ident"))?.to_string().as_str() {
                "uuid" => {
                    let value = meta
                    .value()
                    .map_err(|_| Error::custom("uuid must be followed by '= [data]'.  i.e. uuid = '0x2A37'".to_string()))?;
                    let uuid_string: LitStr = value.parse()?;
                    uuid = Some(Uuid::from_string(uuid_string.value().as_str())?);
                },
                "read" => read = true,
                "write" => write = true,
                "write_without_response" => write_without_response = true,
                "notify" => notify = true,
                "indicate" => indicate = true,
                "on_read" => on_read = Some(meta.value()?.parse()?),
                "on_write" => on_write = Some(meta.value()?.parse()?),
                "value" => {
                    // return Err(Error::custom("Default value is currently unsupported").with_span(&meta.path.span()).into())
                    let value = meta
                    .value()
                    .map_err(|_| Error::custom("value must be followed by '= [data]'.  i.e. value = 'hello'".to_string()))?;
                    default_value = Some(value.parse()?);
                },
                other => return Err(
                    meta.error(
                        format!(
                            "Unsupported characteristic property: '{other}'.\nSupported properties are: uuid, read, write, write_without_response, notify, indicate, value"
                        ))),
            };
            Ok(())
        })?;
        Ok(Self {
            uuid: uuid.ok_or(Error::custom("Characteristic must have a UUID"))?,
            read,
            write,
            write_without_response,
            notify,
            indicate,
            on_read,
            on_write,
            default_value,
            _descriptors: descriptors,
        })
    }
}
