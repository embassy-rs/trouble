//! Characteristic attribute parsing and handling.
//!
//! This module contains the parsing and handling of the characteristic attribute.
//! The characteristic attribute is used to define a characteristic in a service.
//! A characteristic is a data value that can be accessed from a connected client.

use darling::{Error, FromMeta};
use proc_macro2::Span;
use syn::meta::ParseNestedMeta;
use syn::parse::Result;
use syn::spanned::Spanned;
use syn::{Field, Ident, LitStr};

use crate::uuid::Uuid;

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

#[derive(Debug, FromMeta, Default)]
pub(crate) struct AccessArgs {
    /// If true, the characteristic can be written.
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
}

/// Descriptor attribute arguments.
///
/// Descriptors are optional and can be used to add additional metadata to the characteristic.
#[derive(Debug, FromMeta)]
pub(crate) struct DescriptorArgs {
    /// The UUID of the descriptor.
    pub uuid: Uuid,
    /// The initial value of the descriptor (&str).
    /// This is optional and can be used to set the initial value of the descriptor.
    #[darling(default)]
    pub default_value: Option<syn::Expr>,
    #[darling(default)]
    /// Capacity for writing new descriptors (u8)
    pub capacity: Option<syn::Expr>,
    #[darling(default)]
    pub access: AccessArgs,
}

/// Characteristic attribute arguments
#[derive(Debug, FromMeta)]
pub(crate) struct CharacteristicArgs {
    /// The UUID of the characteristic.
    pub uuid: Uuid,
    /// Starting value for this characteristic.
    #[darling(default)]
    pub default_value: Option<syn::Expr>,
    /// Descriptors for the characteristic.
    /// Descriptors are optional and can be used to add additional metadata to the characteristic.
    /// Parsed in super::check_for_characteristic.
    #[darling(default, multiple)]
    pub descriptors: Vec<DescriptorArgs>,
    /// Any '///' comments on each field, parsed in super::check_for_characteristic.
    #[darling(default)]
    pub doc_string: String,
    #[darling(default)]
    pub access: AccessArgs,
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

impl CharacteristicArgs {
    /// Parse the arguments of a characteristic attribute
    pub fn parse(attribute: &syn::Attribute) -> Result<Self> {
        let mut uuid: Option<Uuid> = None;
        let mut read: Option<bool> = None;
        let mut write: Option<bool> = None;
        let mut notify: Option<bool> = None;
        let mut indicate: Option<bool> = None;
        let mut default_value: Option<syn::Expr> = None;
        let mut write_without_response: Option<bool> = None;
        attribute.parse_nested_meta(|meta| {
            match meta.path.get_ident().ok_or(meta.error("no ident"))?.to_string().as_str() {
                "uuid" => {
                    let parser = meta
                    .value()
                    .map_err(|_| meta.error("uuid must be followed by '= [data]'.  i.e. uuid = \"2a37\""))?;
                    let uuid_string: LitStr = parser.parse()?;
                    let value = Uuid::from_string(uuid_string.value().as_str())?;
                    check_multi(&mut uuid, "uuid", &meta, value)?
                },
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
                "default_value" => return Err(meta.error("Use 'value' for default value")),
                "descriptor" => return Err(meta.error("Descriptors are added as separate tags i.e. #[descriptor(uuid = \"1234\", value = 42, read, write, notify, indicate)]")),
                other => return Err(
                    meta.error(
                        format!(
                            "Unsupported characteristic property: '{other}'.\nSupported properties are:\nuuid, read, write, write_without_response, notify, indicate, value\n"
                        ))),
            };
            Ok(())
        })?;
        Ok(Self {
            uuid: uuid.ok_or(Error::custom("Characteristic must have a UUID"))?,
            doc_string: String::new(),
            descriptors: Vec::new(),
            default_value,
            access: AccessArgs {
                write_without_response: write_without_response.unwrap_or_default(),
                indicate: indicate.unwrap_or_default(),
                notify: notify.unwrap_or_default(),
                write: write.unwrap_or_default(),
                read: read.unwrap_or_default(),
            },
        })
    }
}

impl DescriptorArgs {
    pub fn parse(attribute: &syn::Attribute) -> Result<Self> {
        let mut uuid: Option<Uuid> = None;
        let mut read: Option<bool> = None;
        // let mut write: Option<bool> = None;
        let mut on_read: Option<Ident> = None;
        // let mut on_write: Option<Ident> = None;
        // let mut capacity: Option<syn::Expr> = None;
        let mut default_value: Option<syn::Expr> = None;
        // let mut write_without_response: Option<bool> = None;
        attribute.parse_nested_meta(|meta| {
            match meta
                .path
                .get_ident()
                .ok_or(meta.error("no ident"))?
                .to_string()
                .as_str()
            {
                "uuid" => {
                    let parser = meta
                        .value()
                        .map_err(|_| meta.error("uuid must be followed by '= [data]'.  i.e. uuid = \"2a37\""))?;
                    let uuid_string: LitStr = parser.parse()?;
                    let value = Uuid::from_string(uuid_string.value().as_str())?;
                    check_multi(&mut uuid, "uuid", &meta, value)?
                }
                "read" => check_multi(&mut read, "read", &meta, true)?,
                // "write" => check_multi(&mut write, "write", &meta, true)?,
                "on_read" => check_multi(&mut on_read, "on_read", &meta, meta.value()?.parse()?)?,
                // "on_write" => check_multi(&mut on_write, "on_write", &meta, meta.value()?.parse()?)?,
                // "write_without_response" => check_multi(&mut write_without_response, "write_without_response", &meta, true)?,
                "value" => {
                    let value = meta.value().map_err(|_| {
                        meta.error("'value' must be followed by '= [data]'.  i.e. value = \"Hello World\"")
                    })?;
                    check_multi(&mut default_value, "value", &meta, value.parse()?)?
                }
                // "capacity" => {
                //     let value = meta.value().map_err(|_| meta.error("'capacity' must be followed by '= [data]'.  i.e. value = 100"))?;
                //     check_multi(&mut capacity, "capacity", &meta, value.parse()?)?
                //     }
                "default_value" => return Err(meta.error("use 'value' for default value")),
                other => {
                    return Err(meta.error(format!(
                    // "Unsupported descriptor property: '{other}'.\nSupported properties are: uuid, read, write, write_without_response, value,\ncapacity, on_read, on_write"
                    "Unsupported descriptor property: '{other}'.\nSupported properties are: uuid, read, value, on_read"
                )));
                }
            };
            Ok(())
        })?;

        Ok(Self {
            uuid: uuid.ok_or(Error::custom("Descriptor must have a UUID"))?,
            default_value,
            capacity: None,
            access: AccessArgs {
                indicate: false, // not possible for descriptor
                notify: false,   // not possible for descriptor
                read: read.unwrap_or_default(),
                write_without_response: false,
                write: false,
            },
        })
    }
}
