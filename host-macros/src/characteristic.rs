//! Characteristic attribute parsing and handling.
//!
//! This module contains the parsing and handling of the characteristic attribute.
//! The characteristic attribute is used to define a characteristic in a service.
//! A characteristic is a data value that can be read, written, or notified.

use crate::uuid::Uuid;
use darling::Error;
use darling::FromMeta;
use proc_macro2::Span;
use syn::meta::ParseNestedMeta;
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
    pub uuid: Uuid,
    /// The initial value of the descriptor.
    /// This is optional and can be used to set the initial value of the descriptor.
    #[darling(default)]
    pub default_value: Option<syn::Expr>,
    /// If true, the descriptor can be written.
    #[darling(default)]
    pub read: bool,
    /// If true, the descriptor can be written.
    #[darling(default)]
    pub write: bool,
    /// If true, the descriptor can be written without a response.
    #[darling(default)]
    pub write_without_response: bool,
    /// If true, the descriptor can send notifications.
    #[darling(default)]
    pub notify: bool,
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
    /// Descriptors for the characteristic.
    /// Descriptors are optional and can be used to add additional metadata to the characteristic.
    #[darling(default, multiple)]
    pub descriptors: Vec<DescriptorArgs>,
    #[darling(default)]
    pub doc_string: String,
}

/// Check if this bool type has been specified more than once.
fn check_multi(val: &mut Option<bool>, name: &str, meta: &ParseNestedMeta<'_>) -> Result<()> {
    if val.is_none() {
        *val = Some(true);
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
        let mut write_without_response: Option<bool> = None;
        let mut notify: Option<bool> = None;
        let mut indicate: Option<bool> = None;
        let mut on_read = None;
        let mut on_write = None;
        let mut default_value: Option<syn::Expr> = None;
        attribute.parse_nested_meta(|meta| {
            match meta.path.get_ident().ok_or(Error::custom("no ident"))?.to_string().as_str() {
                "uuid" => {
                    if uuid.is_some() {
                        return Err(meta.error("'uuid' should not be specified more than once"))
                    }
                    let value = meta
                    .value()
                    .map_err(|_| Error::custom("uuid must be followed by '= [data]'.  i.e. uuid = '0x2A37'".to_string()))?;
                    let uuid_string: LitStr = value.parse()?;
                    uuid = Some(Uuid::from_string(uuid_string.value().as_str())?);
                },
                "read" => check_multi(&mut read, "read", &meta)?,
                "write" => check_multi(&mut write, "write", &meta)?,
                "write_without_response" => check_multi(&mut write_without_response, "write_without_response", &meta)?,
                "notify" => check_multi(&mut notify, "notify", &meta)?,
                "indicate" => check_multi(&mut indicate, "indicate", &meta)?,
                "on_read" => if on_read.is_none() { 
                        on_read = Some(meta.value()?.parse()?) 
                    } else {
                        return Err(meta.error("'on_read' should not be specified more than once"))
                    },
                "on_write" => if on_write.is_none() {
                        on_write = Some(meta.value()?.parse()?)
                    } else {
                        return Err(meta.error("'on_write' should not be specified more than once"))
                    },
                "value" => {
                    if default_value.is_some() {
                        return Err(meta.error("'value' should not be specified more than once"))
                    }
                    let value = meta
                    .value()
                    .map_err(|_| Error::custom("value must be followed by '= [data]'.  i.e. value = 'hello'".to_string()))?;
                    default_value = Some(value.parse()?); // type checking done in construct_characteristic_static
                },
                "default_value" => return Err(meta.error("use 'value' for default value")),
                "descriptor" => return Err(meta.error("descriptors are added as separate tags i.e. #[descriptor(uuid = \"1234\", value = 42)]")),
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
            read: read.unwrap_or_default(),
            write: write.unwrap_or_default(),
            write_without_response: write_without_response.unwrap_or_default(),
            notify: notify.unwrap_or_default(),
            indicate: indicate.unwrap_or_default(),
            on_read,
            on_write,
            default_value,
            descriptors: Vec::new(),
            doc_string: String::new(),
        })
    }
}

impl DescriptorArgs {
    pub fn parse(attribute: &syn::Attribute) -> Result<Self> {
        let mut uuid: Option<Uuid> = None;
        let mut read: Option<bool> = None;
        let mut write: Option<bool> = None;
        let mut notify: Option<bool> = None;
        let mut default_value: Option<syn::Expr> = None;
        let mut write_without_response: Option<bool> = None;
        attribute.parse_nested_meta(|meta| {
            match meta.path.get_ident().ok_or(Error::custom("no ident"))?.to_string().as_str() {
                "uuid" => {
                    if uuid.is_some() {
                        return Err(meta.error("'uuid' should not be specified more than once"))
                    }
                    let value = meta
                    .value()
                    .map_err(|_| Error::custom("uuid must be followed by '= [data]'.  i.e. uuid = '0x2A37'".to_string()))?;
                    let uuid_string: LitStr = value.parse()?;
                    uuid = Some(Uuid::from_string(uuid_string.value().as_str())?);
                },
                "read" => check_multi(&mut read, "read", &meta)?,
                "write" => check_multi(&mut write, "write", &meta)?,
                "write_without_response" => check_multi(&mut write_without_response, "write_without_response", &meta)?,
                "notify" => check_multi(&mut notify, "notify", &meta)?,
                "value" => {
                    if default_value.is_some() {
                        return Err(meta.error("'value' should not be specified more than once"))
                    }
                    let value = meta
                    .value()
                    .map_err(|_| Error::custom("value must be followed by '= [data]'.  i.e. value = 'hello'".to_string()))?;
                    default_value = Some(value.parse()?); // type checking done in construct_characteristic_static
                },
                "default_value" => return Err(meta.error("use 'value' for default value")),
                other => return Err(
                    meta.error(
                        format!(
                            "Unsupported descriptor property: '{other}'.\nSupported properties are: uuid, read, write, write_without_response, notify, value"
                        ))),
            };
            Ok(())
        })?;
        Ok(Self {
            uuid: uuid.ok_or(Error::custom("Descriptor must have a UUID"))?,
            read: read.unwrap_or_default(),
            write: write.unwrap_or_default(),
            write_without_response: write_without_response.unwrap_or_default(),
            notify: notify.unwrap_or_default(),
            default_value,
        })
    }
}
