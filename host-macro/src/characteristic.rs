use crate::uuid::Uuid;
use darling::Error;
use darling::FromMeta;
use proc_macro2::Span;
use syn::parse::Result;
use syn::spanned::Spanned as _;
use syn::Field;
use syn::LitStr;

#[derive(Debug)]
pub(crate) struct Characteristic {
    name: String,
    ty: syn::Type,
    args: CharacteristicArgs,
    span: Span,
    vis: syn::Visibility,
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
    uuid: Uuid,
    /// The value of the descriptor.
    #[darling(default)]
    value: Option<syn::Expr>,
}

/// Characteristic attribute arguments
#[derive(Debug, FromMeta, Default)]
pub(crate) struct CharacteristicArgs {
    /// The UUID of the characteristic.
    uuid: String,
    /// If true, the characteristic can be read.
    #[darling(default)]
    read: bool,
    /// If true, the characteristic can be written.
    #[darling(default)]
    write: bool,
    /// If true, the characteristic can be written without a response.
    #[darling(default)]
    write_without_response: bool,
    /// If true, the characteristic can send notifications.
    #[darling(default)]
    notify: bool,
    /// If true, the characteristic can send indications.
    #[darling(default)]
    indicate: bool,
    /// The initial value of the characteristic.
    /// This is optional and can be used to set the initial value of the characteristic.
    #[darling(default)]
    value: Option<syn::Expr>,
    // /// Descriptors for the characteristic.
    // /// Descriptors are optional and can be used to add additional metadata to the characteristic.
    #[darling(default, multiple)]
    descriptor: Vec<DescriptorArgs>,
}

impl CharacteristicArgs {
    /// Parse the arguments of a characteristic attribute
    pub fn parse(attribute: &syn::Attribute) -> Result<Self> {
        let mut args = CharacteristicArgs::default();
        attribute.parse_nested_meta(|meta| {
            match meta.path.get_ident().ok_or(Error::custom("no ident"))?.to_string().as_str() {
                "uuid" => {
                    let value = meta
                    .value()
                    .map_err(|_| Error::custom(format!("uuid must be followed by '= [data]'.  i.e. uuid = '0x2A37'")))?;
                    args.uuid = value.parse::<LitStr>()?.value();
                },
                "read" => args.read = true,
                "write" => args.write = true,
                "write_without_response" => args.write_without_response = true,
                "notify" => args.notify = true,
                "indicate" => args.indicate = true,
                "value" => {
                    let value = meta
                    .value()
                    .map_err(|_| Error::custom(format!("value must be followed by '= [data]'.  i.e. value = 'hello'")))?;
                    args.value = Some(value.parse()?);
                },
                other => return Err(
                    meta.error(
                        format!(
                            "Unsupported characteristic property: '{other}'.\nSupported properties are: uuid, read, write, write_without_response, notify, indicate, value"
                        ))),
            };
            Ok(())
        })?;
        Ok(args)
    }
}
