use darling::FromMeta;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote, quote_spanned};
use syn::meta::ParseNestedMeta;
use syn::parse::Result;
use syn::spanned::Spanned;
use syn::{Ident, LitStr};
use crate::uuid::Uuid;
use crate::characteristic::Characteristic;

#[derive(Debug, Default)]
pub(crate) struct ServiceArgs {
    pub uuid: Option<Uuid>,
}

impl ServiceArgs {
    pub fn parse(&mut self, meta: ParseNestedMeta) -> Result<()> {
        if meta.path.is_ident("uuid") {
            let uuid_string: LitStr = meta.value()?.parse()?;
            self.uuid = Some(Uuid::from_string(uuid_string.value().as_str())?);
            Ok(())
        } else {
            Err(meta.error("Unsupported service property, 'uuid' is the only supported property"))
        }
    }
}

pub(crate) struct ServiceBuilder {
    service_props: syn::ItemStruct,
    name: Ident,
    uuid: Uuid,
    event_enum_name: Ident,
    code_impl: TokenStream2,
    code_build_chars: TokenStream2,
    code_struct_init: TokenStream2,
    code_on_write: TokenStream2,
    code_event_enum: TokenStream2,
    code_fields: TokenStream2,
}

impl ServiceBuilder {
    pub fn new(props: syn::ItemStruct, uuid: Uuid) -> Self {
        let name = props.ident.clone();
        Self {
            event_enum_name: format_ident!("{}Event", name),
            name,
            uuid,
            service_props: props,
            code_impl: TokenStream2::new(),
            code_build_chars: TokenStream2::new(),
            code_struct_init: TokenStream2::new(),
            code_on_write: TokenStream2::new(),
            code_event_enum: TokenStream2::new(),
            code_fields: TokenStream2::new(),
        }
    }

    pub fn build(self) -> TokenStream2 {
        let service_props = self.service_props;
        let visibility = service_props.vis.clone();
        let struct_name = self.name;
        let code_struct_init = self.code_struct_init;
        let code_impl = self.code_impl;
        let event_enum_name = self.event_enum_name;
        let code_event_enum = self.code_event_enum;
        let code_build_chars = self.code_build_chars;
        let fields = self.code_fields;
        let uuid = self.uuid;
        let result = quote! {
            #visibility struct #struct_name {
                handle: AttributeHandle,
            #fields
            }

            #[allow(unused)]
            impl #struct_name {
                #visibility fn new<M, const MAX_ATTRIBUTES: usize>(table: &mut AttributeTable<'_, M, MAX_ATTRIBUTES>) -> Result<Self, Error>
                where
                    M: embassy_sync::blocking_mutex::raw::RawMutex,
                {
                    let mut service = table.add_service(Service::new(#uuid));
                    #code_build_chars

                    Ok(Self {
                        handle: service.build(),
                        #code_struct_init
                    })
                }
                #code_impl
            }
            #[allow(unused)]
            #visibility enum #event_enum_name {
                #code_event_enum
            }
        };
        result
    }

    pub fn re_add_fields(mut self, mut fields: Vec<syn::Field>, characteristics: &Vec<Characteristic>) -> Self {
        let event_enum_name = self.event_enum_name.clone();
        for ch in characteristics {
            let name_pascal = inflector::cases::pascalcase::to_pascal_case(&ch.name);
            let name_screaming = format_ident!(
                "{}",
                inflector::cases::screamingsnakecase::to_screaming_snake_case(&ch.name)
            );
            let char_name = format_ident!("{}", ch.name);
            let cccd_handle = format_ident!("{}_cccd_handle", ch.name);
            let get_fn = format_ident!("{}_get", ch.name);
            let set_fn = format_ident!("{}_set", ch.name);
            let notify_fn = format_ident!("{}_notify", ch.name);
            let indicate_fn = format_ident!("{}_indicate", ch.name);
            let fn_vis = ch.vis.clone();

            let uuid = ch.args.uuid.clone();
            let read = ch.args.read;
            let write = ch.args.write;
            let write_without_response = ch.args.write_without_response;
            let notify = ch.args.notify;
            let indicate = ch.args.indicate;
            let ty = &ch.ty;
            let mut properties = Vec::new();
            parse_property_into_list(read, quote! {CharacteristicProp::Read}, &mut properties);
            parse_property_into_list(write, quote! {CharacteristicProp::Write}, &mut properties);
            parse_property_into_list(
                write_without_response,
                quote! {CharacteristicProp::WriteWithoutResponse},
                &mut properties,
            );
            parse_property_into_list(notify, quote! {CharacteristicProp:: Notify}, &mut properties);
            parse_property_into_list(indicate, quote! {CharacteristicProp::Indicate}, &mut properties);
            // let ty = match &ch.ty {
            //     Type::Path(path) => &path.path,
            //     _ => panic!("unexpected type {:#?}", ch.ty),
            // };
            // let ty_as_val = quote!(<#ty as #trouble::Type>);
            // let value = match &ch.args.value {
            //     Some(v) => quote! { #v },
            //     None => quote! { [123u8; #ty_as_val::MIN_SIZE] },
            // };
            // panic!("value {:#?}", value);

            // add fields for each characteristic value handle
            fields.push(syn::Field {
                ident: Some(char_name.clone()),
                ty: syn::Type::Verbatim(quote!(Characteristic)),
                attrs: Vec::new(),
                colon_token: Default::default(),
                vis: syn::Visibility::Inherited,
                mutability: syn::FieldMutability::None,
            });

            self.code_build_chars.extend(quote_spanned! {ch.span=>
                let #char_name = {
                    static #name_screaming: static_cell::StaticCell<[u8; size_of::<#ty>()]> = static_cell::StaticCell::new();
                    let store = #name_screaming.init([0; size_of::<#ty>()]);
                    let builder = service.add_characteristic(#uuid, &[#(#properties),*], store);

                    // TODO: Descriptors

                    builder.build()
                };
            });

            self.code_struct_init.extend(quote_spanned!(ch.span=>
                #char_name,
            ));

            if notify {
                self.code_impl.extend(quote_spanned!(ch.span=>
                    #fn_vis fn #notify_fn(
                        &self,
                        conn: &Connection,
                        val: &#ty,
                    ) -> Result<(), Error> {
                        // let buf = #ty_as_val::to_gatt(val);
                        // #ble::gatt_server::notify_value(conn, self.#value_handle, buf)
                        unimplemented!("notify {val:?}")
                    }
                ));

                if !indicate {
                    let case_cccd_write = format_ident!("{}CccdWrite", name_pascal);

                    self.code_event_enum.extend(quote_spanned!(ch.span=>
                        #case_cccd_write{notifications: bool},
                    ));
                    self.code_on_write.extend(quote_spanned!(ch.span=>
                        if handle == self.#cccd_handle && !data.is_empty() {
                            match data[0] & 0x01 {
                                0x00 => return Some(#event_enum_name::#case_cccd_write{notifications: false}),
                                0x01 => return Some(#event_enum_name::#case_cccd_write{notifications: true}),
                                _ => {},
                            }
                        }
                    ));
                }
            }

            if indicate {
                self.code_impl.extend(quote_spanned!(ch.span=>
                    #fn_vis fn #indicate_fn(
                        &self,
                        conn: &Connection,
                        val: &#ty,
                    ) -> Result<(), Error> {
                        // let buf = #ty_as_val::to_gatt(val);
                        // #ble::gatt_server::indicate_value(conn, self.#value_handle, buf)
                        unimplemented!("indicate {val:?}")
                    }
                ));

                if !notify {
                    let case_cccd_write = format_ident!("{}CccdWrite", name_pascal);

                    self.code_event_enum.extend(quote_spanned!(ch.span=>
                        #case_cccd_write{indications: bool},
                    ));
                    self.code_on_write.extend(quote_spanned!(ch.span=>
                        if handle == self.#cccd_handle && !data.is_empty() {
                            match data[0] & 0x02 {
                                0x00 => return Some(#event_enum_name::#case_cccd_write{indications: false}),
                                0x02 => return Some(#event_enum_name::#case_cccd_write{indications: true}),
                                _ => {},
                            }
                        }
                    ));
                }
            }

            if indicate && notify {
                let case_cccd_write = format_ident!("{}CccdWrite", name_pascal);

                self.code_event_enum.extend(quote_spanned!(ch.span=>
                    #case_cccd_write{indications: bool, notifications: bool},
                ));
                self.code_on_write.extend(quote_spanned!(ch.span=>
                if handle == self.#cccd_handle && !data.is_empty() {
                    match data[0] & 0x03 {
                        0x00 => return Some(#event_enum_name::#case_cccd_write{indications: false, notifications: false}),
                        0x01 => return Some(#event_enum_name::#case_cccd_write{indications: false, notifications: true}),
                        0x02 => return Some(#event_enum_name::#case_cccd_write{indications: true, notifications: false}),
                        0x03 => return Some(#event_enum_name::#case_cccd_write{indications: true, notifications: true}),
                        _ => {},
                    }
                }
            ));
            }
        }
        for field in fields {
            let ident = field.ident.clone();
            let ty = field.ty.clone();
            self.code_fields.extend(quote_spanned! {field.span()=>
                #ident: #ty,
            })
        }
        self
    }
}

fn parse_property_into_list(property: bool, variant: TokenStream2, properties: &mut Vec<TokenStream2>) {
    if property {
        properties.push(variant);
    }
}
