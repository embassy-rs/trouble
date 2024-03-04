extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, parse_quote, Data, DeriveInput, Fields};

#[proc_macro_derive(Codec)]
pub fn derive_codec_fn(item: TokenStream) -> TokenStream {
    let ast = syn::parse_macro_input!(item as DeriveInput);
    let name = &ast.ident;

    if let Data::Struct(data_struct) = &ast.data {
        match &data_struct.fields {
            Fields::Named(fields) => {
                let mut offsets = Vec::new();
                let mut field_constants: Vec<_> = Vec::new();
                let mut field_encoders: Vec<_> = Vec::new();
                let mut field_decoders: Vec<_> = Vec::new();

                for f in fields.named.iter() {
                    let fname = &f.ident;
                    let ftype = &f.ty;
                    let fsize = quote! { <#ftype as FixedSize>::SIZE };

                    let offset: syn::Expr = if offsets.is_empty() {
                        parse_quote! {
                            0
                        }
                    } else {
                        parse_quote! {
                            #(#offsets)+*
                        }
                    };
                    offsets.push(fsize.clone());

                    field_encoders.push(quote! {
                        if #offset + #fsize < dest.len() {
                            self.#fname.encode(&mut dest[#offset..#offset + #fsize])?;
                        } else {
                            return Err(Error::InsufficientSpace);
                        }
                    });

                    field_decoders.push(quote! {
                        #fname : if #offset + #fsize < src.len() {
                            <#ftype as Decode>::decode(&src[#offset..#offset + #fsize])?
                        } else {
                            return Err(Error::InsufficientSpace);
                        },
                    });

                    field_constants.push(quote! {
                        <#ftype as FixedSize>::SIZE
                    });
                }

                quote! {

                    impl FixedSize for #name {
                        const SIZE: usize = #(#field_constants)+*;
                    }

                    impl Encode for #name {
                        fn encode(&self, dest: &mut [u8]) -> Result<(), Error> {
                            #(#field_encoders)*;
                            Ok(())
                        }
                    }

                    impl Decode for #name {
                        fn decode(src: &[u8]) -> Result<Self, Error> {
                            Ok(Self {
                                #(#field_decoders)*
                            })
                        }
                    }
                }
            }
            _ => {
                panic!("only standard structs please");
            }
        }
        .into()
    } else {
        panic!("Codec macro can only be used with structs");
    }
}
