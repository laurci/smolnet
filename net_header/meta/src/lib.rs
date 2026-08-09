use darling::{FromDeriveInput, FromField, ast::Data};
use proc_macro_error::{abort, proc_macro_error};
use proc_macro2::Span;
use quote::{ToTokens, quote};
use syn::{DeriveInput, Lit, TypeArray, TypePath, parse_macro_input};

#[derive(FromDeriveInput)]
#[darling(attributes(header), supports(struct_named))]
struct NetHeaderOpts {
    ident: syn::Ident,
    data: Data<(), NetHeaderField>,
    name: String,
}

#[derive(Debug, FromField)]
#[darling(attributes(header))]
struct NetHeaderField {
    ident: Option<syn::Ident>,
    ty: syn::Type,

    checksum: Option<bool>,
}

#[derive(Default)]
struct FieldGeneratorState {
    offset: usize,
}

fn extract_type_path_numeric_info(tp: &TypePath) -> Option<NumericInfo> {
    match tp.path.get_ident() {
        Some(ident) => {
            if let Some(info) = NumericInfo::from_str(&ident.to_string()) {
                return Some(info);
            };

            None
        }
        _ => None,
    }
}

fn extract_expr_const_int(exp: &syn::Expr) -> Option<usize> {
    match exp {
        syn::Expr::Lit(syn::ExprLit {
            lit: Lit::Int(lit), ..
        }) => {
            if let Ok(n) = lit.base10_parse() {
                return Some(n);
            }
            None
        }
        _ => None,
    }
}

#[derive(Eq, PartialEq)]
struct NumericInfo {
    pub signed: bool,
    pub bytes: usize,
}

impl NumericInfo {
    pub fn from_str(input: &str) -> Option<NumericInfo> {
        let first_char = input.chars().next();

        let signed = match first_char {
            Some('u') => false,
            Some('i') => true,
            _ => return None,
        };

        if let Ok(size) = input[1..].parse::<usize>()
            && size % 8 == 0
        {
            return Some(NumericInfo {
                signed,
                bytes: size / 8,
            });
        }

        None
    }

    pub fn to_string(&self) -> String {
        let size = self.bytes * 8;

        if self.signed {
            format!("i{}", size)
        } else {
            format!("u{}", size)
        }
    }
}

enum HeaderFieldInfo {
    Slice { size: usize },
    Numeric(NumericInfo),
    Checksum,
}

fn parse_header_field_info(field: &NetHeaderField) -> Option<HeaderFieldInfo> {
    match &field.ty {
        syn::Type::Array(TypeArray { elem, len, .. }) => {
            if let syn::Type::Path(tp) = elem.as_ref()
                && extract_type_path_numeric_info(tp)
                    == Some(NumericInfo {
                        signed: false,
                        bytes: 1,
                    })
            {
                if let Some(len) = extract_expr_const_int(&len) {
                    return Some(HeaderFieldInfo::Slice { size: len });
                }

                return None;
            }

            None
        }
        syn::Type::Path(tp) => {
            let Some(info) = extract_type_path_numeric_info(tp) else {
                return None;
            };

            if field.checksum == Some(true) {
                if info
                    != (NumericInfo {
                        bytes: 2,
                        signed: false,
                    })
                {
                    return None;
                }

                return Some(HeaderFieldInfo::Checksum);
            }

            Some(HeaderFieldInfo::Numeric(info))
        }
        _ => None,
    }
}

fn gen_decoder_for_field(
    state: &mut FieldGeneratorState,
    opts: &NetHeaderOpts,
    field: &NetHeaderField,
) -> proc_macro2::TokenStream {
    let Some(field_ident) = &field.ident else {
        abort!(field.ident, "only named fields are supported");
    };

    let Some(field_info) = parse_header_field_info(field) else {
        abort! { field.ident,
                "unsupported field type {}", field.ty.to_token_stream().to_string();
                note = "headers only support numeric types (u8, i16, u32, ..) and fixed size byte slices ([u8; N])"
        };
    };

    let field_name = format!("{}.{}", opts.name, field_ident.to_string());
    let offset = state.offset;

    let (impl_, advance) = match field_info {
        HeaderFieldInfo::Slice { size } => (
            quote! {
                let #field_ident = ::net_header::parse::read_field_slice(#field_name, bytes, #offset)?;
            },
            size,
        ),
        HeaderFieldInfo::Numeric(info) => {
            let parse_method_name = syn::Ident::new(
                &format!("read_field_{}", info.to_string()),
                Span::call_site(),
            );

            (
                quote! {
                    let #field_ident = ::net_header::parse::#parse_method_name(#field_name, bytes, #offset)?;
                },
                info.bytes,
            )
        }
        HeaderFieldInfo::Checksum => (
            quote! {
                let #field_ident = ::net_header::parse::read_field_u16(#field_name, bytes, #offset)?;
            },
            2,
        ),
    };

    state.offset += advance;

    impl_.into()
}

fn gen_encoder_for_field(
    state: &mut FieldGeneratorState,
    opts: &NetHeaderOpts,
    field: &NetHeaderField,
) -> proc_macro2::TokenStream {
    let Some(field_ident) = &field.ident else {
        abort!(field.ident, "only named fields are supported");
    };

    let Some(field_info) = parse_header_field_info(field) else {
        abort! { field.ident,
                "unsupported field type {}", field.ty.to_token_stream().to_string();
                note = "headers only support numeric types (u8, i16, u32, ..) and fixed size byte slices ([u8; N])"
        };
    };

    let field_name = format!("{}.{}", opts.name, field_ident.to_string());
    let offset = state.offset;

    let (impl_, advance) = match field_info {
        HeaderFieldInfo::Slice { size } => (
            quote! {
                let offset = ::net_header::write::write_field_slice(self.#field_ident, #field_name, bytes, #offset);
            },
            size,
        ),
        HeaderFieldInfo::Numeric(info) => {
            let write_method_name = syn::Ident::new(
                &format!("write_field_{}", info.to_string()),
                Span::call_site(),
            );

            (
                quote! {
                    let offset = ::net_header::write::#write_method_name(self.#field_ident, #field_name, bytes, #offset);
                },
                info.bytes,
            )
        }
        HeaderFieldInfo::Checksum => (
            quote! {
                let offset = ::net_header::write::write_field_u16(self.#field_ident, #field_name, bytes, #offset);
            },
            2,
        ),
    };

    state.offset += advance;

    impl_.into()
}

fn gen_fold_for_field(opts: &NetHeaderOpts, field: &NetHeaderField) -> proc_macro2::TokenStream {
    let Some(field_ident) = &field.ident else {
        abort!(field.ident, "only named fields are supported");
    };

    let Some(field_info) = parse_header_field_info(field) else {
        abort! { field.ident,
                "unsupported field type {}", field.ty.to_token_stream().to_string();
                note = "headers only support numeric types (u8, i16, u32, ..) and fixed size byte slices ([u8; N])"
        };
    };

    let _ = opts;

    match field_info {
        HeaderFieldInfo::Slice { .. } => quote! {
            checksum.push(&self.#field_ident);
        },
        HeaderFieldInfo::Numeric(_) => quote! {
            checksum.push(&self.#field_ident.to_be_bytes());
        },
        HeaderFieldInfo::Checksum => quote! {
            checksum.push_u16(0);
        },
    }
}

#[proc_macro_derive(NetHeader, attributes(header))]
#[proc_macro_error]
pub fn net_header_derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let opts = match NetHeaderOpts::from_derive_input(&input) {
        Ok(v) => v,
        Err(e) => {
            abort! {
                input,
                "failed to parse net_header input";
                note = "{}", e
            };
        }
    };

    let ident = &opts.ident;

    let fields = opts
        .data
        .as_ref()
        .take_struct()
        .expect("Should never be enum")
        .fields;

    let mut decoder_gen_state = FieldGeneratorState::default();
    let mut encoder_gen_state = FieldGeneratorState::default();

    let mut struct_assembly_fields = vec![];
    let mut decoder_field_impls = vec![];
    let mut encoder_field_impls = vec![];
    let mut fold_field_impls = vec![];

    for field in fields {
        struct_assembly_fields.push(field.ident.clone().unwrap());
        decoder_field_impls.push(gen_decoder_for_field(&mut decoder_gen_state, &opts, field));
        encoder_field_impls.push(gen_encoder_for_field(&mut encoder_gen_state, &opts, field));
        fold_field_impls.push(gen_fold_for_field(&opts, field));
    }

    let size = encoder_gen_state.offset;

    let impl_ = quote! {
        impl ::net_header::NetHeader for #ident {
            const SIZE: usize = #size;

            fn from_bytes(bytes: &[u8]) -> Result<Self, ::net_header::parse::HeaderParseError> {
                #( #decoder_field_impls )*

                let header = #ident {
                    #( #struct_assembly_fields ),*
                };

                Ok(header)
            }

            fn write(&self, bytes: &mut [u8]) -> usize {
                #( #encoder_field_impls )*

                offset
            }

            fn fold(&self, checksum: &mut ::net_header::Checksum) {
                #( #fold_field_impls )*
            }
        }
    };

    impl_.into()
}
