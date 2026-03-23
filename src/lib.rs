extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse::Parser, punctuated::Punctuated, Expr, Token};

#[proc_macro]
pub fn maybe_log(stream: TokenStream) -> TokenStream {
    let parser = Punctuated::<Expr, Token![,]>::parse_separated_nonempty;
    let parsed = parser.parse(stream).unwrap();

    let mut tsi = parsed.into_iter();
    let logger_name = tsi.next();
    let logger_name = logger_name.unwrap();

    let level = tsi.next();
    let level = level.unwrap();

    let rest: Punctuated<Expr, Token![,]> = tsi.collect();
    let rewritten =
        quote! { #logger_name . as_ref().and_then(|__x| { #level !(__x, #rest ); Some(()) }) };
    TokenStream::from(rewritten)
}

#[proc_macro]
pub fn display_parsed_tlv(stream: TokenStream) -> TokenStream {
    let parser = Punctuated::<Expr, Token![,]>::parse_separated_nonempty;
    let parsed = parser.parse(stream).unwrap();

    let mut tsi = parsed.into_iter();
    let tlv_type = tsi.next();
    let tlv_description = tsi.next();
    let tlv_name = tsi.next();
    let writer = tsi.next();
    let rewritten = quote! { match #tlv_type::try_from( #tlv_name ) {
            Ok(parsed_tlv) => write!(#writer, concat!(" body: ",#tlv_description, " TLV: {:x?}"), parsed_tlv),
            Err(e) => write!(#writer, concat!(" body: ", #tlv_description," TLV (failed to parse: {}): {:x?}"), e, #tlv_name.value),
        }
    };
    TokenStream::from(rewritten)
}
