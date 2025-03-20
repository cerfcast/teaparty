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
