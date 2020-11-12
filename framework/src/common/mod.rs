//! Common utils for NetBricks.
#[doc(hidden)]
mod errors;
pub use self::errors::*;

/// Null metadata associated with packets initially.
#[derive(Debug)]
pub struct EmptyMetadata;

/// Print error util function.
pub fn print_error(e: &Error) {
    println!("Error: {}", e);
    for e in e.iter().skip(1) {
        println!("Cause: {}", e);
    }
    if let Some(backtrace) = e.backtrace() {
        println!("Backtrace: {:?}", backtrace);
    }
}
