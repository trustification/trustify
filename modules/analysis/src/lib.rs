pub mod endpoints;
pub mod error;
pub mod service;
pub use error::Error;
pub mod model;

#[cfg(test)]
pub mod test;
