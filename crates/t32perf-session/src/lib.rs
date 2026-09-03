//! Durable session lifecycle and artifact security for T32Perf.
//!
//! The crate owns the filesystem trust boundary. Callers work with validated
//! session identifiers and model-level [`t32perf_model::ArtifactPath`] values;
//! absolute paths and arbitrary filesystem reads are never accepted as
//! artifact identifiers.

#![deny(missing_docs)]

mod artifact;
mod error;
mod path;
mod session;

pub use artifact::*;
pub use error::*;
pub use path::verify_opened_plain_file_identity;
pub use session::*;
