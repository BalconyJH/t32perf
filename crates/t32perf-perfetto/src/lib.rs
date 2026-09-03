//! Streaming Chrome Trace JSON export for Perfetto.
//!
//! The exporter writes each trace event directly to a synchronous [`std::io::Write`]
//! sink. It retains dictionaries, emitted track metadata, and currently open custom
//! spans, but never constructs an in-memory vector of trace events.

#![deny(missing_docs)]

mod atomic;
mod error;
mod writer;

pub use atomic::export_atomic;
pub use error::ExportError;
pub use writer::{ChromeTraceWriter, TraceConfig, write_trace};
