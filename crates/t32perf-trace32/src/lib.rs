//! Streaming TRACE32 capture adapters and normalized observation transport.
//!
//! The crate keeps target-specific TRACE32 configuration outside the generic
//! parser boundary. Canonical NDJSON, explicitly mapped CSV, build-qualified
//! TRACE32 ASCII/TASKEVENTS text exports, the T32Perf C SDK wire format,
//! synthetic observations, and deterministic source merging are implemented
//! without guessing undocumented columns or commands.

#![deny(missing_docs)]

mod adapter;
mod c_wire;
mod clock;
mod controller;
mod csv_adapter;
mod driver;
mod elf_mapping;
mod firmware_image;
mod input;
mod merge;
mod ndjson;
mod order;
mod qualification;
mod qualified_adapter;
mod resource_schema;
mod resource_text;
mod source;
mod stack_usage;
mod static_ram;
mod synthetic;
mod t32mcp_protocol;
mod target_adapter;
mod trace_export;

pub use adapter::*;
pub use c_wire::*;
pub use clock::*;
pub use controller::*;
pub use csv_adapter::*;
pub use driver::*;
pub use elf_mapping::*;
pub use firmware_image::*;
pub use input::*;
pub use merge::*;
pub use ndjson::*;
pub use order::*;
pub use qualification::*;
pub use qualified_adapter::*;
pub use resource_schema::*;
pub use resource_text::*;
pub use source::*;
pub use stack_usage::*;
pub use static_ram::*;
pub use synthetic::*;
pub use t32mcp_protocol::*;
pub use target_adapter::*;
pub use trace_export::*;
