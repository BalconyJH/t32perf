//! Streaming host-side analysis for normalized t32perf observations.
//!
//! [`Analyzer`] consumes one observation at a time. It keeps execution stacks
//! per context and schedules those contexts through per-core task and nested
//! interrupt state, so wall time and virtual CPU time remain separate.

#![deny(missing_docs)]

mod analyzer;
mod compare;
mod derived_stream;
mod health_policy;
mod histogram;
mod stack_sampling;
mod types;

pub use analyzer::*;
pub use compare::*;
pub use derived_stream::*;
pub use health_policy::*;
pub use histogram::*;
pub use stack_sampling::*;
pub use types::*;
