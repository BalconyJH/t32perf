//! Versioned data contracts shared by every t32perf component.
//!
//! The crate deliberately separates source observations from derived analysis
//! results. Observation producers therefore do not need to know how the host
//! reconstructs spans, computes health, or aggregates hotspots.

#![deny(missing_docs)]

mod analysis;
mod capture;
mod common;
mod derived;
mod health;
mod histogram;
mod observation;
mod perf_surface;
mod performance_run;
mod report;
mod resource;
mod sampling_control;
mod schema;
mod session;
mod stack_sampling;
pub mod strict_json;

pub use analysis::*;
pub use capture::*;
pub use common::*;
pub use derived::*;
pub use health::*;
pub use histogram::*;
pub use observation::*;
pub use perf_surface::*;
pub use performance_run::*;
pub use report::*;
pub use resource::*;
pub use sampling_control::*;
pub use schema::*;
pub use session::*;
pub use stack_sampling::*;
