//! Common scalar and extensibility types.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A timestamp in signed nanoseconds relative to the start of its session.
///
/// Signed storage permits a capture adapter to retain bounded pre-trigger
/// observations without changing the session time origin.
pub type TimestampNs = i64;

/// A nonnegative duration measured in nanoseconds.
pub type DurationNs = u64;

/// Deterministically ordered extension data used for arguments and evidence.
pub type Properties = BTreeMap<String, Value>;

/// Describes how directly a value is supported by the captured trace.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Quality {
    /// The trace directly and completely determines the value.
    Exact,
    /// The value is reconstructed from incomplete but deterministic evidence.
    Inferred,
    /// The value is an estimate obtained from statistical samples.
    Statistical,
}
