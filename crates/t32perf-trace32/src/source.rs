//! Synchronous normalized-observation source abstraction.

use t32perf_model::{Observation, ObservationDictionary};
use thiserror::Error;

use crate::{ClockError, CsvAdapterError, MergeError, NdjsonError, TraceExportError, WireError};

/// Static metadata for one synchronous observation source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDescriptor {
    /// Stable source instance identifier.
    pub source_id: String,
    /// Clock domain in which normalized timestamps are ordered.
    pub clock_domain: String,
}

impl SourceDescriptor {
    /// Creates a source descriptor.
    #[must_use]
    pub fn new(source_id: impl Into<String>, clock_domain: impl Into<String>) -> Self {
        Self {
            source_id: source_id.into(),
            clock_domain: clock_domain.into(),
        }
    }
}

/// One observation plus an optional cross-source ordering key.
#[derive(Debug, Clone, PartialEq)]
pub struct OrderedObservation {
    /// Normalized observation.
    pub observation: Observation,
    /// Explicit order within a shared timestamp tick.
    pub order_key: Option<u64>,
}

impl OrderedObservation {
    /// Creates an observation with no cross-source tie-break key.
    #[must_use]
    pub fn unordered(observation: Observation) -> Self {
        Self {
            observation,
            order_key: None,
        }
    }

    /// Creates an observation with an explicit cross-source tie-break key.
    #[must_use]
    pub fn ordered(observation: Observation, order_key: u64) -> Self {
        Self {
            observation,
            order_key: Some(order_key),
        }
    }
}

/// An observation-source failure.
#[derive(Debug, Error)]
pub enum SourceError {
    /// Canonical NDJSON failed.
    #[error(transparent)]
    Ndjson(#[from] NdjsonError),
    /// Explicitly mapped CSV failed.
    #[error(transparent)]
    Csv(#[from] CsvAdapterError),
    /// C SDK wire decoding failed.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// Timestamp conversion failed.
    #[error(transparent)]
    Clock(#[from] ClockError),
    /// Multi-source merge failed.
    #[error(transparent)]
    Merge(#[from] MergeError),
    /// A versioned TRACE32 text export failed strict decoding.
    #[error(transparent)]
    TraceExport(#[from] TraceExportError),
    /// A source-specific invariant failed.
    #[error("source invariant failed: {message}")]
    Invariant {
        /// Stable failure description.
        message: String,
    },
}

/// A pull-based, synchronous normalized-observation producer.
pub trait ObservationSource {
    /// Returns static metadata for this source instance.
    fn descriptor(&self) -> &SourceDescriptor;

    /// Returns the source dictionary when it is carried by the input format.
    fn dictionary(&self) -> Option<&ObservationDictionary> {
        None
    }

    /// Produces the next observation, or `None` at clean EOF.
    fn next_observation(&mut self) -> Result<Option<OrderedObservation>, SourceError>;
}
