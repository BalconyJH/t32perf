//! Shared observation-order validation.

use std::collections::BTreeMap;

use t32perf_model::{Observation, TimestampNs};
use thiserror::Error;

/// A source or global observation ordering violation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ObservationOrderError {
    /// A source sequence number did not increase strictly.
    #[error(
        "source `{source_id}` sequence {actual} does not follow sequence {previous} monotonically"
    )]
    SourceSequence {
        /// Source containing the violation.
        source_id: String,
        /// Previous sequence number.
        previous: u64,
        /// Rejected sequence number.
        actual: u64,
    },
    /// A timestamp moved backward within one source.
    #[error("source `{source_id}` timestamp {actual} precedes timestamp {previous}")]
    SourceTimestamp {
        /// Source containing the violation.
        source_id: String,
        /// Previous source timestamp.
        previous: TimestampNs,
        /// Rejected timestamp.
        actual: TimestampNs,
    },
    /// A canonical merged stream moved backward globally.
    #[error("global timestamp {actual} precedes timestamp {previous}")]
    GlobalTimestamp {
        /// Previous global timestamp.
        previous: TimestampNs,
        /// Rejected timestamp.
        actual: TimestampNs,
    },
}

#[derive(Debug, Default)]
pub(crate) struct ObservationOrderValidator {
    source_sequences: BTreeMap<String, u64>,
    source_timestamps: BTreeMap<String, TimestampNs>,
    global_timestamp: Option<TimestampNs>,
}

impl ObservationOrderValidator {
    pub(crate) fn observe(
        &mut self,
        observation: &Observation,
    ) -> Result<(), ObservationOrderError> {
        if let Some(previous) = self
            .source_sequences
            .insert(observation.source_id.clone(), observation.source_seq)
            && observation.source_seq <= previous
        {
            return Err(ObservationOrderError::SourceSequence {
                source_id: observation.source_id.clone(),
                previous,
                actual: observation.source_seq,
            });
        }

        let timestamp = observation.ts_ns();
        if let Some(previous) = self
            .source_timestamps
            .insert(observation.source_id.clone(), timestamp)
            && timestamp < previous
        {
            return Err(ObservationOrderError::SourceTimestamp {
                source_id: observation.source_id.clone(),
                previous,
                actual: timestamp,
            });
        }

        if let Some(previous) = self.global_timestamp
            && timestamp < previous
        {
            return Err(ObservationOrderError::GlobalTimestamp {
                previous,
                actual: timestamp,
            });
        }
        self.global_timestamp = Some(timestamp);
        Ok(())
    }
}
