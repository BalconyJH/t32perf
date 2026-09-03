//! Deterministic k-way merge for already sorted sources.

use std::collections::{BTreeMap, BTreeSet};

use t32perf_model::TimestampNs;
use thiserror::Error;

use crate::{
    ObservationOrderValidator, ObservationSource, OrderedObservation, SourceDescriptor, SourceError,
};

#[derive(Debug, Default)]
struct MergeSourceState {
    order: ObservationOrderValidator,
    last_timestamp: Option<TimestampNs>,
    last_order_key: Option<u64>,
}

/// A deterministic merge failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MergeError {
    /// No common timeline exists for the supplied source domains.
    #[error("source `{source_id}` uses clock domain `{actual}` instead of `{expected}`")]
    ClockDomainMismatch {
        /// Source with the mismatched domain.
        source_id: String,
        /// Required domain.
        expected: String,
        /// Actual domain.
        actual: String,
    },
    /// Source descriptors must be unique within one merge.
    #[error("duplicate merge source identifier `{source_id}`")]
    DuplicateSource {
        /// Duplicate source identifier.
        source_id: String,
    },
    /// One source was not sorted by timestamp.
    #[error("source `{source_id}` timestamp {actual} precedes {previous}")]
    SourceOutOfOrder {
        /// Source containing the violation.
        source_id: String,
        /// Previous source timestamp.
        previous: TimestampNs,
        /// Rejected timestamp.
        actual: TimestampNs,
    },
    /// A source sequence did not increase strictly.
    #[error("source `{source_id}` sequence {actual} does not follow {previous} monotonically")]
    SourceSequence {
        /// Source containing the violation.
        source_id: String,
        /// Previous sequence.
        previous: u64,
        /// Rejected sequence.
        actual: u64,
    },
    /// Explicit order keys within one source did not increase at the same tick.
    #[error(
        "source `{source_id}` order key {actual} does not follow {previous} at timestamp {timestamp}"
    )]
    SourceOrderKey {
        /// Source containing the violation.
        source_id: String,
        /// Shared timestamp.
        timestamp: TimestampNs,
        /// Previous key.
        previous: u64,
        /// Rejected key.
        actual: u64,
    },
    /// Multiple sources share a timestamp without unique explicit order keys.
    #[error("ambiguous cross-source order at timestamp {timestamp}: {sources:?}")]
    AmbiguousTick {
        /// Shared timestamp.
        timestamp: TimestampNs,
        /// Sources participating in the ambiguity.
        sources: Vec<String>,
    },
}

/// A pull-based deterministic merge over already sorted observation sources.
pub struct KWayMerge {
    descriptor: SourceDescriptor,
    sources: Vec<Box<dyn ObservationSource + Send>>,
    heads: Vec<Option<OrderedObservation>>,
    states: Vec<MergeSourceState>,
    deferred_error: Option<SourceError>,
}

impl KWayMerge {
    /// Initializes a merge and reads at most one observation from each source.
    pub fn new(mut sources: Vec<Box<dyn ObservationSource + Send>>) -> Result<Self, SourceError> {
        let domain = sources
            .first()
            .map(|source| source.descriptor().clock_domain.clone())
            .unwrap_or_else(|| "session".to_owned());
        let mut source_ids = BTreeSet::new();
        for source in &sources {
            let descriptor = source.descriptor();
            if descriptor.clock_domain != domain {
                return Err(MergeError::ClockDomainMismatch {
                    source_id: descriptor.source_id.clone(),
                    expected: domain.clone(),
                    actual: descriptor.clock_domain.clone(),
                }
                .into());
            }
            if !source_ids.insert(descriptor.source_id.clone()) {
                return Err(MergeError::DuplicateSource {
                    source_id: descriptor.source_id.clone(),
                }
                .into());
            }
        }

        let mut heads = Vec::with_capacity(sources.len());
        let mut states = Vec::with_capacity(sources.len());
        for source in &mut sources {
            let mut state = MergeSourceState::default();
            let head = source.next_observation()?;
            if let Some(record) = &head {
                validate_source_record(source.descriptor(), &mut state, record)?;
            }
            heads.push(head);
            states.push(state);
        }

        Ok(Self {
            descriptor: SourceDescriptor::new("k-way-merge", domain),
            sources,
            heads,
            states,
            deferred_error: None,
        })
    }

    fn select_head(&self) -> Result<Option<usize>, MergeError> {
        let Some(minimum) = self
            .heads
            .iter()
            .filter_map(|head| head.as_ref().map(|record| record.observation.ts_ns()))
            .min()
        else {
            return Ok(None);
        };
        let tied = self
            .heads
            .iter()
            .enumerate()
            .filter_map(|(index, head)| {
                head.as_ref()
                    .filter(|record| record.observation.ts_ns() == minimum)
                    .map(|_| index)
            })
            .collect::<Vec<_>>();
        if tied.len() == 1 {
            return Ok(tied.first().copied());
        }

        let mut by_key = BTreeMap::new();
        for index in &tied {
            let record = self.heads[*index].as_ref().expect("tied head exists");
            let Some(key) = record.order_key else {
                return Err(self.ambiguous(minimum, &tied));
            };
            if by_key.insert(key, *index).is_some() {
                return Err(self.ambiguous(minimum, &tied));
            }
        }
        Ok(by_key.first_key_value().map(|(_, index)| *index))
    }

    fn ambiguous(&self, timestamp: TimestampNs, tied: &[usize]) -> MergeError {
        let mut sources = tied
            .iter()
            .map(|index| self.sources[*index].descriptor().source_id.clone())
            .collect::<Vec<_>>();
        sources.sort();
        MergeError::AmbiguousTick { timestamp, sources }
    }
}

impl ObservationSource for KWayMerge {
    fn descriptor(&self) -> &SourceDescriptor {
        &self.descriptor
    }

    fn next_observation(&mut self) -> Result<Option<OrderedObservation>, SourceError> {
        if let Some(error) = self.deferred_error.take() {
            return Err(error);
        }
        let Some(index) = self.select_head()? else {
            return Ok(None);
        };
        let result = self.heads[index].take().expect("selected head exists");
        match self.sources[index].next_observation() {
            Ok(next) => {
                if let Some(record) = &next
                    && let Err(error) = validate_source_record(
                        self.sources[index].descriptor(),
                        &mut self.states[index],
                        record,
                    )
                {
                    self.deferred_error = Some(error.into());
                }
                self.heads[index] = next;
            }
            Err(error) => self.deferred_error = Some(error),
        }
        Ok(Some(result))
    }
}

fn validate_source_record(
    descriptor: &SourceDescriptor,
    state: &mut MergeSourceState,
    record: &OrderedObservation,
) -> Result<(), MergeError> {
    let timestamp = record.observation.ts_ns();
    if let Some(previous) = state.last_timestamp
        && timestamp < previous
    {
        return Err(MergeError::SourceOutOfOrder {
            source_id: descriptor.source_id.clone(),
            previous,
            actual: timestamp,
        });
    }
    if state.last_timestamp == Some(timestamp)
        && let (Some(previous), Some(actual)) = (state.last_order_key, record.order_key)
        && actual <= previous
    {
        return Err(MergeError::SourceOrderKey {
            source_id: descriptor.source_id.clone(),
            timestamp,
            previous,
            actual,
        });
    }
    state
        .order
        .observe(&record.observation)
        .map_err(|error| match error {
            crate::ObservationOrderError::SourceSequence {
                previous, actual, ..
            } => MergeError::SourceSequence {
                source_id: descriptor.source_id.clone(),
                previous,
                actual,
            },
            crate::ObservationOrderError::SourceTimestamp {
                previous, actual, ..
            }
            | crate::ObservationOrderError::GlobalTimestamp { previous, actual } => {
                MergeError::SourceOutOfOrder {
                    source_id: descriptor.source_id.clone(),
                    previous,
                    actual,
                }
            }
        })?;
    state.last_timestamp = Some(timestamp);
    state.last_order_key = record.order_key;
    Ok(())
}
