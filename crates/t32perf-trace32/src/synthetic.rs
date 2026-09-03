//! Deterministic synthetic observation generation.

use t32perf_model::{Observation, ObservationEvent, Properties, Quality};

use crate::{
    AdapterError, AdapterRequest, ObservationAdapter, ObservationSource, OrderedObservation,
    SourceDescriptor, SourceError,
};

/// Configuration for a deterministic synthetic source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticConfig {
    /// Source identifier placed in every observation.
    pub source_id: String,
    /// Normalized clock-domain identifier.
    pub clock_domain: String,
    /// Number of observations to generate.
    pub count: u64,
    /// Timestamp of the first observation.
    pub start_ns: i64,
    /// Integer timestamp increment.
    pub step_ns: i64,
    /// Sequence number of the first observation.
    pub source_seq_start: u64,
    /// Optional first explicit order key.
    pub order_key_start: Option<u64>,
}

impl SyntheticConfig {
    /// Creates a simple deterministic source configuration.
    #[must_use]
    pub fn new(source_id: impl Into<String>, count: u64) -> Self {
        Self {
            source_id: source_id.into(),
            clock_domain: "session".to_owned(),
            count,
            start_ns: 0,
            step_ns: 1,
            source_seq_start: 0,
            order_key_start: None,
        }
    }

    fn validate(&self) -> Result<(), SourceError> {
        if self.source_id.is_empty() || self.clock_domain.is_empty() {
            return Err(SourceError::Invariant {
                message: "synthetic source and clock-domain IDs must be nonempty".to_owned(),
            });
        }
        if self.step_ns < 0 {
            return Err(SourceError::Invariant {
                message: "synthetic step_ns must be nonnegative".to_owned(),
            });
        }
        let last_index = self.count.saturating_sub(1);
        self.source_seq_start
            .checked_add(last_index)
            .ok_or_else(|| SourceError::Invariant {
                message: "synthetic source sequence overflows".to_owned(),
            })?;
        if let Some(start) = self.order_key_start {
            start
                .checked_add(last_index)
                .ok_or_else(|| SourceError::Invariant {
                    message: "synthetic order key overflows".to_owned(),
                })?;
        }
        if self.count != 0 {
            let last_timestamp = i128::from(self.step_ns)
                .checked_mul(i128::from(last_index))
                .and_then(|delta| i128::from(self.start_ns).checked_add(delta))
                .and_then(|value| i64::try_from(value).ok());
            if last_timestamp.is_none() {
                return Err(SourceError::Invariant {
                    message: "synthetic timestamp overflows".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// A deterministic synthetic observation source.
#[derive(Debug)]
pub struct SyntheticSource {
    descriptor: SourceDescriptor,
    config: SyntheticConfig,
    index: u64,
}

impl SyntheticSource {
    /// Creates a source and validates all ranges before generation.
    pub fn new(config: SyntheticConfig) -> Result<Self, SourceError> {
        config.validate()?;
        Ok(Self {
            descriptor: SourceDescriptor::new(&config.source_id, &config.clock_domain),
            config,
            index: 0,
        })
    }
}

impl ObservationSource for SyntheticSource {
    fn descriptor(&self) -> &SourceDescriptor {
        &self.descriptor
    }

    fn next_observation(&mut self) -> Result<Option<OrderedObservation>, SourceError> {
        if self.index >= self.config.count {
            return Ok(None);
        }
        let timestamp_delta = i128::from(self.config.step_ns) * i128::from(self.index);
        let timestamp = i128::from(self.config.start_ns)
            .checked_add(timestamp_delta)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(|| SourceError::Invariant {
                message: "synthetic timestamp overflows".to_owned(),
            })?;
        let source_seq = self.config.source_seq_start + self.index;
        let observation = Observation::new(
            self.config.source_id.clone(),
            source_seq,
            Quality::Exact,
            ObservationEvent::Instant {
                ts_ns: timestamp,
                core_id: Some(0),
                context_id: None,
                name: format!("synthetic:{}", self.index % 4),
                args: Properties::new(),
            },
        );
        let result = match self.config.order_key_start {
            Some(start) => OrderedObservation::ordered(observation, start + self.index),
            None => OrderedObservation::unordered(observation),
        };
        self.index += 1;
        Ok(Some(result))
    }
}

/// Registry adapter for one immutable synthetic configuration.
#[derive(Debug, Clone)]
pub struct SyntheticAdapter {
    id: String,
    config: SyntheticConfig,
}

impl SyntheticAdapter {
    /// Creates a fixed synthetic adapter.
    pub fn new(id: impl Into<String>, config: SyntheticConfig) -> Result<Self, AdapterError> {
        let id = id.into();
        if id.is_empty() {
            return Err(AdapterError::EmptyAdapterId);
        }
        config
            .validate()
            .map_err(|error| AdapterError::InvalidConfiguration {
                adapter: id.clone(),
                message: error.to_string(),
            })?;
        Ok(Self { id, config })
    }
}

impl ObservationAdapter for SyntheticAdapter {
    fn id(&self) -> &str {
        &self.id
    }

    fn open(
        &self,
        request: AdapterRequest,
    ) -> Result<Box<dyn ObservationSource + Send>, AdapterError> {
        request.reject_options(self.id())?;
        if request.source_id != self.config.source_id {
            return Err(AdapterError::InvalidConfiguration {
                adapter: self.id.clone(),
                message: format!(
                    "request source `{}` does not match fixed source `{}`",
                    request.source_id, self.config.source_id
                ),
            });
        }
        Ok(Box::new(SyntheticSource::new(self.config.clone())?))
    }
}
