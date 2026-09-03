//! Integer timestamp scaling, clock domains, and bounded wrap expansion.

use std::collections::BTreeMap;

use t32perf_model::TimestampNs;
use thiserror::Error;

/// A rational number of nanoseconds per raw timestamp tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RationalTickScale {
    /// Nanosecond numerator.
    pub nanoseconds_numerator: u64,
    /// Tick denominator.
    pub ticks_denominator: u64,
}

impl RationalTickScale {
    /// Creates a rational tick scale.
    pub fn new(nanoseconds_numerator: u64, ticks_denominator: u64) -> Result<Self, ClockError> {
        if nanoseconds_numerator == 0 || ticks_denominator == 0 {
            return Err(ClockError::InvalidScale);
        }
        let divisor = gcd(nanoseconds_numerator, ticks_denominator);
        Ok(Self {
            nanoseconds_numerator: nanoseconds_numerator / divisor,
            ticks_denominator: ticks_denominator / divisor,
        })
    }

    /// Creates a scale for an integer tick frequency in hertz.
    pub fn from_hz(frequency_hz: u64) -> Result<Self, ClockError> {
        Self::new(1_000_000_000, frequency_hz)
    }

    /// Converts an unsigned tick value to nanoseconds using floor rounding.
    pub fn ticks_to_ns(self, ticks: u128) -> Result<u128, ClockError> {
        let numerator = u128::from(self.nanoseconds_numerator);
        let denominator = u128::from(self.ticks_denominator);
        let whole = ticks / denominator;
        let remainder = ticks % denominator;
        whole
            .checked_mul(numerator)
            .and_then(|value| {
                remainder
                    .checked_mul(numerator)
                    .and_then(|fraction| value.checked_add(fraction / denominator))
            })
            .ok_or(ClockError::Overflow)
    }

    /// Converts a tick around an origin to a signed session timestamp.
    pub fn timestamp_ns(
        self,
        ticks: u128,
        origin_ticks: u128,
        origin_ns: TimestampNs,
    ) -> Result<TimestampNs, ClockError> {
        let magnitude_ticks = ticks.abs_diff(origin_ticks);
        let magnitude_ns = self.ticks_to_ns(magnitude_ticks)?;
        let magnitude_ns = i128::try_from(magnitude_ns).map_err(|_| ClockError::Overflow)?;
        let delta = if ticks >= origin_ticks {
            magnitude_ns
        } else {
            -magnitude_ns
        };
        let result = i128::from(origin_ns)
            .checked_add(delta)
            .ok_or(ClockError::Overflow)?;
        i64::try_from(result).map_err(|_| ClockError::Overflow)
    }
}

/// A validated raw clock-domain definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockDomainSpec {
    /// Stable clock-domain identifier.
    pub id: String,
    /// Raw-tick to nanosecond conversion.
    pub scale: RationalTickScale,
    /// Optional raw timestamp modulus.
    pub timestamp_modulus: Option<u64>,
    /// Maximum permitted forward step between adjacent raw records.
    pub max_forward_ticks: Option<u64>,
}

impl ClockDomainSpec {
    /// Validates and creates a clock-domain definition.
    pub fn new(
        id: impl Into<String>,
        scale: RationalTickScale,
        timestamp_modulus: Option<u64>,
        max_forward_ticks: Option<u64>,
    ) -> Result<Self, ClockError> {
        let id = id.into();
        if id.is_empty() {
            return Err(ClockError::EmptyDomain);
        }
        match (timestamp_modulus, max_forward_ticks) {
            (None, Some(_)) => return Err(ClockError::UnexpectedWrapLimit),
            (Some(modulus), _) if modulus < 2 => return Err(ClockError::InvalidModulus),
            (Some(_), None) => return Err(ClockError::MissingForwardLimit),
            (Some(modulus), Some(maximum)) if maximum >= modulus => {
                return Err(ClockError::InvalidForwardLimit { modulus, maximum });
            }
            _ => {}
        }
        Ok(Self {
            id,
            scale,
            timestamp_modulus,
            max_forward_ticks,
        })
    }
}

/// Registry of clock-domain definitions used to reject accidental mixing.
#[derive(Debug, Default)]
pub struct ClockDomainRegistry {
    domains: BTreeMap<String, ClockDomainSpec>,
}

impl ClockDomainRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a domain and rejects duplicate identifiers.
    pub fn register(&mut self, domain: ClockDomainSpec) -> Result<(), ClockError> {
        if self.domains.contains_key(&domain.id) {
            return Err(ClockError::DuplicateDomain {
                id: domain.id.clone(),
            });
        }
        self.domains.insert(domain.id.clone(), domain);
        Ok(())
    }

    /// Returns a registered clock domain.
    pub fn get(&self, id: &str) -> Result<&ClockDomainSpec, ClockError> {
        self.domains
            .get(id)
            .ok_or_else(|| ClockError::UnknownDomain { id: id.to_owned() })
    }

    /// Requires two inputs to use the same normalized clock domain.
    pub fn require_same(&self, left: &str, right: &str) -> Result<(), ClockError> {
        self.get(left)?;
        self.get(right)?;
        if left != right {
            return Err(ClockError::DomainMismatch {
                expected: left.to_owned(),
                actual: right.to_owned(),
            });
        }
        Ok(())
    }
}

/// Expands a bounded wrapping counter to a monotonic integer timeline.
#[derive(Debug, Clone)]
pub struct TimestampUnwrapper {
    modulus: u64,
    max_forward_ticks: u64,
    last_expanded: Option<u128>,
}

impl TimestampUnwrapper {
    /// Creates an unwrapper with an explicit maximum adjacent forward step.
    pub fn new(modulus: u64, max_forward_ticks: u64) -> Result<Self, ClockError> {
        if modulus < 2 {
            return Err(ClockError::InvalidModulus);
        }
        if max_forward_ticks >= modulus {
            return Err(ClockError::InvalidForwardLimit {
                modulus,
                maximum: max_forward_ticks,
            });
        }
        Ok(Self {
            modulus,
            max_forward_ticks,
            last_expanded: None,
        })
    }

    /// Expands the next raw counter value.
    pub fn expand(&mut self, raw: u64) -> Result<u128, ClockError> {
        if raw >= self.modulus {
            return Err(ClockError::RawTickOutsideModulus {
                raw,
                modulus: self.modulus,
            });
        }
        let Some(previous) = self.last_expanded else {
            let expanded = u128::from(raw);
            self.last_expanded = Some(expanded);
            return Ok(expanded);
        };

        let modulus = u128::from(self.modulus);
        let epoch = previous / modulus * modulus;
        let mut candidate = epoch + u128::from(raw);
        if candidate < previous {
            candidate = candidate.checked_add(modulus).ok_or(ClockError::Overflow)?;
        }
        let delta = candidate - previous;
        if delta > u128::from(self.max_forward_ticks) {
            return Err(ClockError::ForwardStepTooLarge {
                previous,
                raw,
                delta,
                maximum: self.max_forward_ticks,
            });
        }
        self.last_expanded = Some(candidate);
        Ok(candidate)
    }
}

/// Stateful raw timestamp normalizer for one clock domain.
#[derive(Debug, Clone)]
pub struct TimestampNormalizer {
    domain: ClockDomainSpec,
    unwrapper: Option<TimestampUnwrapper>,
    origin_ticks: Option<u128>,
    origin_ns: TimestampNs,
    last_unwrapped_ticks: Option<u128>,
}

impl TimestampNormalizer {
    /// Creates a normalizer. `origin_ticks=None` anchors the first record at `origin_ns`.
    pub fn new(
        domain: ClockDomainSpec,
        origin_ticks: Option<u64>,
        origin_ns: TimestampNs,
    ) -> Result<Self, ClockError> {
        let unwrapper = match (domain.timestamp_modulus, domain.max_forward_ticks) {
            (Some(modulus), Some(maximum)) => Some(TimestampUnwrapper::new(modulus, maximum)?),
            (Some(_), None) => return Err(ClockError::MissingForwardLimit),
            (None, _) => None,
        };
        Ok(Self {
            domain,
            unwrapper,
            origin_ticks: origin_ticks.map(u128::from),
            origin_ns,
            last_unwrapped_ticks: None,
        })
    }

    /// Returns the normalized clock-domain identifier.
    #[must_use]
    pub fn domain_id(&self) -> &str {
        &self.domain.id
    }

    /// Converts the next raw timestamp into session-relative nanoseconds.
    pub fn normalize(&mut self, raw: u64) -> Result<TimestampNs, ClockError> {
        let expanded = match &mut self.unwrapper {
            Some(unwrapper) => unwrapper.expand(raw)?,
            None => {
                let expanded = u128::from(raw);
                if let Some(previous) = self.last_unwrapped_ticks
                    && expanded < previous
                {
                    return Err(ClockError::RawTimestampOutOfOrder {
                        previous,
                        actual: expanded,
                    });
                }
                self.last_unwrapped_ticks = Some(expanded);
                expanded
            }
        };
        let origin = *self.origin_ticks.get_or_insert(expanded);
        self.domain
            .scale
            .timestamp_ns(expanded, origin, self.origin_ns)
    }
}

/// A clock-domain or timestamp-conversion failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ClockError {
    /// A rational scale contains zero.
    #[error("tick scale numerator and denominator must be nonzero")]
    InvalidScale,
    /// A clock-domain identifier is empty.
    #[error("clock-domain identifier is empty")]
    EmptyDomain,
    /// A timestamp modulus is smaller than two.
    #[error("timestamp modulus must be at least two")]
    InvalidModulus,
    /// A wrap limit was supplied without a timestamp modulus.
    #[error("max forward ticks requires a timestamp modulus")]
    UnexpectedWrapLimit,
    /// A wrapping domain omitted its required adjacent-step bound.
    #[error("wrapping timestamp domain requires max forward ticks")]
    MissingForwardLimit,
    /// The adjacent-step bound cannot distinguish one wrap.
    #[error("max forward ticks {maximum} must be smaller than modulus {modulus}")]
    InvalidForwardLimit {
        /// Timestamp modulus.
        modulus: u64,
        /// Rejected maximum step.
        maximum: u64,
    },
    /// A raw timestamp is outside its declared modulus.
    #[error("raw timestamp {raw} is outside modulus {modulus}")]
    RawTickOutsideModulus {
        /// Rejected raw value.
        raw: u64,
        /// Timestamp modulus.
        modulus: u64,
    },
    /// An adjacent timestamp step is too large to distinguish wrap from loss.
    #[error("timestamp step {delta} from {previous} through raw value {raw} exceeds {maximum}")]
    ForwardStepTooLarge {
        /// Previous expanded timestamp.
        previous: u128,
        /// Rejected raw timestamp.
        raw: u64,
        /// Expanded delta.
        delta: u128,
        /// Configured maximum delta.
        maximum: u64,
    },
    /// A non-wrapping timestamp moved backward.
    #[error("raw timestamp {actual} precedes {previous}")]
    RawTimestampOutOfOrder {
        /// Previous raw timestamp.
        previous: u128,
        /// Rejected raw timestamp.
        actual: u128,
    },
    /// Two domains cannot be merged without an explicit conversion.
    #[error("clock domain `{actual}` does not match `{expected}`")]
    DomainMismatch {
        /// Required domain.
        expected: String,
        /// Rejected domain.
        actual: String,
    },
    /// A clock domain was registered more than once.
    #[error("clock domain `{id}` is already registered")]
    DuplicateDomain {
        /// Duplicate identifier.
        id: String,
    },
    /// A requested domain is unavailable.
    #[error("clock domain `{id}` is not registered")]
    UnknownDomain {
        /// Missing identifier.
        id: String,
    },
    /// Integer conversion overflowed.
    #[error("timestamp conversion overflow")]
    Overflow,
}

const fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}
