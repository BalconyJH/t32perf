//! Adapter registry and host-owned adapter requests.

use std::{collections::BTreeMap, io::BufRead};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CanonicalNdjsonAdapter, ObservationSource, SourceError, TraceAsciiAdapter,
    TraceTaskEventsAdapter,
};

/// Schema identity for host-inspectable adapter descriptors.
pub const ADAPTER_DESCRIPTOR_SCHEMA: &str = "t32perf.adapter-descriptor/v1";

/// One TRACE32 build range verified against an adapter implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterCompatibility {
    /// TRACE32 release label, matched exactly.
    pub trace32_release: String,
    /// Inclusive minimum TRACE32 build.
    pub minimum_build: u64,
    /// Inclusive maximum TRACE32 build.
    pub maximum_build: u64,
    /// Architecture package identity, matched exactly.
    pub architecture_package: String,
}

impl AdapterCompatibility {
    /// Creates one verified compatibility range.
    #[must_use]
    pub fn new(
        trace32_release: impl Into<String>,
        minimum_build: u64,
        maximum_build: u64,
        architecture_package: impl Into<String>,
    ) -> Self {
        Self {
            trace32_release: trace32_release.into(),
            minimum_build,
            maximum_build,
            architecture_package: architecture_package.into(),
        }
    }

    fn matches(&self, request: &AdapterSelectionRequest) -> bool {
        self.trace32_release == request.trace32_release
            && (self.minimum_build..=self.maximum_build).contains(&request.trace32_build)
            && self.architecture_package == request.architecture_package
    }
}

/// Versioned, host-inspectable description of one adapter implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterDescriptor {
    /// Descriptor schema identity.
    pub schema: String,
    /// Stable registry identifier.
    pub adapter_id: String,
    /// Exact input format identity selected by the host.
    pub format: String,
    /// TRACE32 environments verified by fixtures and hardware evidence.
    pub verified_compatibility: Vec<AdapterCompatibility>,
}

impl AdapterDescriptor {
    /// Creates a versioned descriptor.
    #[must_use]
    pub fn new(
        adapter_id: impl Into<String>,
        format: impl Into<String>,
        verified_compatibility: Vec<AdapterCompatibility>,
    ) -> Self {
        Self {
            schema: ADAPTER_DESCRIPTOR_SCHEMA.to_owned(),
            adapter_id: adapter_id.into(),
            format: format.into(),
            verified_compatibility,
        }
    }

    /// Creates a descriptor with no verified TRACE32 compatibility.
    #[must_use]
    pub fn unverified(adapter_id: impl Into<String>, format: impl Into<String>) -> Self {
        Self::new(adapter_id, format, Vec::new())
    }

    fn validate(&self, registered_id: &str) -> Result<(), AdapterError> {
        if self.schema != ADAPTER_DESCRIPTOR_SCHEMA {
            return Err(AdapterError::InvalidDescriptor {
                adapter: registered_id.to_owned(),
                message: format!("unsupported descriptor schema `{}`", self.schema),
            });
        }
        if self.adapter_id != registered_id {
            return Err(AdapterError::InvalidDescriptor {
                adapter: registered_id.to_owned(),
                message: format!(
                    "descriptor adapter `{}` does not match registered identifier",
                    self.adapter_id
                ),
            });
        }
        if self.format.trim().is_empty() {
            return Err(AdapterError::InvalidDescriptor {
                adapter: registered_id.to_owned(),
                message: "format is empty".to_owned(),
            });
        }
        for compatibility in &self.verified_compatibility {
            if compatibility.trace32_release.trim().is_empty()
                || compatibility.architecture_package.trim().is_empty()
                || compatibility.minimum_build == 0
                || compatibility.minimum_build > compatibility.maximum_build
            {
                return Err(AdapterError::InvalidDescriptor {
                    adapter: registered_id.to_owned(),
                    message: "verified compatibility has an empty identity, zero build, or reversed build range"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Host-owned selection key for one verified TRACE32 adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterSelectionRequest {
    /// Exact input format identity.
    pub format: String,
    /// TRACE32 release label.
    pub trace32_release: String,
    /// TRACE32 build number.
    pub trace32_build: u64,
    /// Architecture package identity.
    pub architecture_package: String,
}

impl AdapterSelectionRequest {
    /// Creates an exact host selection request.
    #[must_use]
    pub fn new(
        format: impl Into<String>,
        trace32_release: impl Into<String>,
        trace32_build: u64,
        architecture_package: impl Into<String>,
    ) -> Self {
        Self {
            format: format.into(),
            trace32_release: trace32_release.into(),
            trace32_build,
            architecture_package: architecture_package.into(),
        }
    }
}

/// Input and immutable metadata supplied when opening an adapter.
pub struct AdapterRequest {
    /// Session identifier that owns generated observations.
    pub session_id: String,
    /// Stable source identifier assigned to generated observations.
    pub source_id: String,
    /// Optional byte input. Synthetic and unsupported adapters may not consume it.
    pub input: Option<Box<dyn BufRead + Send>>,
    /// Explicit adapter-specific options supplied by trusted host code.
    pub options: BTreeMap<String, String>,
}

impl AdapterRequest {
    /// Creates an adapter request without an input stream.
    #[must_use]
    pub fn new(session_id: impl Into<String>, source_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            source_id: source_id.into(),
            input: None,
            options: BTreeMap::new(),
        }
    }

    /// Attaches a synchronous input stream.
    #[must_use]
    pub fn with_input(mut self, input: impl BufRead + Send + 'static) -> Self {
        self.input = Some(Box::new(input));
        self
    }

    /// Takes the required input stream or returns a stable error.
    pub fn take_input(&mut self, adapter: &str) -> Result<Box<dyn BufRead + Send>, AdapterError> {
        self.input.take().ok_or_else(|| AdapterError::MissingInput {
            adapter: adapter.to_owned(),
        })
    }

    /// Rejects every option for an adapter whose configuration is fixed.
    pub fn reject_options(&self, adapter: &str) -> Result<(), AdapterError> {
        if let Some(key) = self.options.keys().next() {
            return Err(AdapterError::InvalidConfiguration {
                adapter: adapter.to_owned(),
                message: format!("unknown option `{key}`"),
            });
        }
        Ok(())
    }
}

/// A factory for one fixed observation adapter.
pub trait ObservationAdapter: Send + Sync {
    /// Stable registry identifier.
    fn id(&self) -> &str;

    /// Returns the versioned format and verified compatibility contract.
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor::unverified(self.id(), self.id())
    }

    /// Opens a synchronous observation source.
    fn open(
        &self,
        request: AdapterRequest,
    ) -> Result<Box<dyn ObservationSource + Send>, AdapterError>;
}

/// Deterministic registry of fixed adapter factories.
#[derive(Default)]
pub struct AdapterRegistry {
    adapters: BTreeMap<String, Box<dyn ObservationAdapter>>,
    descriptors: BTreeMap<String, AdapterDescriptor>,
}

impl AdapterRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates the conservative built-in registry.
    ///
    /// Canonical NDJSON is usable. Raw TRACE32 ASCII and TASKEVENTS adapters
    /// remain registered but return `UNSUPPORTED_NEEDS_TRACE32` until a
    /// validated fixture and mapping are provided.
    pub fn conservative_defaults() -> Result<Self, AdapterError> {
        let mut registry = Self::new();
        registry.register(Box::new(CanonicalNdjsonAdapter::default()))?;
        registry.register(Box::new(TraceAsciiAdapter))?;
        registry.register(Box::new(TraceTaskEventsAdapter))?;
        Ok(registry)
    }

    /// Registers one adapter and rejects duplicate IDs.
    pub fn register(&mut self, adapter: Box<dyn ObservationAdapter>) -> Result<(), AdapterError> {
        let id = adapter.id().to_owned();
        if id.is_empty() {
            return Err(AdapterError::EmptyAdapterId);
        }
        if self.adapters.contains_key(&id) {
            return Err(AdapterError::DuplicateAdapter { id });
        }
        let descriptor = adapter.descriptor();
        descriptor.validate(&id)?;
        self.descriptors.insert(id.clone(), descriptor);
        self.adapters.insert(id, adapter);
        Ok(())
    }

    /// Returns registered adapter IDs in deterministic order.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.adapters.keys().map(String::as_str)
    }

    /// Returns one registered versioned descriptor.
    #[must_use]
    pub fn descriptor(&self, id: &str) -> Option<AdapterDescriptor> {
        self.descriptors.get(id).cloned()
    }

    /// Selects exactly one adapter with verified compatibility for the host key.
    pub fn select_verified(&self, request: &AdapterSelectionRequest) -> Result<&str, AdapterError> {
        if request.format.trim().is_empty()
            || request.trace32_release.trim().is_empty()
            || request.trace32_build == 0
            || request.architecture_package.trim().is_empty()
        {
            return Err(AdapterError::InvalidSelection {
                message:
                    "format, TRACE32 release, nonzero build, and architecture package are required"
                        .to_owned(),
            });
        }
        let mut matches = self
            .descriptors
            .iter()
            .filter_map(|(id, descriptor)| {
                (descriptor.format == request.format
                    && descriptor
                        .verified_compatibility
                        .iter()
                        .any(|compatibility| compatibility.matches(request)))
                .then_some(id.as_str())
            })
            .collect::<Vec<_>>();
        matches.sort_unstable();
        match matches.as_slice() {
            [id] => Ok(*id),
            [] => Err(AdapterError::NoCompatibleAdapter {
                format: request.format.clone(),
                trace32_release: request.trace32_release.clone(),
                trace32_build: request.trace32_build,
                architecture_package: request.architecture_package.clone(),
            }),
            _ => Err(AdapterError::AmbiguousCompatibleAdapters {
                adapters: matches.into_iter().map(str::to_owned).collect(),
            }),
        }
    }

    /// Opens a registered adapter.
    pub fn open(
        &self,
        id: &str,
        request: AdapterRequest,
    ) -> Result<Box<dyn ObservationSource + Send>, AdapterError> {
        self.adapters
            .get(id)
            .ok_or_else(|| AdapterError::UnknownAdapter { id: id.to_owned() })?
            .open(request)
    }
}

/// An adapter-registry or adapter-open failure.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// An adapter attempted to register an empty ID.
    #[error("adapter identifier is empty")]
    EmptyAdapterId,
    /// An adapter ID is already registered.
    #[error("adapter `{id}` is already registered")]
    DuplicateAdapter {
        /// Duplicate adapter ID.
        id: String,
    },
    /// A registered adapter exposed an invalid descriptor.
    #[error("adapter `{adapter}` descriptor is invalid: {message}")]
    InvalidDescriptor {
        /// Registered adapter identifier.
        adapter: String,
        /// Stable validation message.
        message: String,
    },
    /// An adapter ID is unavailable.
    #[error("adapter `{id}` is not registered")]
    UnknownAdapter {
        /// Missing adapter ID.
        id: String,
    },
    /// A host selection request omitted a required identity.
    #[error("adapter selection is invalid: {message}")]
    InvalidSelection {
        /// Stable validation message.
        message: String,
    },
    /// No verified adapter matches the exact host selection key.
    #[error(
        "no verified adapter matches format `{format}`, TRACE32 `{trace32_release}` build {trace32_build}, architecture package `{architecture_package}`"
    )]
    NoCompatibleAdapter {
        /// Requested input format.
        format: String,
        /// Requested TRACE32 release.
        trace32_release: String,
        /// Requested TRACE32 build.
        trace32_build: u64,
        /// Requested architecture package.
        architecture_package: String,
    },
    /// More than one verified adapter matches the exact host selection key.
    #[error("verified adapter selection is ambiguous: {adapters:?}")]
    AmbiguousCompatibleAdapters {
        /// Matching adapter IDs in deterministic order.
        adapters: Vec<String>,
    },
    /// A byte-oriented adapter did not receive input.
    #[error("adapter `{adapter}` requires an input stream")]
    MissingInput {
        /// Adapter requiring input.
        adapter: String,
    },
    /// The real TRACE32 format is intentionally unavailable without evidence.
    #[error("UNSUPPORTED_NEEDS_TRACE32: adapter `{adapter}` requires {requirement}")]
    UnsupportedNeedsTrace32 {
        /// Unsupported adapter ID.
        adapter: String,
        /// Required fixture, mapping, hardware, or TRACE32 evidence.
        requirement: &'static str,
    },
    /// Trusted host configuration is incomplete or inconsistent.
    #[error("adapter `{adapter}` configuration is invalid: {message}")]
    InvalidConfiguration {
        /// Adapter ID.
        adapter: String,
        /// Stable configuration error.
        message: String,
    },
    /// No structurally validated TRACE32 parser matches the typed context.
    #[error("no structurally validated TRACE32 parser matches the context")]
    NoValidatedTrace32Adapter,
    /// More than one structurally validated parser accepted one context.
    #[error("structurally validated TRACE32 parser selection is ambiguous: {adapters:?}")]
    AmbiguousValidatedTrace32Adapters {
        /// Matching parser IDs.
        adapters: Vec<String>,
    },
    /// Opening a source encountered an input failure.
    #[error(transparent)]
    Source(#[from] SourceError),
}
