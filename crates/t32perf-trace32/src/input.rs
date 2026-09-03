//! Bounded physical-line input with exact source locations.

use std::io::BufRead;

use thiserror::Error;

/// Default maximum number of dictionary definitions in canonical NDJSON.
pub const DEFAULT_MAX_DICTIONARY_ENTRIES: u64 = 65_536;
/// Default maximum physical bytes occupied by canonical dictionary lines.
pub const DEFAULT_MAX_DICTIONARY_BYTES: u64 = 64 * 1024 * 1024;
/// Absolute dictionary-definition limit accepted by the parser.
pub const HARD_MAX_DICTIONARY_ENTRIES: u64 = 1_048_576;
/// Absolute physical dictionary-byte limit accepted by the parser.
pub const HARD_MAX_DICTIONARY_BYTES: u64 = 1024 * 1024 * 1024;

/// A precise position in an input stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputLocation {
    /// Zero-based byte offset from the beginning of the input.
    pub byte_offset: u64,
    /// One-based physical line number.
    pub line: u64,
    /// Zero-based logical record number.
    pub record: u64,
}

impl InputLocation {
    pub(crate) const fn new(byte_offset: u64, line: u64, record: u64) -> Self {
        Self {
            byte_offset,
            line,
            record,
        }
    }
}

/// Limits applied before a complete line or record is allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineLimits {
    /// Maximum number of bytes in one record, excluding the terminating LF.
    pub max_line_bytes: usize,
    /// Maximum number of logical records, including stream metadata records.
    pub max_records: u64,
    /// Maximum number of dictionary definitions before observations begin.
    pub max_dictionary_entries: u64,
    /// Maximum physical bytes occupied by dictionary lines, including LF.
    pub max_dictionary_bytes: u64,
}

impl Default for LineLimits {
    fn default() -> Self {
        Self {
            max_line_bytes: 1024 * 1024,
            max_records: 10_000_000,
            max_dictionary_entries: DEFAULT_MAX_DICTIONARY_ENTRIES,
            max_dictionary_bytes: DEFAULT_MAX_DICTIONARY_BYTES,
        }
    }
}

impl LineLimits {
    pub(crate) fn validate(self) -> Result<(), InputErrorKind> {
        if self.max_line_bytes == 0
            || self.max_records == 0
            || self.max_dictionary_entries == 0
            || self.max_dictionary_bytes == 0
        {
            return Err(InputErrorKind::InvalidLimit);
        }
        if self.max_dictionary_entries > HARD_MAX_DICTIONARY_ENTRIES {
            return Err(InputErrorKind::DictionaryEntryLimitTooLarge {
                limit: self.max_dictionary_entries,
                maximum: HARD_MAX_DICTIONARY_ENTRIES,
            });
        }
        if self.max_dictionary_bytes > HARD_MAX_DICTIONARY_BYTES {
            return Err(InputErrorKind::DictionaryByteLimitTooLarge {
                limit: self.max_dictionary_bytes,
                maximum: HARD_MAX_DICTIONARY_BYTES,
            });
        }
        Ok(())
    }
}

/// A bounded-line input failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{kind} at byte {location_byte}, line {location_line}, record {location_record}")]
pub struct InputError {
    /// Exact input position associated with the failure.
    pub location: InputLocation,
    /// Failure category.
    pub kind: InputErrorKind,
    location_byte: u64,
    location_line: u64,
    location_record: u64,
}

impl InputError {
    pub(crate) fn new(location: InputLocation, kind: InputErrorKind) -> Self {
        Self {
            location,
            kind,
            location_byte: location.byte_offset,
            location_line: location.line,
            location_record: location.record,
        }
    }
}

/// The category of a bounded-line input failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InputErrorKind {
    /// A configured limit is zero and therefore cannot accept any input.
    #[error("invalid zero input limit")]
    InvalidLimit,
    /// The configured dictionary-entry bound exceeds the parser hard limit.
    #[error("dictionary entry limit {limit} exceeds hard maximum {maximum}")]
    DictionaryEntryLimitTooLarge {
        /// Rejected configured limit.
        limit: u64,
        /// Parser hard maximum.
        maximum: u64,
    },
    /// The configured dictionary-byte bound exceeds the parser hard limit.
    #[error("dictionary byte limit {limit} exceeds hard maximum {maximum}")]
    DictionaryByteLimitTooLarge {
        /// Rejected configured limit.
        limit: u64,
        /// Parser hard maximum.
        maximum: u64,
    },
    /// An operating-system read failed.
    #[error("I/O error: {message}")]
    Io {
        /// Original I/O error text.
        message: String,
    },
    /// A physical line exceeded its configured bound.
    #[error("line exceeds {limit} bytes")]
    LineTooLong {
        /// Configured maximum line length.
        limit: usize,
    },
    /// More logical records were present than allowed.
    #[error("record count exceeds {limit}")]
    RecordLimitExceeded {
        /// Configured maximum record count.
        limit: u64,
    },
    /// EOF occurred after a record began but before its LF terminator.
    #[error("truncated record without terminating LF")]
    TruncatedLine,
    /// CRLF is rejected because canonical streams use LF delimiters.
    #[error("non-canonical CRLF line ending")]
    NonCanonicalLineEnding,
}

#[derive(Debug)]
pub(crate) struct LocatedLine {
    pub(crate) bytes: Vec<u8>,
    pub(crate) location: InputLocation,
}

pub(crate) struct BoundedLineReader<R> {
    inner: R,
    limits: LineLimits,
    byte_offset: u64,
    line: u64,
    record: u64,
    accept_crlf: bool,
}

impl<R: BufRead> BoundedLineReader<R> {
    pub(crate) fn new(inner: R, limits: LineLimits) -> Result<Self, InputError> {
        Self::with_crlf(inner, limits, false)
    }

    pub(crate) fn vendor_text(inner: R, limits: LineLimits) -> Result<Self, InputError> {
        Self::with_crlf(inner, limits, true)
    }

    fn with_crlf(inner: R, limits: LineLimits, accept_crlf: bool) -> Result<Self, InputError> {
        if let Err(kind) = limits.validate() {
            return Err(InputError::new(InputLocation::new(0, 1, 0), kind));
        }
        Ok(Self {
            inner,
            limits,
            byte_offset: 0,
            line: 1,
            record: 0,
            accept_crlf,
        })
    }

    pub(crate) fn next_line(&mut self) -> Result<Option<LocatedLine>, InputError> {
        let start = InputLocation::new(self.byte_offset, self.line, self.record);
        if self.record >= self.limits.max_records {
            let has_more = !self
                .inner
                .fill_buf()
                .map_err(|error| {
                    InputError::new(
                        start,
                        InputErrorKind::Io {
                            message: error.to_string(),
                        },
                    )
                })?
                .is_empty();
            if has_more {
                return Err(InputError::new(
                    start,
                    InputErrorKind::RecordLimitExceeded {
                        limit: self.limits.max_records,
                    },
                ));
            }
            return Ok(None);
        }

        let mut bytes = Vec::new();
        loop {
            let available = self.inner.fill_buf().map_err(|error| {
                InputError::new(
                    InputLocation::new(self.byte_offset, self.line, self.record),
                    InputErrorKind::Io {
                        message: error.to_string(),
                    },
                )
            })?;

            if available.is_empty() {
                if bytes.is_empty() {
                    return Ok(None);
                }
                return Err(InputError::new(
                    InputLocation::new(self.byte_offset, self.line, self.record),
                    InputErrorKind::TruncatedLine,
                ));
            }

            let newline = available.iter().position(|byte| *byte == b'\n');
            let take = newline.unwrap_or(available.len());
            if bytes.len().saturating_add(take) > self.limits.max_line_bytes {
                return Err(InputError::new(
                    InputLocation::new(
                        start.byte_offset + self.limits.max_line_bytes as u64,
                        start.line,
                        start.record,
                    ),
                    InputErrorKind::LineTooLong {
                        limit: self.limits.max_line_bytes,
                    },
                ));
            }

            bytes.extend_from_slice(&available[..take]);
            let consumed = take + usize::from(newline.is_some());
            self.inner.consume(consumed);
            self.byte_offset = self.byte_offset.saturating_add(consumed as u64);

            if newline.is_some() {
                if bytes.last() == Some(&b'\r') {
                    if self.accept_crlf {
                        bytes.pop();
                    } else {
                        return Err(InputError::new(
                            InputLocation::new(
                                start.byte_offset + bytes.len().saturating_sub(1) as u64,
                                start.line,
                                start.record,
                            ),
                            InputErrorKind::NonCanonicalLineEnding,
                        ));
                    }
                }
                self.line = self.line.saturating_add(1);
                self.record = self.record.saturating_add(1);
                return Ok(Some(LocatedLine {
                    bytes,
                    location: start,
                }));
            }
        }
    }

    pub(crate) const fn next_location(&self) -> InputLocation {
        InputLocation::new(self.byte_offset, self.line, self.record)
    }
}
