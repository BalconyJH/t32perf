//! Bounded platform-text input for compiler and linker artifacts.

use std::io::BufRead;

use thiserror::Error;

use crate::LineLimits;

/// A precise position in a compiler or linker text artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceTextLocation {
    /// Zero-based byte offset from the beginning of the artifact.
    pub byte_offset: u64,
    /// One-based physical line number.
    pub line: u64,
    /// Zero-based physical record number.
    pub record: u64,
}

impl ResourceTextLocation {
    const fn new(byte_offset: u64, line: u64, record: u64) -> Self {
        Self {
            byte_offset,
            line,
            record,
        }
    }
}

/// A bounded compiler or linker text-input failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{kind} at byte {location_byte}, line {location_line}, record {location_record}")]
pub struct ResourceTextError {
    /// Exact artifact position associated with the failure.
    pub location: ResourceTextLocation,
    /// Failure category.
    pub kind: ResourceTextErrorKind,
    location_byte: u64,
    location_line: u64,
    location_record: u64,
}

impl ResourceTextError {
    fn new(location: ResourceTextLocation, kind: ResourceTextErrorKind) -> Self {
        Self {
            location,
            kind,
            location_byte: location.byte_offset,
            location_line: location.line,
            location_record: location.record,
        }
    }
}

/// The category of a bounded resource-text input failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ResourceTextErrorKind {
    /// A configured line or record limit is zero.
    #[error("invalid zero input limit")]
    InvalidLimit,
    /// An operating-system read failed.
    #[error("I/O error: {message}")]
    Io {
        /// Original I/O error text.
        message: String,
    },
    /// One physical line exceeded its configured content bound.
    #[error("line exceeds {limit} bytes")]
    LineTooLong {
        /// Configured maximum content bytes, excluding CRLF or LF.
        limit: usize,
    },
    /// More physical records were present than configured.
    #[error("record count exceeds {limit}")]
    RecordLimitExceeded {
        /// Configured maximum record count.
        limit: u64,
    },
}

pub(crate) struct ResourceTextLine {
    pub(crate) bytes: Vec<u8>,
    pub(crate) location: ResourceTextLocation,
}

pub(crate) struct ResourceTextReader<R> {
    inner: R,
    limits: LineLimits,
    byte_offset: u64,
    line: u64,
    record: u64,
    finished: bool,
}

impl<R: BufRead> ResourceTextReader<R> {
    pub(crate) fn new(inner: R, limits: LineLimits) -> Result<Self, ResourceTextError> {
        if limits.max_line_bytes == 0 || limits.max_records == 0 {
            return Err(ResourceTextError::new(
                ResourceTextLocation::new(0, 1, 0),
                ResourceTextErrorKind::InvalidLimit,
            ));
        }
        Ok(Self {
            inner,
            limits,
            byte_offset: 0,
            line: 1,
            record: 0,
            finished: false,
        })
    }

    pub(crate) fn next_line(&mut self) -> Result<Option<ResourceTextLine>, ResourceTextError> {
        if self.finished {
            return Ok(None);
        }
        let start = ResourceTextLocation::new(self.byte_offset, self.line, self.record);
        if self.record >= self.limits.max_records {
            let has_more = !self
                .inner
                .fill_buf()
                .map_err(|error| {
                    ResourceTextError::new(
                        start,
                        ResourceTextErrorKind::Io {
                            message: error.to_string(),
                        },
                    )
                })?
                .is_empty();
            if has_more {
                return Err(ResourceTextError::new(
                    start,
                    ResourceTextErrorKind::RecordLimitExceeded {
                        limit: self.limits.max_records,
                    },
                ));
            }
            self.finished = true;
            return Ok(None);
        }

        let mut bytes = Vec::new();
        loop {
            let available = self.inner.fill_buf().map_err(|error| {
                ResourceTextError::new(
                    ResourceTextLocation::new(self.byte_offset, self.line, self.record),
                    ResourceTextErrorKind::Io {
                        message: error.to_string(),
                    },
                )
            })?;
            if available.is_empty() {
                self.finished = true;
                if bytes.is_empty() {
                    return Ok(None);
                }
                if bytes.len() > self.limits.max_line_bytes {
                    return Err(self.line_too_long(start));
                }
                self.record += 1;
                return Ok(Some(ResourceTextLine {
                    bytes,
                    location: start,
                }));
            }

            let newline = available.iter().position(|byte| *byte == b'\n');
            let take = newline.unwrap_or(available.len());
            if newline.is_some() {
                let cr_in_available = take != 0 && available[take - 1] == b'\r';
                let cr_in_previous = take == 0 && bytes.last() == Some(&b'\r');
                let content_len = bytes
                    .len()
                    .saturating_add(take)
                    .saturating_sub(usize::from(cr_in_available || cr_in_previous));
                if content_len > self.limits.max_line_bytes {
                    return Err(self.line_too_long(start));
                }
                bytes.extend_from_slice(&available[..take]);
                if cr_in_available || cr_in_previous {
                    bytes.pop();
                }
                self.inner.consume(take + 1);
                self.byte_offset += take as u64 + 1;
                self.line += 1;
                self.record += 1;
                return Ok(Some(ResourceTextLine {
                    bytes,
                    location: start,
                }));
            }

            let raw_len = bytes.len().saturating_add(take);
            let pending_cr = raw_len == self.limits.max_line_bytes.saturating_add(1)
                && available.last() == Some(&b'\r');
            if raw_len > self.limits.max_line_bytes && !pending_cr {
                return Err(self.line_too_long(start));
            }
            bytes.extend_from_slice(available);
            self.inner.consume(take);
            self.byte_offset += take as u64;
        }
    }

    fn line_too_long(&self, start: ResourceTextLocation) -> ResourceTextError {
        ResourceTextError::new(
            ResourceTextLocation::new(
                start.byte_offset + self.limits.max_line_bytes as u64,
                start.line,
                start.record,
            ),
            ResourceTextErrorKind::LineTooLong {
                limit: self.limits.max_line_bytes,
            },
        )
    }
}
