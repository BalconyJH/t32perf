//! Bounded synchronous NDJSON I/O for derived function spans.

use std::{
    fmt,
    io::{self, BufRead, Read, Write},
};

use serde::Serialize;
use serde::de::DeserializeOwned;
use t32perf_model::{DerivedStreamHeader, DerivedValidationError, FunctionSpan, strict_json};
use thiserror::Error;

/// Default maximum JSON payload size of one derived-stream line.
pub const DEFAULT_DERIVED_LINE_LIMIT: usize = 1024 * 1024;

/// Kind of record associated with a derived-stream error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivedRecordKind {
    /// The first-line [`DerivedStreamHeader`].
    Header,
    /// A subsequent [`FunctionSpan`].
    FunctionSpan,
}

impl fmt::Display for DerivedRecordKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header => formatter.write_str("header"),
            Self::FunctionSpan => formatter.write_str("function span"),
        }
    }
}

/// A precise derived NDJSON read or write failure.
#[derive(Debug, Error)]
pub enum DerivedStreamError {
    /// The configured line limit is zero or cannot reserve delimiter bytes.
    #[error("derived-stream line limit {limit} is invalid")]
    InvalidLineLimit {
        /// Rejected byte limit.
        limit: usize,
    },
    /// A writer header has no Session identifier.
    #[error("derived-stream header session_id is empty")]
    EmptyHeaderSession,
    /// A reader was not given an expected Session identifier.
    #[error("expected derived-stream session_id is empty")]
    EmptyExpectedSession,
    /// The stream contains no header record.
    #[error("derived stream is empty; expected a header on line 1")]
    EmptyStream,
    /// The stream header belongs to another Session.
    #[error(
        "derived-stream session `{actual}` does not match expected Session `{expected}` on line 1"
    )]
    SessionMismatch {
        /// Required Session identifier.
        expected: String,
        /// Session identifier found in the header.
        actual: String,
    },
    /// A JSON line is empty.
    #[error("derived-stream line {line} is empty")]
    EmptyLine {
        /// One-based stream line number.
        line: u64,
    },
    /// A line exceeded its configured JSON byte limit.
    #[error(
        "derived-stream line {line} exceeds {limit} bytes; observed at least {observed_at_least} bytes"
    )]
    LineTooLong {
        /// One-based stream line number.
        line: u64,
        /// Configured maximum JSON bytes, excluding CRLF or LF.
        limit: usize,
        /// Bytes observed before bounded reading stopped.
        observed_at_least: usize,
    },
    /// A record could not be serialized as JSON.
    #[error("failed to serialize derived-stream {record} on line {line}: {source}")]
    Serialization {
        /// One-based stream line number.
        line: u64,
        /// Record kind being serialized.
        record: DerivedRecordKind,
        /// JSON serialization error.
        #[source]
        source: serde_json::Error,
    },
    /// A record contains malformed or incompatible JSON.
    #[error("invalid derived-stream {record} JSON on line {line}: {source}")]
    InvalidJson {
        /// One-based stream line number.
        line: u64,
        /// Record kind being decoded.
        record: DerivedRecordKind,
        /// JSON decoding or schema-version error.
        #[source]
        source: serde_json::Error,
    },
    /// A decoded span violates the derived model invariants.
    #[error("invalid derived function span on line {line}: {source}")]
    InvalidSpan {
        /// One-based stream line number.
        line: u64,
        /// Derived span invariant error.
        #[source]
        source: DerivedValidationError,
    },
    /// Stream I/O failed at a known line.
    #[error("derived-stream I/O failed at line {line}: {source}")]
    Io {
        /// One-based stream line number.
        line: u64,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The one-based line counter overflowed.
    #[error("derived-stream line counter overflowed after line {line}")]
    LineNumberOverflow {
        /// Last representable line number.
        line: u64,
    },
    /// The count of successfully written span records overflowed.
    #[error("derived-stream span count overflowed after line {line}")]
    SpanCountOverflow {
        /// Line containing the span that exceeded the counter.
        line: u64,
    },
    /// A direct read was attempted after a previous terminal decoding error.
    #[error("derived-stream reader is unusable after a previous error")]
    ReaderPoisoned,
}

/// Synchronous writer for a header followed by function-span NDJSON records.
#[derive(Debug)]
pub struct DerivedNdjsonWriter<W> {
    writer: W,
    header: DerivedStreamHeader,
    max_line_bytes: usize,
    next_line: u64,
    spans_written: u64,
}

impl<W: Write> DerivedNdjsonWriter<W> {
    /// Creates a writer using [`DEFAULT_DERIVED_LINE_LIMIT`].
    pub fn new(writer: W, header: DerivedStreamHeader) -> Result<Self, DerivedStreamError> {
        Self::with_line_limit(writer, header, DEFAULT_DERIVED_LINE_LIMIT)
    }

    /// Creates a writer with an explicit maximum JSON payload size per line.
    pub fn with_line_limit(
        writer: W,
        header: DerivedStreamHeader,
        max_line_bytes: usize,
    ) -> Result<Self, DerivedStreamError> {
        validate_line_limit(max_line_bytes)?;
        if header.session_id.is_empty() {
            return Err(DerivedStreamError::EmptyHeaderSession);
        }
        let mut stream = Self {
            writer,
            header,
            max_line_bytes,
            next_line: 1,
            spans_written: 0,
        };
        let header = stream.header.clone();
        stream.write_record(&header, DerivedRecordKind::Header)?;
        Ok(stream)
    }

    /// Returns the header already written to line one.
    #[must_use]
    pub fn header(&self) -> &DerivedStreamHeader {
        &self.header
    }

    /// Returns the number of function-span records written successfully.
    #[must_use]
    pub const fn spans_written(&self) -> u64 {
        self.spans_written
    }

    /// Validates and writes one function span.
    pub fn write_span(&mut self, span: &FunctionSpan) -> Result<(), DerivedStreamError> {
        let line = self.next_line;
        span.validate()
            .map_err(|source| DerivedStreamError::InvalidSpan { line, source })?;
        self.write_record(span, DerivedRecordKind::FunctionSpan)?;
        self.spans_written = self
            .spans_written
            .checked_add(1)
            .ok_or(DerivedStreamError::SpanCountOverflow { line })?;
        Ok(())
    }

    /// Writes every span from an iterator in order.
    pub fn write_spans<'a>(
        &mut self,
        spans: impl IntoIterator<Item = &'a FunctionSpan>,
    ) -> Result<(), DerivedStreamError> {
        for span in spans {
            self.write_span(span)?;
        }
        Ok(())
    }

    /// Flushes the underlying writer.
    pub fn flush(&mut self) -> Result<(), DerivedStreamError> {
        self.writer
            .flush()
            .map_err(|source| DerivedStreamError::Io {
                line: self.next_line,
                source,
            })
    }

    /// Flushes and returns the underlying writer.
    pub fn finish(mut self) -> Result<W, DerivedStreamError> {
        self.flush()?;
        Ok(self.writer)
    }

    fn write_record<T: Serialize>(
        &mut self,
        record: &T,
        record_kind: DerivedRecordKind,
    ) -> Result<(), DerivedStreamError> {
        let line = self.next_line;
        let encoded =
            serde_json::to_vec(record).map_err(|source| DerivedStreamError::Serialization {
                line,
                record: record_kind,
                source,
            })?;
        if encoded.len() > self.max_line_bytes {
            return Err(DerivedStreamError::LineTooLong {
                line,
                limit: self.max_line_bytes,
                observed_at_least: encoded.len(),
            });
        }
        self.writer
            .write_all(&encoded)
            .and_then(|()| self.writer.write_all(b"\n"))
            .map_err(|source| DerivedStreamError::Io { line, source })?;
        self.next_line = self
            .next_line
            .checked_add(1)
            .ok_or(DerivedStreamError::LineNumberOverflow { line })?;
        Ok(())
    }
}

/// Bounded synchronous reader for a derived-span NDJSON stream.
#[derive(Debug)]
pub struct DerivedNdjsonReader<R> {
    reader: R,
    header: DerivedStreamHeader,
    max_line_bytes: usize,
    next_line: u64,
    buffer: Vec<u8>,
    finished: bool,
    poisoned: bool,
}

impl<R: BufRead> DerivedNdjsonReader<R> {
    /// Reads and validates a header using [`DEFAULT_DERIVED_LINE_LIMIT`].
    pub fn new(reader: R, expected_session_id: &str) -> Result<Self, DerivedStreamError> {
        Self::with_line_limit(reader, expected_session_id, DEFAULT_DERIVED_LINE_LIMIT)
    }

    /// Reads and validates a header with an explicit maximum JSON size per line.
    pub fn with_line_limit(
        mut reader: R,
        expected_session_id: &str,
        max_line_bytes: usize,
    ) -> Result<Self, DerivedStreamError> {
        validate_line_limit(max_line_bytes)?;
        if expected_session_id.is_empty() {
            return Err(DerivedStreamError::EmptyExpectedSession);
        }
        let mut buffer = Vec::new();
        if !read_bounded_line(&mut reader, &mut buffer, max_line_bytes, 1)? {
            return Err(DerivedStreamError::EmptyStream);
        }
        if buffer.is_empty() {
            return Err(DerivedStreamError::EmptyLine { line: 1 });
        }
        let header: DerivedStreamHeader = decode_record(&buffer, 1, DerivedRecordKind::Header)?;
        if header.session_id.is_empty() {
            return Err(DerivedStreamError::EmptyHeaderSession);
        }
        if header.session_id != expected_session_id {
            return Err(DerivedStreamError::SessionMismatch {
                expected: expected_session_id.to_owned(),
                actual: header.session_id,
            });
        }
        Ok(Self {
            reader,
            header,
            max_line_bytes,
            next_line: 2,
            buffer,
            finished: false,
            poisoned: false,
        })
    }

    /// Returns the validated first-line header.
    #[must_use]
    pub fn header(&self) -> &DerivedStreamHeader {
        &self.header
    }

    /// Reads, decodes, and validates the next function span.
    pub fn read_span(&mut self) -> Result<Option<FunctionSpan>, DerivedStreamError> {
        if self.poisoned {
            return Err(DerivedStreamError::ReaderPoisoned);
        }
        if self.finished {
            return Ok(None);
        }
        let result = self.read_span_inner();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Returns the underlying buffered reader.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.reader
    }

    fn read_span_inner(&mut self) -> Result<Option<FunctionSpan>, DerivedStreamError> {
        let line = self.next_line;
        if !read_bounded_line(
            &mut self.reader,
            &mut self.buffer,
            self.max_line_bytes,
            line,
        )? {
            self.finished = true;
            return Ok(None);
        }
        if self.buffer.is_empty() {
            return Err(DerivedStreamError::EmptyLine { line });
        }
        let span: FunctionSpan =
            decode_record(&self.buffer, line, DerivedRecordKind::FunctionSpan)?;
        span.validate()
            .map_err(|source| DerivedStreamError::InvalidSpan { line, source })?;
        self.next_line = self
            .next_line
            .checked_add(1)
            .ok_or(DerivedStreamError::LineNumberOverflow { line })?;
        Ok(Some(span))
    }
}

impl<R: BufRead> Iterator for DerivedNdjsonReader<R> {
    type Item = Result<FunctionSpan, DerivedStreamError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished || self.poisoned {
            return None;
        }
        match self.read_span() {
            Ok(Some(span)) => Some(Ok(span)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }
}

fn validate_line_limit(limit: usize) -> Result<(), DerivedStreamError> {
    if limit == 0 || limit.checked_add(2).is_none() {
        return Err(DerivedStreamError::InvalidLineLimit { limit });
    }
    Ok(())
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    max_line_bytes: usize,
    line: u64,
) -> Result<bool, DerivedStreamError> {
    buffer.clear();
    let read_limit = max_line_bytes
        .checked_add(2)
        .ok_or(DerivedStreamError::InvalidLineLimit {
            limit: max_line_bytes,
        })?;
    let mut limited = reader.take(read_limit as u64);
    let bytes_read = limited
        .read_until(b'\n', buffer)
        .map_err(|source| DerivedStreamError::Io { line, source })?;
    if bytes_read == 0 {
        return Ok(false);
    }
    if buffer.last() == Some(&b'\n') {
        buffer.pop();
        if buffer.last() == Some(&b'\r') {
            buffer.pop();
        }
    }
    if buffer.len() > max_line_bytes {
        return Err(DerivedStreamError::LineTooLong {
            line,
            limit: max_line_bytes,
            observed_at_least: buffer.len(),
        });
    }
    Ok(true)
}

fn decode_record<T: DeserializeOwned>(
    bytes: &[u8],
    line: u64,
    record: DerivedRecordKind,
) -> Result<T, DerivedStreamError> {
    strict_json::from_slice(bytes).map_err(|source| DerivedStreamError::InvalidJson {
        line,
        record,
        source,
    })
}
