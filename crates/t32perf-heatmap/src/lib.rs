//! Accessible, bounded SVG rendering for statistical PC-hit heatmaps.
//!
//! This crate renders only a [`t32perf_model::Heatmap`] that has been bound to
//! its source [`t32perf_model::PcHitHistogram`]. It never collects samples,
//! controls a target, or infers code coverage.

#![deny(missing_docs)]

use std::{cmp::Ordering, error::Error, fmt};

use t32perf_model::{
    FirmwareBindingStatus, Heatmap, HeatmapAgainstHistogramValidationError, HeatmapCell,
    HeatmapCellKey, HeatmapProjectionKind, PcHitHistogram, PcSamplingMethod, Sha256Digest,
};

/// Smallest accepted output limit in bytes.
pub const MIN_OUTPUT_LIMIT_BYTES: usize = 4 * 1024;
/// Largest accepted output limit in bytes.
pub const MAX_OUTPUT_LIMIT_BYTES: usize = 1024 * 1024;
/// Largest number of data rows that can be shown in one SVG.
pub const MAX_RENDER_ROWS: usize = 100;

/// Bounded rendering controls for [`render_svg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SvgRenderOptions {
    /// Maximum number of attributed cells displayed; valid range is `1..=100`.
    pub max_rows: usize,
    /// Maximum serialized SVG size; valid range is 4 KiB through 1 MiB.
    pub output_limit_bytes: usize,
}

impl Default for SvgRenderOptions {
    fn default() -> Self {
        Self {
            max_rows: 25,
            output_limit_bytes: 256 * 1024,
        }
    }
}

/// A rendered SVG and the explicit truncation information associated with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvgDocument {
    /// Complete standalone SVG document.
    pub svg: String,
    /// Number of attributed heatmap cells displayed in the chart.
    pub rendered_rows: usize,
    /// Number of attributed heatmap cells omitted by `max_rows`.
    pub omitted_rows: usize,
}

/// Failures that prevent rendering an SVG document.
#[derive(Debug)]
pub enum SvgRenderError {
    /// The heatmap did not validate against its exact source histogram.
    InvalidEvidence(HeatmapAgainstHistogramValidationError),
    /// `max_rows` was outside the supported range.
    InvalidMaxRows {
        /// Received value.
        actual: usize,
    },
    /// `output_limit_bytes` was outside the supported range.
    InvalidOutputLimit {
        /// Received value.
        actual: usize,
    },
    /// The valid document exceeded the caller's requested output bound.
    OutputLimitExceeded {
        /// Serialized SVG length in bytes.
        actual: usize,
        /// Caller-specified byte limit.
        limit: usize,
    },
}

impl fmt::Display for SvgRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEvidence(error) => write!(formatter, "invalid heatmap evidence: {error}"),
            Self::InvalidMaxRows { actual } => write!(
                formatter,
                "max_rows must be in 1..={MAX_RENDER_ROWS}; received {actual}"
            ),
            Self::InvalidOutputLimit { actual } => write!(
                formatter,
                "output_limit_bytes must be in {MIN_OUTPUT_LIMIT_BYTES}..={MAX_OUTPUT_LIMIT_BYTES}; received {actual}"
            ),
            Self::OutputLimitExceeded { actual, limit } => write!(
                formatter,
                "rendered SVG is {actual} bytes, exceeding its {limit}-byte limit"
            ),
        }
    }
}

impl Error for SvgRenderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidEvidence(error) => Some(error),
            Self::InvalidMaxRows { .. }
            | Self::InvalidOutputLimit { .. }
            | Self::OutputLimitExceeded { .. } => None,
        }
    }
}

/// Renders one validated coarse PC-sampling projection as an accessible SVG.
///
/// The renderer first invokes [`Heatmap::validate_against`]. Shares are derived
/// from the validated integer `denominator_hits`; this SVG does not claim
/// coverage, execution absence, average sampling rate, or exact runtime.
/// Function rows use descending hits. Address and source-line rows first select
/// top hits, then use address or source order respectively.
pub fn render_svg(
    histogram: &PcHitHistogram,
    observed_histogram_sha256: Sha256Digest,
    heatmap: &Heatmap,
    options: SvgRenderOptions,
) -> Result<SvgDocument, SvgRenderError> {
    heatmap
        .validate_against(histogram, observed_histogram_sha256)
        .map_err(SvgRenderError::InvalidEvidence)?;
    validate_options(options)?;
    let selected = select_cells(heatmap, options.max_rows);
    let omitted_rows = heatmap.cells.len().saturating_sub(selected.len());
    let rendered_rows = selected.len();
    let selected_has_debugger_locations =
        selected.iter().any(|cell| cell.debugger_location.is_some());
    let row_height = if selected_has_debugger_locations {
        ANNOTATED_ROW_HEIGHT
    } else {
        DEFAULT_ROW_HEIGHT
    };
    let has_unattributed = heatmap.unattributed_hits > 0;
    let row_count = rendered_rows + usize::from(has_unattributed);
    let metadata = metadata_lines(histogram, heatmap);
    let chart_top = 110_u32 + (metadata.len() as u32 * 20);
    let height =
        chart_top + 24 + (row_count as u32 * row_height) + u32::from(omitted_rows > 0) * 26;
    let title = format!(
        "{} statistical PC-sample hotspots",
        projection_label(heatmap)
    );
    let description = format!(
        "Statistical PC-hit projection. {} in-scope samples; {} unattributed samples. {}.",
        heatmap.denominator_hits,
        heatmap.unattributed_hits,
        truncation_text(omitted_rows)
    );
    let mut svg = String::with_capacity(8_192);
    svg.push_str(&format!(r#"<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="{height}" viewBox="0 0 1000 {height}" role="img" aria-labelledby="title desc">"#));
    svg.push_str("<title id=\"title\">");
    push_escaped(&mut svg, &title);
    svg.push_str("</title><desc id=\"desc\">");
    push_escaped(&mut svg, &description);
    svg.push_str("</desc>");
    svg.push_str(STYLE);
    if selected_has_debugger_locations {
        svg.push_str(ANNOTATION_STYLE);
    }
    text(&mut svg, 32, 38, "heading", &title);
    text(
        &mut svg,
        32,
        62,
        "subtitle",
        "Statistical PC samples — not an execution-completeness or exact-time claim",
    );
    for (index, line) in metadata.iter().enumerate() {
        text(&mut svg, 32, 92 + (index as u32 * 20), "metadata", line);
    }
    text(&mut svg, 32, chart_top - 10, "axis", "Location");
    text(&mut svg, 434, chart_top - 10, "axis", "PC samples");
    for (index, cell) in selected.iter().enumerate() {
        push_row(
            &mut svg,
            cell,
            heatmap.denominator_hits,
            index,
            chart_top,
            row_height,
            false,
        );
    }
    if has_unattributed {
        push_unattributed_row(
            &mut svg,
            heatmap.unattributed_hits,
            heatmap.denominator_hits,
            rendered_rows,
            chart_top,
            row_height,
        );
    }
    if omitted_rows > 0 {
        text(
            &mut svg,
            32,
            chart_top + (row_count as u32 * row_height) + 18,
            "truncation",
            &truncation_text(omitted_rows),
        );
    }
    svg.push_str("</svg>");
    if svg.len() > options.output_limit_bytes {
        return Err(SvgRenderError::OutputLimitExceeded {
            actual: svg.len(),
            limit: options.output_limit_bytes,
        });
    }
    Ok(SvgDocument {
        svg,
        rendered_rows,
        omitted_rows,
    })
}

const STYLE: &str = r#"<style>
:root { color-scheme: light dark; --foreground: #172033; --muted: #536176; --grid: #d7deea; --bar: #1769aa; --neutral: #778397; }
@media (prefers-color-scheme: dark) { :root { --foreground: #f8fafc; --muted: #c0cad8; --grid: #455166; --bar: #6db6ff; --neutral: #a8b3c5; } }
.heading { fill: var(--foreground); font: 500 20px sans-serif; } .subtitle { fill: var(--muted); font: 400 13px sans-serif; } .metadata { fill: var(--foreground); font: 400 13px sans-serif; } .axis { fill: var(--muted); font: 500 12px sans-serif; } .label { fill: var(--foreground); font: 400 13px sans-serif; } .value { fill: var(--foreground); font: 400 12px sans-serif; } .empty { fill: var(--muted); font: italic 400 12px sans-serif; } .truncation { fill: var(--muted); font: 400 12px sans-serif; } .track { fill: none; stroke: var(--grid); stroke-width: 1; } .bar { fill: var(--bar); } .unattributed { fill: var(--neutral); }
</style>"#;

const ANNOTATION_STYLE: &str =
    r#"<style>.annotation { fill: var(--muted); font: 400 11px sans-serif; }</style>"#;

const DEFAULT_ROW_HEIGHT: u32 = 42;
const ANNOTATED_ROW_HEIGHT: u32 = 58;

fn validate_options(options: SvgRenderOptions) -> Result<(), SvgRenderError> {
    if !(1..=MAX_RENDER_ROWS).contains(&options.max_rows) {
        return Err(SvgRenderError::InvalidMaxRows {
            actual: options.max_rows,
        });
    }
    if !(MIN_OUTPUT_LIMIT_BYTES..=MAX_OUTPUT_LIMIT_BYTES).contains(&options.output_limit_bytes) {
        return Err(SvgRenderError::InvalidOutputLimit {
            actual: options.output_limit_bytes,
        });
    }
    Ok(())
}
fn select_cells(heatmap: &Heatmap, max_rows: usize) -> Vec<&HeatmapCell> {
    let mut cells = heatmap.cells.iter().collect::<Vec<_>>();
    cells.sort_unstable_by(hit_order);
    cells.truncate(max_rows);
    match heatmap.projection_kind {
        HeatmapProjectionKind::Function => {}
        HeatmapProjectionKind::AddressRange => cells.sort_unstable_by(address_order),
        HeatmapProjectionKind::SourceLine => cells.sort_unstable_by(source_line_order),
    }
    cells
}
fn hit_order(left: &&HeatmapCell, right: &&HeatmapCell) -> Ordering {
    right
        .hits
        .cmp(&left.hits)
        .then_with(|| left.display_name.cmp(&right.display_name))
        .then_with(|| key_text(&left.key).cmp(&key_text(&right.key)))
}
fn address_order(left: &&HeatmapCell, right: &&HeatmapCell) -> Ordering {
    match (&left.key, &right.key) {
        (
            HeatmapCellKey::AddressRange {
                start_address: a,
                end_address: b,
            },
            HeatmapCellKey::AddressRange {
                start_address: c,
                end_address: d,
            },
        ) => a.cmp(c).then_with(|| b.cmp(d)),
        _ => Ordering::Equal,
    }
}
fn source_line_order(left: &&HeatmapCell, right: &&HeatmapCell) -> Ordering {
    match (&left.key, &right.key) {
        (
            HeatmapCellKey::SourceLine {
                source_path: a,
                line: b,
            },
            HeatmapCellKey::SourceLine {
                source_path: c,
                line: d,
            },
        ) => a.cmp(c).then_with(|| b.cmp(d)),
        _ => Ordering::Equal,
    }
}
fn key_text(key: &HeatmapCellKey) -> String {
    match key {
        HeatmapCellKey::AddressRange {
            start_address,
            end_address,
        } => format!("{start_address:016x}-{end_address:016x}"),
        HeatmapCellKey::Function { function_id } => function_id.clone(),
        HeatmapCellKey::SourceLine { source_path, line } => format!("{source_path}:{line:010}"),
    }
}
fn projection_label(heatmap: &Heatmap) -> &'static str {
    match heatmap.projection_kind {
        HeatmapProjectionKind::AddressRange => "Address-range",
        HeatmapProjectionKind::Function => "Function",
        HeatmapProjectionKind::SourceLine => "Source-line",
    }
}
fn metadata_lines(histogram: &PcHitHistogram, heatmap: &Heatmap) -> Vec<String> {
    let mut lines = vec![
        format!(
            "Method: {} · intrusive: {}",
            method_label(histogram.method),
            histogram.intrusive
        ),
        format!(
            "CPU: {} · core: {} · address space: {}",
            histogram.cpu, histogram.core_id, histogram.address_space
        ),
        format!(
            "Requested duration: {} · observed duration: {}",
            format_duration(histogram.requested_duration_ns),
            format_duration(histogram.observed_duration_ns)
        ),
        format!("In-scope hits: {}", heatmap.denominator_hits),
        format!("Unattributed in-scope hits: {}", heatmap.unattributed_hits),
        format!(
            "Last rate snapshot: {} Hz (not an average)",
            histogram.last_sample_rate_hz
        ),
        format!("PC-snoop failures: {}", histogram.snoop_failures),
        format!(
            "Firmware status: {}",
            firmware_status(histogram.firmware.status)
        ),
        format!(
            "ELF SHA-256: {}",
            histogram
                .firmware
                .elf_sha256
                .as_ref()
                .map_or("unverified", Sha256Digest::as_str)
        ),
        format!(
            "Quantitative gate: ≥{} in-scope hits · ≥{} observed · snoop failures ≤{} · StopAndGo retained runtime ≥{:.1}%",
            heatmap.quantitative_policy.min_in_scope_hits,
            format_duration(heatmap.quantitative_policy.min_observed_duration_ns),
            heatmap.quantitative_policy.max_snoop_failures,
            heatmap
                .quantitative_policy
                .min_stop_and_go_retained_runtime_percent,
        ),
        diagnostic_line(histogram),
    ];
    if heatmap.projection_kind == HeatmapProjectionKind::AddressRange
        && heatmap
            .cells
            .iter()
            .any(|cell| cell.debugger_location.is_some())
    {
        lines.push(
            "TRACE32 symbol-table labels: debugger-reported; labels do not verify firmware"
                .to_owned(),
        );
    }
    lines
}
fn diagnostic_line(histogram: &PcHitHistogram) -> String {
    if histogram.firmware.status == FirmwareBindingStatus::DeploymentAsserted {
        "Evidence status: diagnostic only — ELF was precommitted, target image was not compared."
            .to_owned()
    } else if histogram.snoop_failures > 0
        || !histogram.target_state_before.running
        || !histogram.target_state_after.running
    {
        "Evidence status: diagnostic only — snoop failures or a non-running target boundary were observed.".to_owned()
    } else {
        "Evidence status: statistical estimate.".to_owned()
    }
}
fn method_label(method: PcSamplingMethod) -> String {
    match method {
        PcSamplingMethod::Realtime => "RealTime".to_owned(),
        PcSamplingMethod::StopAndGo {
            configured_retained_runtime_percent,
            observed_retained_runtime_percent,
        } => format!(
            "StopAndGo (retained runtime configured {:.1}%, observed {:.1}%)",
            configured_retained_runtime_percent, observed_retained_runtime_percent
        ),
    }
}
fn firmware_status(status: FirmwareBindingStatus) -> &'static str {
    match status {
        FirmwareBindingStatus::Verified => "verified",
        FirmwareBindingStatus::DeploymentAsserted => {
            "deployment asserted (target image not compared)"
        }
        FirmwareBindingStatus::Unverified => "unverified",
        FirmwareBindingStatus::Mismatch => "mismatch",
    }
}
fn format_duration(duration_ns: u64) -> String {
    if duration_ns.is_multiple_of(1_000_000_000) {
        format!("{} s", duration_ns / 1_000_000_000)
    } else if duration_ns.is_multiple_of(1_000_000) {
        format!("{} ms", duration_ns / 1_000_000)
    } else if duration_ns.is_multiple_of(1_000) {
        format!("{} µs", duration_ns / 1_000)
    } else {
        format!("{duration_ns} ns")
    }
}
fn push_row(
    svg: &mut String,
    cell: &HeatmapCell,
    denominator: u64,
    index: usize,
    chart_top: u32,
    row_height: u32,
    unattributed: bool,
) {
    let y = chart_top + (index as u32 * row_height);
    text(svg, 32, y + 19, "label", &label_for(cell));
    svg.push_str(&format!(
        "<line class=\"track\" x1=\"434\" y1=\"{}\" x2=\"814\" y2=\"{}\"/>",
        y + 14,
        y + 14
    ));
    if cell.hits == 0 {
        text(svg, 434, y + 34, "empty", "not observed");
    } else {
        let width = bar_width(cell.hits, denominator);
        let class = if unattributed { "unattributed" } else { "bar" };
        svg.push_str(&format!(
            "<rect class=\"{class}\" x=\"434\" y=\"{}\" width=\"{width}\" height=\"16\"/>",
            y + 6
        ));
        text(
            svg,
            824,
            y + 19,
            "value",
            &hit_label(cell.hits, denominator),
        );
    }
    if let Some(annotation) = debugger_annotation_for(cell) {
        text(svg, 32, y + 43, "annotation", &annotation);
    }
}
fn push_unattributed_row(
    svg: &mut String,
    hits: u64,
    denominator: u64,
    index: usize,
    chart_top: u32,
    row_height: u32,
) {
    let cell = HeatmapCell {
        key: HeatmapCellKey::Function {
            function_id: "renderer-unattributed".to_owned(),
        },
        display_name: "Unattributed in-scope samples".to_owned(),
        hits,
        debugger_location: None,
    };
    push_row(svg, &cell, denominator, index, chart_top, row_height, true);
}
fn label_for(cell: &HeatmapCell) -> String {
    match &cell.key {
        HeatmapCellKey::AddressRange {
            start_address,
            end_address,
        } => format!("{start_address:#010x}..{end_address:#010x}"),
        HeatmapCellKey::Function { .. } => clip_label(&cell.display_name),
        HeatmapCellKey::SourceLine { source_path, line } => {
            clip_label(&format!("{source_path}:{line}"))
        }
    }
}
fn debugger_annotation_for(cell: &HeatmapCell) -> Option<String> {
    let location = cell.debugger_location.as_ref()?;
    let mut annotation = format!("dominant {}/{}", location.dominant_hits, location.hits);
    let mut label = String::new();
    if let Some(function_name) = &location.function_name {
        label.push_str(function_name);
    }
    if let (Some(source_file), Some(source_line)) = (&location.source_file, location.source_line) {
        if !label.is_empty() {
            label.push_str(" · ");
        }
        label.push_str(source_file);
        label.push(':');
        label.push_str(&source_line.to_string());
    }
    if !label.is_empty() {
        annotation.push_str(" · ");
        annotation.push_str(&clip_label(&label));
    }
    Some(annotation)
}
fn clip_label(value: &str) -> String {
    const LIMIT: usize = 46;
    let mut chars = value.chars();
    let prefix = chars.by_ref().take(LIMIT).collect::<String>();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}
fn hit_label(hits: u64, denominator: u64) -> String {
    let tenths_percent = (u128::from(hits) * 1_000) / u128::from(denominator);
    format!("{hits} / {}.{}%", tenths_percent / 10, tenths_percent % 10)
}
fn bar_width(hits: u64, denominator: u64) -> u64 {
    ((u128::from(hits) * 380) / u128::from(denominator)) as u64
}
fn truncation_text(omitted_rows: usize) -> String {
    if omitted_rows == 0 {
        "All attributed rows are shown.".to_owned()
    } else {
        format!("Top rows shown; {omitted_rows} attributed row(s) omitted by max_rows.")
    }
}
fn text(svg: &mut String, x: u32, y: u32, class: &str, value: &str) {
    svg.push_str(&format!("<text class=\"{class}\" x=\"{x}\" y=\"{y}\">"));
    push_escaped(svg, value);
    svg.push_str("</text>");
}
fn push_escaped(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            _ => output.push(character),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use t32perf_model::{
        DebuggerHotspotLocation, DebuggerSymbolization, DebuggerSymbolizationSource,
        DebuggerSymbolizationTrust, FirmwareBinding, FirmwareBindingProof, HeatmapCellKey,
        HeatmapQuality, HeatmapSchemaVersion, OutOfScopeHits, PcHitBucket,
        PcHitHistogramSchemaVersion, QuantitativePolicy, TargetExecutionState,
    };
    fn digest(character: char) -> Sha256Digest {
        Sha256Digest::new(character.to_string().repeat(64)).unwrap()
    }
    fn histogram() -> PcHitHistogram {
        PcHitHistogram {
            schema: PcHitHistogramSchemaVersion,
            session_id: "session-01".to_owned(),
            endpoint_fingerprint: digest('f'),
            endpoint_fingerprint_scheme:
                t32perf_model::EndpointFingerprintScheme::T32PerfEndpointFingerprintV2,
            trace32: "R.2026.02".to_owned(),
            cpu: "CortexM0+".to_owned(),
            address_space: "P:".to_owned(),
            core_id: 0,
            method: PcSamplingMethod::Realtime,
            intrusive: false,
            requested_duration_ns: 1_000_000,
            observed_duration_ns: 1_100_000,
            last_sample_rate_hz: 2_000,
            snoop_failures: 1,
            target_state_before: TargetExecutionState {
                powered: true,
                running: true,
                halted: false,
            },
            target_state_after: TargetExecutionState {
                powered: true,
                running: true,
                halted: false,
            },
            firmware: FirmwareBinding {
                status: FirmwareBindingStatus::Verified,
                elf_sha256: Some(digest('e')),
                proof: Some(FirmwareBindingProof::DigestBoundDeployment {
                    evidence_artifact_sha256: digest('d'),
                }),
            },
            cleanup_complete: true,
            in_scope_hits: 10,
            buckets: vec![
                PcHitBucket {
                    start_address: 0x1000,
                    end_address: 0x1010,
                    hits: 6,
                },
                PcHitBucket {
                    start_address: 0x1010,
                    end_address: 0x1020,
                    hits: 4,
                },
            ],
            debugger_symbolization: None,
        }
    }
    fn heatmap(kind: HeatmapProjectionKind, cells: Vec<HeatmapCell>) -> Heatmap {
        let attributed_hits = cells.iter().map(|cell| cell.hits).sum();
        Heatmap {
            schema: HeatmapSchemaVersion,
            session_id: "session-01".to_owned(),
            histogram_sha256: digest('a'),
            quality: HeatmapQuality::Statistical,
            projection_kind: kind,
            quantitative_policy: QuantitativePolicy {
                min_in_scope_hits: 1,
                min_observed_duration_ns: 1,
                min_stop_and_go_retained_runtime_percent: 90.0,
                max_snoop_failures: 1,
            },
            denominator_hits: 10,
            attributed_hits,
            unattributed_hits: 10 - attributed_hits,
            out_of_scope_hits: OutOfScopeHits::Unknown,
            cells,
        }
    }
    fn render(map: &Heatmap) -> SvgDocument {
        render_svg(&histogram(), digest('a'), map, SvgRenderOptions::default()).unwrap()
    }
    #[test]
    fn renders_function_rows_by_descending_hits_and_unattributed() {
        let map = heatmap(
            HeatmapProjectionKind::Function,
            vec![function("worker", 2), function("main", 6)],
        );
        let document = render(&map);
        assert!(document.svg.find("main").unwrap() < document.svg.find("worker").unwrap());
        assert!(document.svg.contains("Unattributed in-scope samples"));
        assert!(document.svg.contains("6 / 60.0%"));
    }
    #[test]
    fn renders_address_top_hits_in_address_order() {
        let map = heatmap(
            HeatmapProjectionKind::AddressRange,
            vec![address(0x1000, 0x1010, 6), address(0x1010, 0x1020, 4)],
        );
        let document = render(&map);
        assert!(
            document.svg.find("0x00001000").unwrap() < document.svg.find("0x00001010").unwrap()
        );
    }
    #[test]
    fn renders_source_line_top_hits_in_source_order() {
        let map = heatmap(
            HeatmapProjectionKind::SourceLine,
            vec![source("z.c", 2, 2), source("a.c", 9, 6)],
        );
        let document = render(&map);
        assert!(document.svg.find("a.c:9").unwrap() < document.svg.find("z.c:2").unwrap());
    }
    #[test]
    fn zero_hits_are_not_described_as_coverage() {
        let map = heatmap(HeatmapProjectionKind::Function, vec![function("idle", 0)]);
        let document = render(&map);
        assert!(document.svg.contains("not observed"));
        assert!(!document.svg.contains("unexecuted"));
        assert!(!document.svg.contains("coverage"));
    }
    #[test]
    fn includes_required_metadata_and_escapes_labels() {
        let map = heatmap(HeatmapProjectionKind::Function, vec![function("<&\"'", 10)]);
        let document = render(&map);
        assert!(document.svg.contains("Method: RealTime · intrusive: false"));
        assert!(
            document
                .svg
                .contains("Requested duration: 1 ms · observed duration: 1100 µs")
        );
        assert!(
            document
                .svg
                .contains("Last rate snapshot: 2000 Hz (not an average)")
        );
        assert!(document.svg.contains("PC-snoop failures: 1"));
        assert!(document.svg.contains("Firmware status: verified"));
        assert!(
            document.svg.contains(
                "Quantitative gate: ≥1 in-scope hits · ≥1 ns observed · snoop failures ≤1"
            )
        );
        assert!(
            document
                .svg
                .contains("CPU: CortexM0+ · core: 0 · address space: P:")
        );
        assert!(document.svg.contains(
            "ELF SHA-256: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        ));
        assert!(document.svg.contains("Evidence status: diagnostic only"));
        assert!(document.svg.contains("&lt;&amp;&quot;&apos;"));
        assert!(document.svg.contains("aria-labelledby=\"title desc\""));
        assert!(!document.svg.contains("class=\"background\""));
        assert!(!document.svg.contains("rx=\""));
    }
    #[test]
    fn labels_deployment_assertion_without_claiming_verification() {
        let map = heatmap(HeatmapProjectionKind::Function, vec![function("main", 10)]);
        let mut asserted = histogram();
        asserted.firmware.status = FirmwareBindingStatus::DeploymentAsserted;
        asserted.firmware.proof = Some(FirmwareBindingProof::PrecommittedElfAssertion {
            evidence_artifact_sha256: digest('d'),
        });
        let document =
            render_svg(&asserted, digest('a'), &map, SvgRenderOptions::default()).unwrap();
        assert!(
            document
                .svg
                .contains("Firmware status: deployment asserted (target image not compared)")
        );
        assert!(document.svg.contains(
            "Evidence status: diagnostic only — ELF was precommitted, target image was not compared."
        ));
        assert!(!document.svg.contains("Firmware status: verified"));
    }
    #[test]
    fn renders_debugger_reported_address_labels_with_xml_escaping() {
        let long_function = format!("main<&{}", "x".repeat(80));
        let location = DebuggerHotspotLocation {
            bucket_start_address: 0x1000,
            bucket_end_address: 0x1010,
            hits: 6,
            dominant_start_address: 0x1004,
            dominant_end_address: 0x1008,
            dominant_hits: 5,
            function_name: Some(long_function),
            source_file: Some("main.c".to_owned()),
            source_line: Some(42),
        };
        let mut input = histogram();
        input.debugger_symbolization = Some(DebuggerSymbolization {
            source: DebuggerSymbolizationSource::Trace32SymbolTable,
            trust: DebuggerSymbolizationTrust::DebuggerReported,
            refinement_granularity_bytes: 4,
            locations: vec![location.clone()],
        });
        let mut map = heatmap(
            HeatmapProjectionKind::AddressRange,
            vec![address(0x1000, 0x1010, 6), address(0x1010, 0x1020, 4)],
        );
        map.cells[0].debugger_location = Some(location);
        let document = render_svg(&input, digest('a'), &map, SvgRenderOptions::default()).unwrap();
        assert!(document.svg.contains(
            "TRACE32 symbol-table labels: debugger-reported; labels do not verify firmware"
        ));
        assert!(document.svg.contains("height=\"490\""));
        assert!(
            document
                .svg
                .contains("<text class=\"label\" x=\"32\" y=\"369\">0x00001000..0x00001010</text>")
        );
        assert!(document.svg.contains("6 / 60.0%"));
        assert!(document.svg.contains(
            "<text class=\"annotation\" x=\"32\" y=\"393\">dominant 5/6 · main&lt;&amp;"
        ));
        assert!(document.svg.contains("…</text>"));
    }
    #[test]
    fn rejects_digest_mismatch_and_option_boundaries() {
        let map = heatmap(HeatmapProjectionKind::Function, vec![function("main", 10)]);
        assert!(matches!(
            render_svg(&histogram(), digest('b'), &map, SvgRenderOptions::default()),
            Err(SvgRenderError::InvalidEvidence(_))
        ));
        assert!(matches!(
            render_svg(
                &histogram(),
                digest('a'),
                &map,
                SvgRenderOptions {
                    max_rows: 0,
                    ..SvgRenderOptions::default()
                }
            ),
            Err(SvgRenderError::InvalidMaxRows { .. })
        ));
        assert!(matches!(
            render_svg(
                &histogram(),
                digest('a'),
                &map,
                SvgRenderOptions {
                    max_rows: 101,
                    ..SvgRenderOptions::default()
                }
            ),
            Err(SvgRenderError::InvalidMaxRows { .. })
        ));
    }
    #[test]
    fn uses_wide_arithmetic_for_full_width_hit_counts() {
        assert_eq!(bar_width(u64::MAX, u64::MAX), 380);
        assert_eq!(
            hit_label(u64::MAX, u64::MAX),
            "18446744073709551615 / 100.0%"
        );
    }
    fn function(name: &str, hits: u64) -> HeatmapCell {
        HeatmapCell {
            key: HeatmapCellKey::Function {
                function_id: name.to_owned(),
            },
            display_name: name.to_owned(),
            hits,
            debugger_location: None,
        }
    }
    fn address(start_address: u64, end_address: u64, hits: u64) -> HeatmapCell {
        HeatmapCell {
            key: HeatmapCellKey::AddressRange {
                start_address,
                end_address,
            },
            display_name: "ignored for addresses".to_owned(),
            hits,
            debugger_location: None,
        }
    }
    fn source(path: &str, line: u32, hits: u64) -> HeatmapCell {
        HeatmapCell {
            key: HeatmapCellKey::SourceLine {
                source_path: path.to_owned(),
                line,
            },
            display_name: format!("{path}:{line}"),
            hits,
            debugger_location: None,
        }
    }
}
