//! Bounded SVG rendering for flat sampled PC profiles.
//!
//! PC samples identify locations, not caller/callee stacks. This crate therefore
//! always labels its output as a synthetic flat hierarchy.

#![deny(missing_docs)]

use std::{cmp::Ordering, collections::BTreeSet, error::Error, fmt};

use t32perf_model::{
    FoldedStackFrame, FoldedStackProfile, FoldedStackProfileValidationError, Heatmap,
    HeatmapAgainstHistogramValidationError, HeatmapCell, HeatmapCellKey, HeatmapProjectionKind,
    PcHitHistogram, Sha256Digest, StackSampleTermination,
};
use takumi::{
    prelude::{
        Color, ColorInput, Display, FlexDirection, Fonts, Length::Px, Node, Style,
        StyleDeclaration, SvgOptions, Viewport,
    },
    render_svg as render_takumi_svg,
};

/// Fixed native SVG root-frame width.
pub const ROOT_WIDTH: u32 = 1_200;
const ROOT_FRAME_HEIGHT: u32 = 28;
const STACK_FRAME_HEIGHT: u32 = 28;
const FLAT_LEAF_HEIGHT: u32 = 44;
/// Leaves room for boundary and aggregated-siblings markers per selected
/// real frame while keeping worst-case escaped SVG comfortably below 1 MiB.
const MAX_STACK_REAL_NODES: usize = 128;
/// Maximum visible leaf frames.
pub const MAX_FRAMES: usize = 100;
/// Smallest output byte limit.
pub const MIN_OUTPUT_LIMIT_BYTES: usize = 4 * 1024;
/// Largest output byte limit.
pub const MAX_OUTPUT_LIMIT_BYTES: usize = 1024 * 1024;

/// Bounds for [`render_flat_sampled_svg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlatFlameGraphOptions {
    /// Maximum visible frames, in `1..=100`.
    pub max_frames: usize,
    /// Maximum serialized SVG size in bytes.
    pub output_limit_bytes: usize,
}

impl Default for FlatFlameGraphOptions {
    fn default() -> Self {
        Self {
            max_frames: 25,
            output_limit_bytes: 256 * 1024,
        }
    }
}

/// Rendered SVG and explicit aggregation accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatFlameGraphDocument {
    /// Standalone SVG document.
    pub svg: String,
    /// Visible frames, including `[other sampled PCs]` if present.
    pub rendered_frames: usize,
    /// Original frames absorbed into `[other sampled PCs]`.
    pub omitted_frames: usize,
}

/// Bounds for [`render_stack_sampled_svg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackFlameGraphOptions {
    /// Maximum observed stack-frame depth to show, in `1..=64`.
    pub max_depth: usize,
    /// Maximum serialized SVG size in bytes.
    pub output_limit_bytes: usize,
}

impl Default for StackFlameGraphOptions {
    fn default() -> Self {
        Self {
            max_depth: 64,
            output_limit_bytes: 256 * 1024,
        }
    }
}

/// A true observed-stack flame graph and its depth-truncation accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackFlameGraphDocument {
    /// Complete standalone SVG document.
    pub svg: String,
    /// Number of visible observed stack frames, excluding synthetic markers.
    pub rendered_frames: usize,
    /// Number of visible synthetic markers for exact outer-boundary reasons.
    pub boundary_markers: usize,
    /// Number of visible synthetic markers aggregating omitted observed paths.
    pub other_markers: usize,
    /// Number of real observed frame nodes represented by `other_markers`.
    pub aggregated_nodes: usize,
    /// Maximum number of observed frame levels hidden below the depth limit.
    pub omitted_depth: usize,
}

/// Failures that prevent rendering.
#[derive(Debug)]
pub enum FlatFlameGraphError {
    /// Input evidence failed exact validation.
    InvalidEvidence(HeatmapAgainstHistogramValidationError),
    /// Frame limit was unsupported.
    InvalidMaxFrames {
        /// Received value.
        actual: usize,
    },
    /// Output byte limit was unsupported.
    InvalidOutputLimit {
        /// Received value.
        actual: usize,
    },
    /// Takumi SVG serialization failed.
    Takumi {
        /// Backend error text.
        message: String,
    },
    /// Takumi returned an unexpected SVG envelope.
    InvalidNativeSvg {
        /// The required SVG structure that was absent.
        required: &'static str,
    },
    /// Final SVG exceeded its requested bound.
    OutputLimitExceeded {
        /// Actual byte size.
        actual: usize,
        /// Requested limit.
        limit: usize,
    },
    /// A folded stack profile violated its data contract.
    InvalidStackProfile(FoldedStackProfileValidationError),
    /// A valid profile had no observed paths to render.
    EmptyStackProfile,
    /// Stack depth bound was unsupported.
    InvalidMaxDepth {
        /// Received value.
        actual: usize,
    },
}

impl fmt::Display for FlatFlameGraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEvidence(error) => write!(f, "invalid heatmap evidence: {error}"),
            Self::InvalidMaxFrames { actual } => write!(
                f,
                "max_frames must be in 1..={MAX_FRAMES}; received {actual}"
            ),
            Self::InvalidOutputLimit { actual } => write!(
                f,
                "output_limit_bytes must be in {MIN_OUTPUT_LIMIT_BYTES}..={MAX_OUTPUT_LIMIT_BYTES}; received {actual}"
            ),
            Self::Takumi { message } => write!(f, "Takumi SVG rendering failed: {message}"),
            Self::InvalidNativeSvg { required } => {
                write!(f, "Takumi SVG is missing required {required}")
            }
            Self::OutputLimitExceeded { actual, limit } => write!(
                f,
                "rendered SVG is {actual} bytes, exceeding its {limit}-byte limit"
            ),
            Self::InvalidStackProfile(error) => write!(f, "invalid folded stack profile: {error}"),
            Self::EmptyStackProfile => write!(f, "folded stack profile has no observed paths"),
            Self::InvalidMaxDepth { actual } => {
                write!(f, "max_depth must be in 1..=64; received {actual}")
            }
        }
    }
}

impl Error for FlatFlameGraphError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidEvidence(error) => Some(error),
            Self::InvalidStackProfile(error) => Some(error),
            _ => None,
        }
    }
}

/// Renders a flat sampled profile, never a call-stack flame graph.
///
/// `Heatmap::validate_against` runs before projecting. Function/source cells
/// become leaves. Address cells with a debugger location produce one exact
/// debugger-reported code leaf for `dominant_hits` plus a residual address leaf.
/// The output states `synthetic hierarchy` and `no call-stack evidence`.
pub fn render_flat_sampled_svg(
    histogram: &PcHitHistogram,
    observed_histogram_sha256: Sha256Digest,
    heatmap: &Heatmap,
    options: FlatFlameGraphOptions,
) -> Result<FlatFlameGraphDocument, FlatFlameGraphError> {
    heatmap
        .validate_against(histogram, observed_histogram_sha256)
        .map_err(FlatFlameGraphError::InvalidEvidence)?;
    validate_options(options)?;
    let leaves = project_leaves(heatmap);
    let (visible, omitted_frames) = bound_leaves(leaves, options.max_frames);
    debug_assert_eq!(
        visible.iter().map(|leaf| leaf.hits).sum::<u64>(),
        heatmap.denominator_hits
    );
    let native = render_native_geometry(&visible, heatmap.denominator_hits)?;
    let svg =
        append_accessible_overlay(native, &visible, heatmap.denominator_hits, omitted_frames)?;
    if svg.len() > options.output_limit_bytes {
        return Err(FlatFlameGraphError::OutputLimitExceeded {
            actual: svg.len(),
            limit: options.output_limit_bytes,
        });
    }
    Ok(FlatFlameGraphDocument {
        svg,
        rendered_frames: visible.len(),
        omitted_frames,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LeafFrame {
    stable_key: String,
    label: String,
    hits: u64,
}

fn validate_options(options: FlatFlameGraphOptions) -> Result<(), FlatFlameGraphError> {
    if !(1..=MAX_FRAMES).contains(&options.max_frames) {
        return Err(FlatFlameGraphError::InvalidMaxFrames {
            actual: options.max_frames,
        });
    }
    if !(MIN_OUTPUT_LIMIT_BYTES..=MAX_OUTPUT_LIMIT_BYTES).contains(&options.output_limit_bytes) {
        return Err(FlatFlameGraphError::InvalidOutputLimit {
            actual: options.output_limit_bytes,
        });
    }
    Ok(())
}

fn project_leaves(heatmap: &Heatmap) -> Vec<LeafFrame> {
    let mut leaves = Vec::with_capacity(heatmap.cells.len() * 2 + 1);
    for cell in &heatmap.cells {
        if heatmap.projection_kind == HeatmapProjectionKind::AddressRange {
            project_address(cell, &mut leaves);
        } else {
            leaves.push(LeafFrame {
                stable_key: cell_key(cell),
                label: cell.display_name.clone(),
                hits: cell.hits,
            });
        }
    }
    if heatmap.unattributed_hits > 0 {
        leaves.push(LeafFrame {
            stable_key: "~unattributed".into(),
            label: "[unattributed sampled PCs]".into(),
            hits: heatmap.unattributed_hits,
        });
    }
    leaves.retain(|leaf| leaf.hits > 0);
    leaves.sort_unstable_by(leaf_order);
    leaves
}

fn project_address(cell: &HeatmapCell, leaves: &mut Vec<LeafFrame>) {
    let address = address_label(&cell.key);
    if let Some(location) = &cell.debugger_location {
        let label = debugger_label(
            location.function_name.as_deref(),
            location.source_file.as_deref(),
            location.source_line,
        )
        .unwrap_or_else(|| address.clone());
        leaves.push(LeafFrame {
            stable_key: format!("{}:code", cell_key(cell)),
            label,
            hits: location.dominant_hits,
        });
        let residual = cell.hits - location.dominant_hits;
        if residual > 0 {
            leaves.push(LeafFrame {
                stable_key: format!("{}:residual", cell_key(cell)),
                label: format!("{address} [address residual]"),
                hits: residual,
            });
        }
    } else {
        leaves.push(LeafFrame {
            stable_key: cell_key(cell),
            label: address,
            hits: cell.hits,
        });
    }
}

fn debugger_label(function: Option<&str>, file: Option<&str>, line: Option<u32>) -> Option<String> {
    match (function, file, line) {
        (Some(function), Some(file), Some(line)) => Some(format!("{function} · {file}:{line}")),
        (Some(function), _, _) => Some(function.to_owned()),
        (_, Some(file), Some(line)) => Some(format!("{file}:{line}")),
        _ => None,
    }
}

fn address_label(key: &HeatmapCellKey) -> String {
    match key {
        HeatmapCellKey::AddressRange {
            start_address,
            end_address,
        } => format!("{start_address:#010x}..{end_address:#010x}"),
        _ => unreachable!("validated address projection"),
    }
}
fn cell_key(cell: &HeatmapCell) -> String {
    match &cell.key {
        HeatmapCellKey::AddressRange {
            start_address,
            end_address,
        } => format!("address:{start_address:016x}-{end_address:016x}"),
        HeatmapCellKey::Function { function_id } => format!("function:{function_id}"),
        HeatmapCellKey::SourceLine { source_path, line } => {
            format!("source:{source_path}:{line:010}")
        }
    }
}
fn leaf_order(left: &LeafFrame, right: &LeafFrame) -> Ordering {
    right
        .hits
        .cmp(&left.hits)
        .then_with(|| left.stable_key.cmp(&right.stable_key))
}

fn bound_leaves(mut leaves: Vec<LeafFrame>, max_frames: usize) -> (Vec<LeafFrame>, usize) {
    if leaves.len() <= max_frames {
        return (leaves, 0);
    }
    let omitted = leaves.split_off(max_frames.saturating_sub(1));
    let omitted_frames = omitted.len();
    leaves.push(LeafFrame {
        stable_key: "~other".into(),
        label: "[other sampled PCs]".into(),
        hits: omitted.iter().map(|leaf| leaf.hits).sum(),
    });
    (leaves, omitted_frames)
}

fn render_native_geometry(
    leaves: &[LeafFrame],
    denominator_hits: u64,
) -> Result<String, FlatFlameGraphError> {
    let row = Node::container(
        leaves
            .iter()
            .zip(closed_widths(leaves, denominator_hits))
            .map(|(leaf, width)| {
                rectangle(
                    width,
                    FLAT_LEAF_HEIGHT,
                    flame_color(leaf.hits, denominator_hits),
                )
            })
            .collect::<Vec<_>>(),
    )
    .with_style(
        Style::default()
            .with(StyleDeclaration::display(Display::Flex))
            .with(StyleDeclaration::flex_direction(FlexDirection::Row))
            .with(StyleDeclaration::width(Px(ROOT_WIDTH as f32)))
            .with(StyleDeclaration::height(Px(FLAT_LEAF_HEIGHT as f32))),
    );
    let node = Node::container([
        rectangle(ROOT_WIDTH, ROOT_FRAME_HEIGHT, [91, 30, 45, 255]),
        row,
    ])
    .with_style(
        Style::default()
            .with(StyleDeclaration::display(Display::Flex))
            .with(StyleDeclaration::flex_direction(FlexDirection::Column))
            .with(StyleDeclaration::width(Px(ROOT_WIDTH as f32)))
            .with(StyleDeclaration::height(Px(140.0)))
            .with(StyleDeclaration::background_color(ColorInput::Value(
                Color([255, 250, 245, 255]),
            ))),
    );
    let fonts = Fonts::default();
    render_takumi_svg(
        SvgOptions::builder()
            .viewport(Viewport::new((ROOT_WIDTH, 140)))
            .node(node)
            .fonts(&fonts)
            .build(),
    )
    .map_err(|error| FlatFlameGraphError::Takumi {
        message: error.to_string(),
    })
}

fn rectangle(width: u32, height: u32, color: [u8; 4]) -> Node {
    Node::container([]).with_style(
        Style::default()
            .with(StyleDeclaration::width(Px(width as f32)))
            .with(StyleDeclaration::height(Px(height as f32)))
            .with(StyleDeclaration::background_color(ColorInput::Value(
                Color(color),
            ))),
    )
}
fn closed_widths(leaves: &[LeafFrame], denominator: u64) -> Vec<u32> {
    let mut used = 0_u32;
    leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| {
            let width = if index + 1 == leaves.len() {
                ROOT_WIDTH - used
            } else {
                ((u128::from(leaf.hits) * u128::from(ROOT_WIDTH)) / u128::from(denominator)) as u32
            };
            used += width;
            width
        })
        .collect()
}
fn flame_color(hits: u64, denominator: u64) -> [u8; 4] {
    let share = ((u128::from(hits) * 255) / u128::from(denominator)) as u8;
    [
        255,
        225_u8.saturating_sub(share / 3),
        140_u8.saturating_sub(share / 4),
        255,
    ]
}

fn append_accessible_overlay(
    mut svg: String,
    leaves: &[LeafFrame],
    denominator: u64,
    omitted: usize,
) -> Result<String, FlatFlameGraphError> {
    prepare_svg_overlay(&mut svg)?;
    svg.push_str("<title id=\"title\">Flat sampled profile</title><desc id=\"desc\">Flat sampled profile with synthetic hierarchy; no call-stack evidence. Leaf widths represent PC-hit share only.</desc><g role=\"list\" aria-label=\"Flat sampled profile frames\">");
    let mut x = 0_u32;
    for (leaf, width) in leaves.iter().zip(closed_widths(leaves, denominator)) {
        svg.push_str("<g role=\"listitem\" data-hits=\"");
        svg.push_str(&leaf.hits.to_string());
        svg.push_str("\" data-key=\"");
        push_xml_escaped(&mut svg, &leaf.stable_key);
        svg.push_str("\"><title>");
        push_xml_escaped(
            &mut svg,
            &format!("{}: {} sampled PC hits", leaf.label, leaf.hits),
        );
        svg.push_str("</title><rect x=\"");
        svg.push_str(&x.to_string());
        svg.push_str("\" y=\"");
        svg.push_str(&ROOT_FRAME_HEIGHT.to_string());
        svg.push_str("\" width=\"");
        svg.push_str(&width.to_string());
        svg.push_str("\" height=\"");
        svg.push_str(&FLAT_LEAF_HEIGHT.to_string());
        svg.push_str("\" fill=\"transparent\" pointer-events=\"all\"/>");
        frame_text(
            &mut svg,
            x,
            ROOT_FRAME_HEIGHT + ((FLAT_LEAF_HEIGHT + 12) / 2),
            width,
            &leaf.label,
        );
        svg.push_str("</g>");
        x += width;
    }
    svg.push_str("</g>");
    text(
        &mut svg,
        16,
        104,
        "Flat sampled profile — synthetic hierarchy; no call-stack evidence",
    );
    text(
        &mut svg,
        16,
        126,
        &format!(
            "{denominator} sampled PC hits; {omitted} frame(s) aggregated into [other sampled PCs]"
        ),
    );
    svg.push_str("</svg>");
    Ok(svg)
}
fn text(svg: &mut String, x: u32, y: u32, value: &str) {
    svg.push_str("<text x=\"");
    svg.push_str(&x.to_string());
    svg.push_str("\" y=\"");
    svg.push_str(&y.to_string());
    svg.push_str("\" font-family=\"sans-serif\" font-size=\"14\" fill=\"#3b1f1f\">");
    push_xml_escaped(svg, value);
    svg.push_str("</text>");
}

/// Adds a label only when the rendered frame can contain it. The character
/// bound is deliberately conservative for the fixed 12px sans-serif overlay;
/// the same input therefore always produces the same truncation.
fn frame_text(svg: &mut String, x: u32, y: u32, width: u32, value: &str) {
    const HORIZONTAL_PADDING: u32 = 8;
    const MIN_LABEL_WIDTH: u32 = 48;
    const APPROXIMATE_CHARACTER_WIDTH: u32 = 7;

    if width < MIN_LABEL_WIDTH {
        return;
    }
    let maximum_characters = ((width - HORIZONTAL_PADDING) / APPROXIMATE_CHARACTER_WIDTH) as usize;
    let label = truncate_frame_label(value, maximum_characters);
    if label.is_empty() {
        return;
    }
    svg.push_str("<text class=\"frame-label\" x=\"");
    svg.push_str(&(x + 4).to_string());
    svg.push_str("\" y=\"");
    svg.push_str(&y.to_string());
    svg.push_str(
        "\" font-family=\"sans-serif\" font-size=\"12\" fill=\"#3b1f1f\" pointer-events=\"none\">",
    );
    push_xml_escaped(svg, &label);
    svg.push_str("</text>");
}

fn truncate_frame_label(value: &str, maximum_characters: usize) -> String {
    let character_count = value.chars().count();
    if character_count <= maximum_characters {
        return value.to_owned();
    }
    if maximum_characters <= 1 {
        return "…".into();
    }
    let mut truncated = value
        .chars()
        .take(maximum_characters - 1)
        .collect::<String>();
    truncated.push('…');
    truncated
}
fn push_xml_escaped(output: &mut String, value: &str) {
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

/// Renders a real hierarchy from observed intrusive stack samples.
///
/// The profile's root-to-leaf paths are inserted into a prefix trie. No parent
/// frame is inferred: every non-synthetic frame in the SVG occurred in at least
/// one path. The synthetic root is only the container for all sample counts.
pub fn render_stack_sampled_svg(
    profile: &FoldedStackProfile,
    options: StackFlameGraphOptions,
) -> Result<StackFlameGraphDocument, FlatFlameGraphError> {
    profile
        .validate()
        .map_err(FlatFlameGraphError::InvalidStackProfile)?;
    if profile.paths.is_empty() {
        return Err(FlatFlameGraphError::EmptyStackProfile);
    }
    if !(1..=64).contains(&options.max_depth) {
        return Err(FlatFlameGraphError::InvalidMaxDepth {
            actual: options.max_depth,
        });
    }
    if !(MIN_OUTPUT_LIMIT_BYTES..=MAX_OUTPUT_LIMIT_BYTES).contains(&options.output_limit_bytes) {
        return Err(FlatFlameGraphError::InvalidOutputLimit {
            actual: options.output_limit_bytes,
        });
    }
    let trie = stack_trie(profile);
    let maximum_depth = deepest_stack_depth(&trie);
    let visible_depth = maximum_depth.min(options.max_depth);
    let omitted_depth = maximum_depth.saturating_sub(visible_depth);
    let selected = select_stack_frames(&trie, visible_depth);
    let total_real_nodes = count_stack_nodes(&trie, visible_depth);
    let aggregated_nodes = total_real_nodes.saturating_sub(selected.len());
    let nodes = stack_layout(&trie, visible_depth, &selected);
    let svg = append_stack_overlay(
        render_stack_native_geometry(&nodes, visible_depth, profile.included_samples)?,
        &nodes,
        profile,
        visible_depth,
        omitted_depth,
        aggregated_nodes,
    )?;
    if svg.len() > options.output_limit_bytes {
        return Err(FlatFlameGraphError::OutputLimitExceeded {
            actual: svg.len(),
            limit: options.output_limit_bytes,
        });
    }
    Ok(StackFlameGraphDocument {
        svg,
        rendered_frames: nodes
            .iter()
            .filter(|node| matches!(&node.kind, StackLayoutKind::Frame(_)))
            .count(),
        boundary_markers: nodes
            .iter()
            .filter(|node| matches!(&node.kind, StackLayoutKind::Boundary(_)))
            .count(),
        other_markers: nodes
            .iter()
            .filter(|node| matches!(&node.kind, StackLayoutKind::Other))
            .count(),
        aggregated_nodes,
        omitted_depth,
    })
}

#[derive(Debug, Default)]
struct StackTrie {
    samples: u32,
    boundaries: std::collections::BTreeMap<StackSampleTermination, StackTrieNode>,
}

#[derive(Debug, Default)]
struct StackTrieNode {
    samples: u32,
    children: std::collections::BTreeMap<FoldedStackFrame, StackTrieNode>,
}

#[derive(Debug, Clone)]
struct StackNodeLayout {
    kind: StackLayoutKind,
    depth: usize,
    samples: u32,
    x: u32,
    width: u32,
}

#[derive(Debug, Clone)]
enum StackLayoutKind {
    Frame(FoldedStackFrame),
    /// Exact reason TRACE32 stopped walking outside the observed root frame.
    Boundary(StackSampleTermination),
    /// A parent-prefix-local aggregation of omitted observed descendants.
    Other,
}

fn stack_trie(profile: &FoldedStackProfile) -> StackTrie {
    let mut root = StackTrie::default();
    for path in &profile.paths {
        root.samples += path.samples;
        let mut node = root.boundaries.entry(path.outer_boundary).or_default();
        node.samples += path.samples;
        for frame in &path.frames {
            node = node.children.entry(frame.clone()).or_default();
            node.samples += path.samples;
        }
    }
    root
}

fn deepest_stack_depth(root: &StackTrie) -> usize {
    root.boundaries
        .values()
        .map(deepest_frame_depth)
        .max()
        .unwrap_or(0)
}

fn deepest_frame_depth(node: &StackTrieNode) -> usize {
    node.children
        .values()
        .map(|child| 1 + deepest_frame_depth(child))
        .max()
        .unwrap_or(0)
}

fn select_stack_frames(
    root: &StackTrie,
    visible_depth: usize,
) -> BTreeSet<(StackSampleTermination, Vec<FoldedStackFrame>)> {
    let mut selected = BTreeSet::new();
    let mut candidates = root
        .boundaries
        .iter()
        .flat_map(|(boundary, boundary_node)| {
            boundary_node
                .children
                .iter()
                .map(|(frame, node)| StackCandidate {
                    boundary: *boundary,
                    path: vec![frame.clone()],
                    node,
                })
        })
        .collect::<Vec<_>>();

    while selected.len() < MAX_STACK_REAL_NODES && !candidates.is_empty() {
        candidates.sort_unstable_by(|left, right| {
            right
                .node
                .samples
                .cmp(&left.node.samples)
                .then_with(|| left.boundary.cmp(&right.boundary))
                .then_with(|| left.path.cmp(&right.path))
        });
        let candidate = candidates.remove(0);
        if !selected.insert((candidate.boundary, candidate.path.clone()))
            || candidate.path.len() == visible_depth
        {
            continue;
        }
        candidates.extend(candidate.node.children.iter().map(|(frame, node)| {
            let mut path = candidate.path.clone();
            path.push(frame.clone());
            StackCandidate {
                boundary: candidate.boundary,
                path,
                node,
            }
        }));
    }
    selected
}

struct StackCandidate<'a> {
    boundary: StackSampleTermination,
    path: Vec<FoldedStackFrame>,
    node: &'a StackTrieNode,
}

fn count_stack_nodes(root: &StackTrie, visible_depth: usize) -> usize {
    root.boundaries
        .values()
        .map(|node| count_frame_nodes(node, 1, visible_depth))
        .sum()
}

fn count_frame_nodes(node: &StackTrieNode, depth: usize, visible_depth: usize) -> usize {
    if depth > visible_depth {
        return 0;
    }
    node.children
        .values()
        .map(|child| 1 + count_frame_nodes(child, depth + 1, visible_depth))
        .sum()
}

fn stack_layout(
    root: &StackTrie,
    visible_depth: usize,
    selected: &BTreeSet<(StackSampleTermination, Vec<FoldedStackFrame>)>,
) -> Vec<StackNodeLayout> {
    let mut nodes = Vec::new();
    let mut boundaries = root.boundaries.iter().collect::<Vec<_>>();
    boundaries.sort_unstable_by(|(left_reason, left_node), (right_reason, right_node)| {
        right_node
            .samples
            .cmp(&left_node.samples)
            .then_with(|| left_reason.cmp(right_reason))
    });
    let mut boundary_samples = 0_u32;
    for (reason, boundary_node) in boundaries {
        let start = ((u128::from(boundary_samples) * u128::from(ROOT_WIDTH))
            / u128::from(root.samples)) as u32;
        boundary_samples += boundary_node.samples;
        let end = ((u128::from(boundary_samples) * u128::from(ROOT_WIDTH))
            / u128::from(root.samples)) as u32;
        nodes.push(StackNodeLayout {
            kind: StackLayoutKind::Boundary(*reason),
            depth: 0,
            samples: boundary_node.samples,
            x: start,
            width: end - start,
        });
        let mut context = StackLayoutContext {
            visible_depth,
            selected,
            output: &mut nodes,
        };
        layout_stack_children(
            boundary_node,
            *reason,
            &[],
            1,
            start,
            end - start,
            &mut context,
        );
    }
    nodes
}

struct StackLayoutContext<'a> {
    visible_depth: usize,
    selected: &'a BTreeSet<(StackSampleTermination, Vec<FoldedStackFrame>)>,
    output: &'a mut Vec<StackNodeLayout>,
}

fn layout_stack_children(
    node: &StackTrieNode,
    boundary: StackSampleTermination,
    parent_path: &[FoldedStackFrame],
    depth: usize,
    x: u32,
    width: u32,
    context: &mut StackLayoutContext<'_>,
) {
    if depth > context.visible_depth {
        return;
    }
    let mut selected_children = Vec::new();
    let mut other_samples = 0_u32;
    for (frame, child) in &node.children {
        let mut path = parent_path.to_vec();
        path.push(frame.clone());
        if context.selected.contains(&(boundary, path.clone())) {
            selected_children.push((frame, child, path));
        } else {
            other_samples += child.samples;
        }
    }
    let mut segments = selected_children
        .into_iter()
        .map(|(frame, child, path)| StackLayoutSegment::Child { frame, child, path })
        .collect::<Vec<_>>();
    if other_samples > 0 {
        segments.push(StackLayoutSegment::Other {
            samples: other_samples,
        });
    }
    segments.sort_unstable_by(|left, right| {
        right
            .samples()
            .cmp(&left.samples())
            .then_with(|| left.sort_key().cmp(&right.sort_key()))
    });
    let mut allocated_samples = 0_u32;
    for segment in &segments {
        let samples = segment.samples();
        let segment_x = x
            + ((u128::from(allocated_samples) * u128::from(width)) / u128::from(node.samples))
                as u32;
        allocated_samples += samples;
        let segment_end = x
            + ((u128::from(allocated_samples) * u128::from(width)) / u128::from(node.samples))
                as u32;
        let segment_width = segment_end - segment_x;
        match segment {
            StackLayoutSegment::Child { frame, child, path } => {
                context.output.push(StackNodeLayout {
                    kind: StackLayoutKind::Frame((*frame).clone()),
                    depth,
                    samples,
                    x: segment_x,
                    width: segment_width,
                });
                layout_stack_children(
                    child,
                    boundary,
                    path,
                    depth + 1,
                    segment_x,
                    segment_width,
                    context,
                );
            }
            StackLayoutSegment::Other { .. } => context.output.push(StackNodeLayout {
                kind: StackLayoutKind::Other,
                depth,
                samples,
                x: segment_x,
                width: segment_width,
            }),
        }
    }
}

enum StackLayoutSegment<'a> {
    Child {
        frame: &'a FoldedStackFrame,
        child: &'a StackTrieNode,
        path: Vec<FoldedStackFrame>,
    },
    Other {
        samples: u32,
    },
}

impl StackLayoutSegment<'_> {
    fn samples(&self) -> u32 {
        match self {
            Self::Child { child, .. } => child.samples,
            Self::Other { samples } => *samples,
        }
    }

    fn sort_key(&self) -> (u8, Option<&FoldedStackFrame>) {
        match self {
            Self::Child { frame, .. } => (0, Some(frame)),
            Self::Other { .. } => (1, None),
        }
    }
}

fn render_stack_native_geometry(
    nodes: &[StackNodeLayout],
    visible_depth: usize,
    denominator: u32,
) -> Result<String, FlatFlameGraphError> {
    let mut rows = Vec::with_capacity(visible_depth + 1);
    for depth in (1..=visible_depth).rev() {
        rows.push(stack_row(nodes, depth, denominator));
    }
    rows.push(stack_row(nodes, 0, denominator));
    let height = ((visible_depth + 1) as u32 * STACK_FRAME_HEIGHT) + 62;
    let node = Node::container(rows).with_style(
        Style::default()
            .with(StyleDeclaration::display(Display::Flex))
            .with(StyleDeclaration::flex_direction(FlexDirection::Column))
            .with(StyleDeclaration::width(Px(ROOT_WIDTH as f32)))
            .with(StyleDeclaration::height(Px(height as f32)))
            .with(StyleDeclaration::background_color(ColorInput::Value(
                Color([255, 250, 245, 255]),
            ))),
    );
    let fonts = Fonts::default();
    render_takumi_svg(
        SvgOptions::builder()
            .viewport(Viewport::new((ROOT_WIDTH, height)))
            .node(node)
            .fonts(&fonts)
            .build(),
    )
    .map_err(|error| FlatFlameGraphError::Takumi {
        message: error.to_string(),
    })
}

fn stack_row(nodes: &[StackNodeLayout], depth: usize, denominator: u32) -> Node {
    let mut nodes_at_depth = nodes
        .iter()
        .filter(|node| node.depth == depth)
        .collect::<Vec<_>>();
    nodes_at_depth.sort_unstable_by_key(|node| node.x);
    let mut children = Vec::with_capacity(nodes_at_depth.len() * 2 + 1);
    let mut cursor = 0_u32;
    for node in nodes_at_depth {
        if node.x > cursor {
            children.push(rectangle(node.x - cursor, STACK_FRAME_HEIGHT, [0, 0, 0, 0]));
        }
        children.push(rectangle(
            node.width,
            STACK_FRAME_HEIGHT,
            stack_node_color(node, denominator),
        ));
        cursor = node.x + node.width;
    }
    if cursor < ROOT_WIDTH {
        children.push(rectangle(
            ROOT_WIDTH - cursor,
            STACK_FRAME_HEIGHT,
            [0, 0, 0, 0],
        ));
    }
    Node::container(children).with_style(
        Style::default()
            .with(StyleDeclaration::display(Display::Flex))
            .with(StyleDeclaration::flex_direction(FlexDirection::Row))
            .with(StyleDeclaration::width(Px(ROOT_WIDTH as f32)))
            .with(StyleDeclaration::height(Px(STACK_FRAME_HEIGHT as f32))),
    )
}

fn stack_node_color(node: &StackNodeLayout, denominator: u32) -> [u8; 4] {
    match &node.kind {
        StackLayoutKind::Frame(_) => flame_color(u64::from(node.samples), u64::from(denominator)),
        StackLayoutKind::Boundary(StackSampleTermination::TerminalUnverified) => {
            [222, 216, 205, 255]
        }
        StackLayoutKind::Boundary(StackSampleTermination::MaxFrames) => [232, 164, 74, 255],
        StackLayoutKind::Boundary(StackSampleTermination::PcReadFailed) => [190, 82, 82, 255],
        StackLayoutKind::Boundary(StackSampleTermination::FrameCycle) => [151, 105, 179, 255],
        StackLayoutKind::Boundary(StackSampleTermination::HaltDeadline) => [218, 190, 74, 255],
        StackLayoutKind::Other => [194, 205, 214, 255],
    }
}

fn append_stack_overlay(
    mut svg: String,
    nodes: &[StackNodeLayout],
    profile: &FoldedStackProfile,
    visible_depth: usize,
    omitted_depth: usize,
    aggregated_nodes: usize,
) -> Result<String, FlatFlameGraphError> {
    prepare_svg_overlay(&mut svg)?;
    svg.push_str("<title id=\"title\">Intrusive sampled stack flame graph</title><desc id=\"desc\">Intrusive sampled stack flame graph from TRACE32 Break, Frame.Up, and Go. The outer unwind boundary may be unverified. Widths are observed sample counts, not CPU time, duration, or call counts.</desc><g role=\"list\" aria-label=\"Observed stack frames\">");
    for node in nodes {
        let y = (visible_depth - node.depth) as u32 * STACK_FRAME_HEIGHT;
        svg.push_str("<g role=\"listitem\" data-depth=\"");
        svg.push_str(&node.depth.to_string());
        svg.push_str("\" data-samples=\"");
        svg.push_str(&node.samples.to_string());
        svg.push_str("\" data-kind=\"");
        svg.push_str(stack_node_kind(node));
        if let StackLayoutKind::Boundary(reason) = &node.kind {
            svg.push_str("\" data-boundary=\"");
            svg.push_str(boundary_label(*reason));
        }
        svg.push_str("\"><title>");
        push_xml_escaped(&mut svg, &stack_node_title(node));
        svg.push_str("</title><rect x=\"");
        svg.push_str(&node.x.to_string());
        svg.push_str("\" y=\"");
        svg.push_str(&y.to_string());
        svg.push_str("\" width=\"");
        svg.push_str(&node.width.to_string());
        svg.push_str("\" height=\"");
        svg.push_str(&STACK_FRAME_HEIGHT.to_string());
        svg.push_str("\" fill=\"transparent\" pointer-events=\"all\"/>");
        frame_text(
            &mut svg,
            node.x,
            y + ((STACK_FRAME_HEIGHT + 12) / 2),
            node.width,
            &stack_node_label(node),
        );
        svg.push_str("</g>");
    }
    svg.push_str("</g>");
    let text_y = ((visible_depth + 1) as u32 * STACK_FRAME_HEIGHT) + 20;
    text(
        &mut svg,
        16,
        text_y,
        "Intrusive sampled stack flame graph — Break / Frame.Up / Go",
    );
    text(
        &mut svg,
        16,
        text_y + 20,
        &format!(
            "raw samples SHA-256: {}; terminal-unverified samples: {}; truncated samples: {}; omitted depth: {}; aggregated observed frame nodes: {}",
            profile.raw_samples_sha256.as_str(),
            profile.terminal_unverified_samples,
            profile.truncated_samples,
            omitted_depth,
            aggregated_nodes
        ),
    );
    svg.push_str("</svg>");
    Ok(svg)
}

fn prepare_svg_overlay(svg: &mut String) -> Result<(), FlatFlameGraphError> {
    if !svg.starts_with("<svg") {
        return Err(FlatFlameGraphError::InvalidNativeSvg {
            required: "opening <svg> tag",
        });
    }
    let Some(open_end) = svg.find('>') else {
        return Err(FlatFlameGraphError::InvalidNativeSvg {
            required: "complete opening <svg> tag",
        });
    };
    svg.insert_str(open_end, " role=\"img\" aria-labelledby=\"title desc\"");
    if !svg.ends_with("</svg>") {
        return Err(FlatFlameGraphError::InvalidNativeSvg {
            required: "closing </svg> tag",
        });
    }
    svg.truncate(svg.len() - "</svg>".len());
    Ok(())
}

fn stack_frame_label(frame: &FoldedStackFrame) -> String {
    debugger_label(
        frame.function_name.as_deref(),
        frame.source_file.as_deref(),
        frame.source_line,
    )
    .unwrap_or_else(|| format!("{:#010x}", frame.pc))
}

fn stack_node_label(node: &StackNodeLayout) -> String {
    match &node.kind {
        StackLayoutKind::Frame(frame) => stack_frame_label(frame),
        StackLayoutKind::Boundary(reason) => format!("[outer: {}]", boundary_label(*reason)),
        StackLayoutKind::Other => "[other observed paths]".into(),
    }
}

fn stack_node_kind(node: &StackNodeLayout) -> &'static str {
    match &node.kind {
        StackLayoutKind::Frame(_) => "frame",
        StackLayoutKind::Boundary(_) => "boundary",
        StackLayoutKind::Other => "other",
    }
}

fn stack_node_title(node: &StackNodeLayout) -> String {
    match &node.kind {
        StackLayoutKind::Frame(frame) => format!(
            "{} @ {:#010x}; depth {}; {} observed stack samples",
            stack_frame_label(frame),
            frame.pc,
            node.depth,
            node.samples
        ),
        StackLayoutKind::Boundary(reason) => format!(
            "outer unwind boundary {}; below the observed root frame; {} observed stack samples; not an inferred frame",
            boundary_label(*reason),
            node.samples
        ),
        StackLayoutKind::Other => format!(
            "{} observed stack samples aggregated under this parent prefix; not an inferred frame",
            node.samples
        ),
    }
}

fn boundary_label(reason: StackSampleTermination) -> &'static str {
    match reason {
        StackSampleTermination::TerminalUnverified => "terminal_unverified",
        StackSampleTermination::MaxFrames => "max_frames",
        StackSampleTermination::PcReadFailed => "pc_read_failed",
        StackSampleTermination::FrameCycle => "frame_cycle",
        StackSampleTermination::HaltDeadline => "halt_deadline",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use t32perf_model::*;
    #[test]
    fn escaping_is_strict() {
        let mut value = String::new();
        push_xml_escaped(&mut value, "<&>\"'");
        assert_eq!(value, "&lt;&amp;&gt;&quot;&apos;");
    }
    #[test]
    fn bounded_aggregation_conserves_hits() {
        let leaves = vec![leaf("a", 7), leaf("b", 5), leaf("c", 3)];
        let (visible, omitted) = bound_leaves(leaves, 2);
        assert_eq!(omitted, 2);
        assert_eq!(visible.iter().map(|leaf| leaf.hits).sum::<u64>(), 15);
        assert_eq!(visible[1].label, "[other sampled PCs]");
    }
    #[test]
    fn widths_close() {
        assert_eq!(
            closed_widths(&[leaf("a", 1), leaf("b", 1), leaf("c", 1)], 3)
                .iter()
                .sum::<u32>(),
            ROOT_WIDTH
        );
    }
    #[test]
    fn takumi_emits_native_geometry() {
        let svg = render_native_geometry(&[leaf("a", 5), leaf("b", 5)], 10).unwrap();
        assert!(svg.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\""));
        assert!(svg.contains("<rect"));
        assert!(!svg.contains("base64"));
    }
    #[test]
    fn disclaimer_is_deterministic() {
        let leaves = vec![leaf("a", 1)];
        let first =
            append_accessible_overlay(render_native_geometry(&leaves, 1).unwrap(), &leaves, 1, 0)
                .unwrap();
        let second =
            append_accessible_overlay(render_native_geometry(&leaves, 1).unwrap(), &leaves, 1, 0)
                .unwrap();
        assert_eq!(first, second);
        assert!(first.contains("synthetic hierarchy"));
        assert!(first.contains("no call-stack evidence"));
    }

    #[test]
    fn actual_render_escapes_debugger_function_and_source_labels() {
        let (histogram, heatmap, digest) = address_fixture();
        let document = render_flat_sampled_svg(
            &histogram,
            digest,
            &heatmap,
            FlatFlameGraphOptions::default(),
        )
        .unwrap();
        assert!(
            document
                .svg
                .contains("role=\"img\" aria-labelledby=\"title desc\"")
        );
        assert!(
            document
                .svg
                .contains("fn&lt;&amp;&gt;&quot;&apos; · file&lt;&amp;&gt;&quot;&apos;:7")
        );
        assert!(!document.svg.contains("fn<&>\"' · file<&>\"':7"));
        assert!(document.svg.contains(
            "class=\"frame-label\" x=\"4\" y=\"56\" font-family=\"sans-serif\" font-size=\"12\" fill=\"#3b1f1f\" pointer-events=\"none\">fn&lt;&amp;&gt;&quot;&apos; · file&lt;&amp;&gt;&quot;&apos;:7</text>"
        ));
    }

    #[test]
    fn actual_render_rejects_mismatched_digest() {
        let (histogram, heatmap, _) = function_fixture();
        let error = render_flat_sampled_svg(
            &histogram,
            digest('b'),
            &heatmap,
            FlatFlameGraphOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(error, FlatFlameGraphError::InvalidEvidence(_)));
    }

    #[test]
    fn actual_render_max_one_aggregates_and_conserves_hits() {
        let (histogram, heatmap, digest) = function_fixture();
        let document = render_flat_sampled_svg(
            &histogram,
            digest,
            &heatmap,
            FlatFlameGraphOptions {
                max_frames: 1,
                output_limit_bytes: 256 * 1024,
            },
        )
        .unwrap();
        assert_eq!(document.rendered_frames, 1);
        assert_eq!(document.omitted_frames, 3);
        assert!(document.svg.contains("[other sampled PCs]"));
        assert!(document.svg.contains("data-hits=\"10\""));
    }

    fn function_fixture() -> (PcHitHistogram, Heatmap, Sha256Digest) {
        let digest = digest('a');
        let histogram = base_histogram(vec![
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
        ]);
        let heatmap = Heatmap {
            schema: HeatmapSchemaVersion,
            session_id: "session-01".into(),
            histogram_sha256: digest.clone(),
            quality: HeatmapQuality::Statistical,
            projection_kind: HeatmapProjectionKind::Function,
            quantitative_policy: policy(),
            denominator_hits: 10,
            attributed_hits: 8,
            unattributed_hits: 2,
            out_of_scope_hits: OutOfScopeHits::Unknown,
            cells: vec![
                HeatmapCell {
                    key: HeatmapCellKey::Function {
                        function_id: "alpha".into(),
                    },
                    display_name: "alpha".into(),
                    hits: 6,
                    debugger_location: None,
                },
                HeatmapCell {
                    key: HeatmapCellKey::Function {
                        function_id: "beta".into(),
                    },
                    display_name: "beta".into(),
                    hits: 2,
                    debugger_location: None,
                },
            ],
        };
        (histogram, heatmap, digest)
    }

    fn address_fixture() -> (PcHitHistogram, Heatmap, Sha256Digest) {
        let digest = digest('a');
        let location = DebuggerHotspotLocation {
            bucket_start_address: 0x1000,
            bucket_end_address: 0x1010,
            hits: 10,
            dominant_start_address: 0x1004,
            dominant_end_address: 0x1008,
            dominant_hits: 7,
            function_name: Some("fn<&>\"'".into()),
            source_file: Some("file<&>\"'".into()),
            source_line: Some(7),
        };
        let mut histogram = base_histogram(vec![PcHitBucket {
            start_address: 0x1000,
            end_address: 0x1010,
            hits: 10,
        }]);
        histogram.debugger_symbolization = Some(DebuggerSymbolization {
            source: DebuggerSymbolizationSource::Trace32SymbolTable,
            trust: DebuggerSymbolizationTrust::DebuggerReported,
            refinement_granularity_bytes: 4,
            locations: vec![location.clone()],
        });
        let heatmap = Heatmap {
            schema: HeatmapSchemaVersion,
            session_id: "session-01".into(),
            histogram_sha256: digest.clone(),
            quality: HeatmapQuality::Statistical,
            projection_kind: HeatmapProjectionKind::AddressRange,
            quantitative_policy: policy(),
            denominator_hits: 10,
            attributed_hits: 10,
            unattributed_hits: 0,
            out_of_scope_hits: OutOfScopeHits::Unknown,
            cells: vec![HeatmapCell {
                key: HeatmapCellKey::AddressRange {
                    start_address: 0x1000,
                    end_address: 0x1010,
                },
                display_name: "0x00001000..0x00001010".into(),
                hits: 10,
                debugger_location: Some(location),
            }],
        };
        (histogram, heatmap, digest)
    }

    fn base_histogram(buckets: Vec<PcHitBucket>) -> PcHitHistogram {
        PcHitHistogram {
            schema: PcHitHistogramSchemaVersion,
            session_id: "session-01".into(),
            endpoint_fingerprint: digest('f'),
            endpoint_fingerprint_scheme: EndpointFingerprintScheme::T32PerfEndpointFingerprintV2,
            trace32: "R.2026.02.000190766".into(),
            cpu: "CortexM0+".into(),
            address_space: "P:".into(),
            core_id: 0,
            method: PcSamplingMethod::Realtime,
            intrusive: false,
            requested_duration_ns: 1_000_000,
            observed_duration_ns: 1_100_000,
            last_sample_rate_hz: 2_000,
            snoop_failures: 0,
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
            in_scope_hits: buckets.iter().map(|bucket| bucket.hits).sum(),
            buckets,
            debugger_symbolization: None,
        }
    }

    fn policy() -> QuantitativePolicy {
        QuantitativePolicy {
            min_in_scope_hits: 1,
            min_observed_duration_ns: 1,
            min_stop_and_go_retained_runtime_percent: 0.0,
            max_snoop_failures: 0,
        }
    }

    fn digest(character: char) -> Sha256Digest {
        Sha256Digest::new(character.to_string().repeat(64)).unwrap()
    }

    #[test]
    fn stack_render_keeps_shared_prefix_and_distinguishes_same_name_pcs() {
        let profile = stack_fixture(vec![
            stack_path(&[frame(0x1000, "root"), frame(0x1010, "work")], 3),
            stack_path(&[frame(0x1000, "root"), frame(0x1020, "work")], 2),
            stack_path(&[frame(0x2000, "root"), frame(0x2010, "idle")], 1),
        ]);
        let document =
            render_stack_sampled_svg(&profile, StackFlameGraphOptions::default()).unwrap();
        assert_eq!(document.rendered_frames, 5);
        assert!(document.svg.contains("data-samples=\"5\""));
        assert!(document.svg.contains("work @ 0x00001010"));
        assert!(document.svg.contains("work @ 0x00001020"));
    }

    #[test]
    fn stack_widths_conserve_and_depth_limit_is_explicit() {
        let profile = stack_fixture(vec![
            stack_path(
                &[frame(0x1000, "a"), frame(0x1010, "b"), frame(0x1020, "c")],
                4,
            ),
            stack_path(
                &[frame(0x2000, "d"), frame(0x2010, "e"), frame(0x2020, "f")],
                2,
            ),
        ]);
        let trie = stack_trie(&profile);
        let selected = select_stack_frames(&trie, 1);
        let layouts = stack_layout(&trie, 1, &selected);
        for depth in [0, 1] {
            assert_eq!(
                layouts
                    .iter()
                    .filter(|node| node.depth == depth)
                    .map(|node| node.width)
                    .sum::<u32>(),
                ROOT_WIDTH
            );
        }
        let document = render_stack_sampled_svg(
            &profile,
            StackFlameGraphOptions {
                max_depth: 1,
                output_limit_bytes: 256 * 1024,
            },
        )
        .unwrap();
        assert_eq!(document.omitted_depth, 2);
        assert_eq!(document.rendered_frames, 2);
    }

    #[test]
    fn a_path_ending_at_a_frame_leaves_no_fabricated_child() {
        let profile = stack_fixture(vec![
            stack_path(&[frame(0x1000, "root")], 9),
            stack_path(&[frame(0x1000, "root"), frame(0x1010, "leaf")], 1),
        ]);
        let trie = stack_trie(&profile);
        let selected = select_stack_frames(&trie, 2);
        let layouts = stack_layout(&trie, 2, &selected);
        let children_of_root = layouts
            .iter()
            .filter(|node| node.depth == 2)
            .collect::<Vec<_>>();
        assert_eq!(children_of_root.len(), 1);
        let leaf = children_of_root
            .iter()
            .find(|node| matches!(&node.kind, StackLayoutKind::Frame(frame) if frame.pc == 0x1010))
            .unwrap();
        assert_eq!(leaf.samples, 1);
        assert_eq!(leaf.width, ROOT_WIDTH / 10);
        let boundary = layouts
            .iter()
            .find(|node| matches!(&node.kind, StackLayoutKind::Boundary(_)))
            .unwrap();
        assert_eq!(boundary.depth, 0);
        assert_eq!(boundary.samples, 10);
        assert_eq!(boundary.width, ROOT_WIDTH);

        let document =
            render_stack_sampled_svg(&profile, StackFlameGraphOptions::default()).unwrap();
        assert_eq!(document.rendered_frames, 2);
        assert_eq!(document.boundary_markers, 1);
        assert!(document.svg.contains("data-kind=\"boundary\""));
        assert!(document.svg.contains("[outer: terminal_unverified]"));
        assert!(
            document
                .svg
                .contains(&format!("raw samples SHA-256: {}", digest('c')))
        );
        assert!(!document.svg.contains("profile SHA-256:"));
        assert!(!document.svg.contains("[terminal at root]"));
    }

    #[test]
    fn outer_boundaries_parent_only_their_exact_observed_paths() {
        let profile = stack_fixture(vec![
            stack_path_with_boundary(
                &[frame(0x2000, "terminal-root")],
                1,
                StackSampleTermination::TerminalUnverified,
            ),
            stack_path_with_boundary(
                &[frame(0x1000, "max-root")],
                3,
                StackSampleTermination::MaxFrames,
            ),
        ]);
        let trie = stack_trie(&profile);
        let selected = select_stack_frames(&trie, 1);
        let layouts = stack_layout(&trie, 1, &selected);
        let max_boundary = layouts
            .iter()
            .find(|node| {
                matches!(
                    node.kind,
                    StackLayoutKind::Boundary(StackSampleTermination::MaxFrames)
                )
            })
            .unwrap();
        let max_root = layouts
            .iter()
            .find(|node| matches!(&node.kind, StackLayoutKind::Frame(frame) if frame.pc == 0x1000))
            .unwrap();
        let terminal_boundary = layouts
            .iter()
            .find(|node| {
                matches!(
                    node.kind,
                    StackLayoutKind::Boundary(StackSampleTermination::TerminalUnverified)
                )
            })
            .unwrap();
        let terminal_root = layouts
            .iter()
            .find(|node| matches!(&node.kind, StackLayoutKind::Frame(frame) if frame.pc == 0x2000))
            .unwrap();
        assert_eq!(
            (max_root.x, max_root.width),
            (max_boundary.x, max_boundary.width)
        );
        assert_eq!(
            (terminal_root.x, terminal_root.width),
            (terminal_boundary.x, terminal_boundary.width)
        );

        let document =
            render_stack_sampled_svg(&profile, StackFlameGraphOptions::default()).unwrap();
        assert_stack_overlay_row(&document.svg, 0, STACK_FRAME_HEIGHT);
        assert_stack_overlay_row(&document.svg, 1, 0);
        assert!(document.svg.contains("[outer: max_frames]"));
        assert!(document.svg.contains("[outer: terminal_unverified]"));
    }

    #[test]
    fn stack_overlay_escapes_labels_and_empty_profile_is_rejected() {
        let escaped = stack_fixture(vec![stack_path(&[frame(0x1000, "<&>\"'")], 1)]);
        let document =
            render_stack_sampled_svg(&escaped, StackFlameGraphOptions::default()).unwrap();
        assert!(
            document
                .svg
                .contains("&lt;&amp;&gt;&quot;&apos; @ 0x00001000")
        );
        assert!(!document.svg.contains("<&>\"' @ 0x00001000"));
        assert!(document.svg.contains(
            "class=\"frame-label\" x=\"4\" y=\"20\" font-family=\"sans-serif\" font-size=\"12\" fill=\"#3b1f1f\" pointer-events=\"none\">&lt;&amp;&gt;&quot;&apos;</text>"
        ));
        let empty = stack_fixture(vec![]);
        assert!(matches!(
            render_stack_sampled_svg(&empty, StackFlameGraphOptions::default()),
            Err(FlatFlameGraphError::EmptyStackProfile)
        ));
    }

    #[test]
    fn flat_overlay_stays_inside_the_native_leaf_row() {
        let (histogram, heatmap, digest) = address_fixture();
        let document = render_flat_sampled_svg(
            &histogram,
            digest,
            &heatmap,
            FlatFlameGraphOptions::default(),
        )
        .unwrap();
        let rectangle = overlay_rect_after(&document.svg, "data-hits=\"7\"");
        assert_eq!(svg_u32_attribute(rectangle, "y"), ROOT_FRAME_HEIGHT);
        assert_eq!(svg_u32_attribute(rectangle, "height"), FLAT_LEAF_HEIGHT);
        assert_eq!(
            svg_u32_attribute(rectangle, "y") + svg_u32_attribute(rectangle, "height"),
            ROOT_FRAME_HEIGHT + FLAT_LEAF_HEIGHT
        );
    }

    #[test]
    fn stack_overlay_coordinates_follow_native_rows_at_depth_two_and_sixty_four() {
        let shallow = stack_fixture(vec![stack_path(
            &[frame(0x1000, "root"), frame(0x1010, "leaf")],
            1,
        )]);
        let shallow_svg = render_stack_sampled_svg(&shallow, StackFlameGraphOptions::default())
            .unwrap()
            .svg;
        assert_stack_overlay_row(&shallow_svg, 2, 0);
        assert_stack_overlay_row(&shallow_svg, 1, STACK_FRAME_HEIGHT);

        let deep_frames = (0..64)
            .map(|index| frame(0x1000 + (index * 4), &format!("f{index}")))
            .collect::<Vec<_>>();
        let deep = stack_fixture(vec![stack_path(&deep_frames, 1)]);
        let deep_svg = render_stack_sampled_svg(&deep, StackFlameGraphOptions::default())
            .unwrap()
            .svg;
        assert_stack_overlay_row(&deep_svg, 64, 0);
        assert_stack_overlay_row(&deep_svg, 1, 63 * STACK_FRAME_HEIGHT);
    }

    #[test]
    fn stack_node_budget_is_deterministic_and_aggregates_legal_high_diversity_input() {
        let long_label = "&".repeat(256);
        let paths = (0..512)
            .map(|path_index| {
                let frames = (0..64)
                    .map(|depth| FoldedStackFrame {
                        pc: 0x1000 + ((path_index as u64) << 16) + ((depth as u64) * 4),
                        function_name: Some(long_label.clone()),
                        source_file: Some("x".repeat(256)),
                        source_line: Some(1),
                    })
                    .collect::<Vec<_>>();
                stack_path(&frames, 1)
            })
            .collect::<Vec<_>>();
        let profile = stack_fixture(paths);
        let trie = stack_trie(&profile);
        let selected = select_stack_frames(&trie, 64);
        let layouts = stack_layout(&trie, 64, &selected);
        assert_eq!(selected.len(), MAX_STACK_REAL_NODES);
        assert_eq!(count_stack_nodes(&trie, 64), 512 * 64);
        assert_eq!(
            layouts
                .iter()
                .filter(|node| node.depth == 1)
                .map(|node| node.samples)
                .sum::<u32>(),
            profile.included_samples
        );
        assert!(
            layouts
                .iter()
                .any(|node| matches!(&node.kind, StackLayoutKind::Other))
        );

        let first = render_stack_sampled_svg(
            &profile,
            StackFlameGraphOptions {
                max_depth: 64,
                output_limit_bytes: MAX_OUTPUT_LIMIT_BYTES,
            },
        )
        .unwrap();
        let second = render_stack_sampled_svg(
            &profile,
            StackFlameGraphOptions {
                max_depth: 64,
                output_limit_bytes: MAX_OUTPUT_LIMIT_BYTES,
            },
        )
        .unwrap();
        assert_eq!(first.svg, second.svg);
        assert!(first.svg.len() <= MAX_OUTPUT_LIMIT_BYTES);
        assert_eq!(first.rendered_frames, MAX_STACK_REAL_NODES);
        assert_eq!(first.other_markers, 1);
        assert_eq!(first.aggregated_nodes, (512 * 64) - MAX_STACK_REAL_NODES);
        assert!(first.svg.contains("data-kind=\"other\""));
        assert!(first.svg.contains("[other observed paths]"));
        assert!(first.svg.contains("aggregated observed frame nodes: 32640"));
        assert_stack_overlay_row(&first.svg, 1, 63 * STACK_FRAME_HEIGHT);
    }

    fn assert_stack_overlay_row(svg: &str, depth: usize, expected_y: u32) {
        let rectangle = overlay_rect_after(svg, &format!("data-depth=\"{depth}\""));
        assert_eq!(svg_u32_attribute(rectangle, "y"), expected_y);
        assert_eq!(svg_u32_attribute(rectangle, "height"), STACK_FRAME_HEIGHT);
    }

    fn overlay_rect_after<'a>(svg: &'a str, marker: &str) -> &'a str {
        let marker_offset = svg.find(marker).expect("expected SVG overlay marker");
        let rect_offset = svg[marker_offset..]
            .find("<rect ")
            .expect("expected transparent overlay rect");
        let rectangle = &svg[marker_offset + rect_offset..];
        let end = rectangle.find("/>").expect("expected closed SVG rect");
        &rectangle[..end + 2]
    }

    fn svg_u32_attribute(rectangle: &str, name: &str) -> u32 {
        let prefix = format!("{name}=\"");
        let value = rectangle
            .split(&prefix)
            .nth(1)
            .and_then(|remaining| remaining.split('"').next())
            .expect("expected SVG numeric attribute");
        value
            .parse()
            .expect("expected unsigned SVG numeric attribute")
    }

    fn stack_fixture(paths: Vec<FoldedStackPath>) -> FoldedStackProfile {
        let included_samples = paths.iter().map(|path| path.samples).sum::<u32>();
        let terminal_unverified_samples = paths
            .iter()
            .filter(|path| path.outer_boundary == StackSampleTermination::TerminalUnverified)
            .map(|path| path.samples)
            .sum::<u32>();
        FoldedStackProfile {
            schema: FoldedStackProfileSchemaVersion,
            session_id: "session-01".into(),
            raw_samples_sha256: digest('c'),
            quality: FoldedStackProfileQuality::IntrusiveStatistical,
            method: StackSamplingMethod::BreakFrameWalk,
            frame_order: FoldedStackFrameOrder::RootToLeaf,
            attempted_samples: included_samples,
            collected_samples: included_samples,
            included_samples,
            terminal_unverified_samples,
            truncated_samples: included_samples - terminal_unverified_samples,
            paths,
        }
    }
    fn stack_path(frames: &[FoldedStackFrame], samples: u32) -> FoldedStackPath {
        stack_path_with_boundary(frames, samples, StackSampleTermination::TerminalUnverified)
    }
    fn stack_path_with_boundary(
        frames: &[FoldedStackFrame],
        samples: u32,
        outer_boundary: StackSampleTermination,
    ) -> FoldedStackPath {
        FoldedStackPath {
            outer_boundary,
            frames: frames.to_vec(),
            samples,
        }
    }
    fn frame(pc: u64, function_name: &str) -> FoldedStackFrame {
        FoldedStackFrame {
            pc,
            function_name: Some(function_name.into()),
            source_file: None,
            source_line: None,
        }
    }

    fn leaf(key: &str, hits: u64) -> LeafFrame {
        LeafFrame {
            stable_key: key.into(),
            label: key.into(),
            hits,
        }
    }
}
