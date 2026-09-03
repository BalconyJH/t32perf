//! Deterministic aggregation of intrusive TRACE32 stack samples.

use std::collections::BTreeMap;

use t32perf_model::{
    FoldedStackFrame, FoldedStackFrameOrder, FoldedStackPath, FoldedStackProfile,
    FoldedStackProfileQuality, FoldedStackProfileSchemaVersion, FoldedStackProfileValidationError,
    Sha256Digest, StackSampleTermination, StackSamples, StackSamplesValidationError,
};
use thiserror::Error;

/// Failure while constructing a folded stack profile.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FoldedStackBuildError {
    /// The source artifact was invalid.
    #[error("invalid raw stack samples: {0}")]
    Raw(#[from] StackSamplesValidationError),
    /// More than 512 unique observed paths would be emitted.
    #[error("folded profile has more than 512 unique paths")]
    TooManyPaths,
    /// A path count could not fit in the bounded artifact representation.
    #[error("folded profile sample count overflowed")]
    CountOverflow,
    /// The constructed contract rejected its own accounting.
    #[error("constructed folded profile was invalid: {0}")]
    Profile(#[from] FoldedStackProfileValidationError),
}

/// Builds a deterministic root-to-leaf aggregation without inventing parents.
///
/// Each raw leaf-to-root frame vector is reversed verbatim. The aggregation
/// key includes all frame identity fields and the recorded termination reason,
/// so recursive frames and distinct unverified outer boundaries remain distinct.
pub fn build_folded_stack_profile(
    raw: &StackSamples,
    raw_samples_sha256: Sha256Digest,
) -> Result<FoldedStackProfile, FoldedStackBuildError> {
    raw.validate()?;

    let mut paths = BTreeMap::<(StackSampleTermination, Vec<FoldedStackFrame>), u32>::new();
    for sample in &raw.samples {
        let frames = sample
            .frames
            .iter()
            .rev()
            .map(|frame| FoldedStackFrame {
                pc: frame.pc,
                function_name: frame.function_name.clone(),
                source_file: frame.source_file.clone(),
                source_line: frame.source_line,
            })
            .collect::<Vec<_>>();
        let count = paths.entry((sample.termination, frames)).or_default();
        *count = count
            .checked_add(1)
            .ok_or(FoldedStackBuildError::CountOverflow)?;
    }
    if paths.len() > t32perf_model::MAX_STACK_SAMPLES {
        return Err(FoldedStackBuildError::TooManyPaths);
    }

    let mut terminal_unverified_samples = 0_u32;
    let mut truncated_samples = 0_u32;
    let paths = paths
        .into_iter()
        .map(|((outer_boundary, frames), samples)| {
            if outer_boundary == StackSampleTermination::TerminalUnverified {
                terminal_unverified_samples = terminal_unverified_samples
                    .checked_add(samples)
                    .ok_or(FoldedStackBuildError::CountOverflow)?;
            } else {
                truncated_samples = truncated_samples
                    .checked_add(samples)
                    .ok_or(FoldedStackBuildError::CountOverflow)?;
            }
            Ok(FoldedStackPath {
                outer_boundary,
                frames,
                samples,
            })
        })
        .collect::<Result<Vec<_>, FoldedStackBuildError>>()?;

    let profile = FoldedStackProfile {
        schema: FoldedStackProfileSchemaVersion,
        session_id: raw.session_id.clone(),
        raw_samples_sha256,
        quality: FoldedStackProfileQuality::IntrusiveStatistical,
        method: raw.method,
        frame_order: FoldedStackFrameOrder::RootToLeaf,
        attempted_samples: raw.attempted_samples,
        collected_samples: raw.collected_samples,
        included_samples: raw.collected_samples,
        terminal_unverified_samples,
        truncated_samples,
        paths,
    };
    profile.validate()?;
    Ok(profile)
}
