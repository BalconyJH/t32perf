use t32perf_analysis::{
    FunctionAddressRange, FunctionAddressRangeValidationError, HistogramHeatmapError,
    QuantitativeHistogramValidationError, build_address_heatmap, build_function_heatmap,
    validate_quantitative_histogram,
};
use t32perf_model::{
    DebuggerHotspotLocation, DebuggerSymbolization, DebuggerSymbolizationSource,
    DebuggerSymbolizationTrust, FirmwareBinding, FirmwareBindingProof, FirmwareBindingStatus,
    HeatmapCellKey, PcHitBucket, PcHitHistogram, PcHitHistogramSchemaVersion,
    PcHitHistogramValidationError, PcSamplingMethod, Sha256Digest, TargetExecutionState,
};

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(character.to_string().repeat(64)).unwrap()
}

fn histogram() -> PcHitHistogram {
    PcHitHistogram {
        schema: PcHitHistogramSchemaVersion,
        session_id: "histogram-01".to_owned(),
        endpoint_fingerprint: digest('f'),
        endpoint_fingerprint_scheme:
            t32perf_model::EndpointFingerprintScheme::T32PerfEndpointFingerprintV2,
        trace32: "R.2026.02.000190766".to_owned(),
        cpu: "CortexM0+".to_owned(),
        address_space: "P:".to_owned(),
        core_id: 0,
        method: PcSamplingMethod::Realtime,
        intrusive: false,
        requested_duration_ns: 100_000_000,
        observed_duration_ns: 100_000_000,
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
        in_scope_hits: 100,
        buckets: vec![
            PcHitBucket {
                start_address: 0x1000,
                end_address: 0x1010,
                hits: 100,
            },
            PcHitBucket {
                start_address: 0x1010,
                end_address: 0x1020,
                hits: 0,
            },
        ],
        debugger_symbolization: None,
    }
}

fn range(id: &str, name: &str, start_address: u64, end_address: u64) -> FunctionAddressRange {
    FunctionAddressRange {
        function_id: id.to_owned(),
        display_name: name.to_owned(),
        start_address,
        end_address,
    }
}

#[test]
fn address_heatmap_projects_every_bucket_and_binds_digest() {
    let histogram = histogram();
    let result = build_address_heatmap(&histogram, digest('a')).unwrap();

    assert_eq!(result.denominator_hits, 100);
    assert_eq!(result.attributed_hits, 100);
    assert_eq!(result.unattributed_hits, 0);
    assert_eq!(result.cells.len(), 2);
    assert_eq!(result.cells[1].hits, 0);
    assert_eq!(result.cells[0].display_name, "0x1000..0x1010");
    assert_eq!(
        result.cells[0].key,
        HeatmapCellKey::AddressRange {
            start_address: 0x1000,
            end_address: 0x1010,
        }
    );
    assert!(result.validate_against(&histogram, digest('a')).is_ok());
    assert!(result.validate_against(&histogram, digest('b')).is_err());
}

#[test]
fn address_heatmap_copies_exact_debugger_hotspot_location() {
    let mut histogram = histogram();
    let location = DebuggerHotspotLocation {
        bucket_start_address: 0x1000,
        bucket_end_address: 0x1010,
        hits: 100,
        dominant_start_address: 0x1004,
        dominant_end_address: 0x1008,
        dominant_hits: 80,
        function_name: Some("main".to_owned()),
        source_file: Some("main.c".to_owned()),
        source_line: Some(42),
    };
    histogram.debugger_symbolization = Some(DebuggerSymbolization {
        source: DebuggerSymbolizationSource::Trace32SymbolTable,
        trust: DebuggerSymbolizationTrust::DebuggerReported,
        refinement_granularity_bytes: 4,
        locations: vec![location.clone()],
    });

    let heatmap = build_address_heatmap(&histogram, digest('a')).unwrap();
    assert_eq!(heatmap.cells[0].debugger_location, Some(location));
    assert_eq!(heatmap.cells[1].debugger_location, None);
}

#[test]
fn function_heatmap_never_splits_cross_boundary_buckets_and_is_deterministic() {
    let mut histogram = histogram();
    histogram.buckets = vec![
        PcHitBucket {
            start_address: 0x1000,
            end_address: 0x1010,
            hits: 60,
        },
        PcHitBucket {
            start_address: 0x1010,
            end_address: 0x1020,
            hits: 40,
        },
    ];
    let ranges = [
        range("beta", "beta", 0x1000, 0x1010),
        range("alpha", "alpha", 0x1010, 0x1018),
        range("gamma", "gamma", 0x1018, 0x1020),
    ];
    let result = build_function_heatmap(&histogram, digest('a'), &ranges).unwrap();

    assert_eq!(result.attributed_hits, 60);
    assert_eq!(result.unattributed_hits, 40);
    assert_eq!(result.cells.len(), 1);
    assert_eq!(
        result.cells[0].key,
        HeatmapCellKey::Function {
            function_id: "beta".to_owned(),
        }
    );

    let ties = [
        range("zeta", "zeta", 0x1000, 0x1010),
        range("alpha", "alpha", 0x1010, 0x1020),
    ];
    let mut tied_histogram = histogram.clone();
    tied_histogram.buckets[0].hits = 50;
    tied_histogram.buckets[1].hits = 50;
    let tied = build_function_heatmap(&tied_histogram, digest('a'), &ties).unwrap();
    assert_eq!(
        tied.cells[0].key,
        HeatmapCellKey::Function {
            function_id: "alpha".to_owned()
        }
    );
    assert_eq!(
        tied.cells[1].key,
        HeatmapCellKey::Function {
            function_id: "zeta".to_owned()
        }
    );
}

#[test]
fn function_ranges_reject_aliases_overlap_and_unordered_input() {
    let histogram = histogram();
    let overlap = [
        range("a", "a", 0x1000, 0x1010),
        range("alias", "alias", 0x1000, 0x1010),
    ];
    assert!(matches!(
        build_function_heatmap(&histogram, digest('a'), &overlap),
        Err(HistogramHeatmapError::FunctionRanges(
            FunctionAddressRangeValidationError::OverlappingRanges { .. }
        ))
    ));
    let unordered = [
        range("a", "a", 0x1010, 0x1020),
        range("b", "b", 0x1000, 0x1010),
    ];
    assert!(matches!(
        build_function_heatmap(&histogram, digest('a'), &unordered),
        Err(HistogramHeatmapError::FunctionRanges(
            FunctionAddressRangeValidationError::UnsortedRanges { .. }
        ))
    ));
}

#[test]
fn quantitative_gate_rejects_target_drift_and_invalid_sampling_evidence() {
    let mut value = histogram();
    value.last_sample_rate_hz = 0;
    assert_eq!(
        validate_quantitative_histogram(&value),
        Err(QuantitativeHistogramValidationError::ZeroSampleRate)
    );
    value = histogram();
    value.in_scope_hits = 0;
    value.buckets[0].hits = 0;
    assert_eq!(
        validate_quantitative_histogram(&value),
        Err(
            QuantitativeHistogramValidationError::InsufficientInScopeHits {
                minimum: 100,
                actual: 0,
            }
        )
    );
    value = histogram();
    value.snoop_failures = 1;
    assert_eq!(
        validate_quantitative_histogram(&value),
        Err(QuantitativeHistogramValidationError::SnoopFailures { count: 1 })
    );
    value = histogram();
    value.observed_duration_ns = 99_999_999;
    assert_eq!(
        validate_quantitative_histogram(&value),
        Err(
            QuantitativeHistogramValidationError::InsufficientObservedDuration {
                minimum: 100_000_000,
                actual: 99_999_999,
            }
        )
    );
    value = histogram();
    value.target_state_after.running = false;
    assert_eq!(
        validate_quantitative_histogram(&value),
        Err(QuantitativeHistogramValidationError::TargetNotRunning { boundary: "after" })
    );
    value = histogram();
    value.method = PcSamplingMethod::StopAndGo {
        configured_retained_runtime_percent: 99.0,
        observed_retained_runtime_percent: 98.0,
    };
    value.intrusive = true;
    assert!(validate_quantitative_histogram(&value).is_ok());
    value.method = PcSamplingMethod::StopAndGo {
        configured_retained_runtime_percent: 99.0,
        observed_retained_runtime_percent: 89.9,
    };
    assert!(matches!(
        validate_quantitative_histogram(&value),
        Err(QuantitativeHistogramValidationError::InsufficientRetainedRuntime { .. })
    ));
}

#[test]
fn function_projection_requires_verified_firmware_and_propagates_overflow() {
    let mut unverified = histogram();
    unverified.firmware.status = FirmwareBindingStatus::Unverified;
    unverified.firmware.elf_sha256 = None;
    unverified.firmware.proof = None;
    assert!(matches!(
        build_function_heatmap(&unverified, digest('a'), &[]),
        Err(HistogramHeatmapError::Heatmap(
            t32perf_model::HeatmapAgainstHistogramValidationError::AttributedFirmwareBindingRequired
        ))
    ));

    let mut overflowing = histogram();
    overflowing.buckets[0].hits = u64::MAX;
    overflowing.buckets[1].hits = 1;
    overflowing.in_scope_hits = u64::MAX;
    assert!(matches!(
        validate_quantitative_histogram(&overflowing),
        Err(QuantitativeHistogramValidationError::Histogram(
            PcHitHistogramValidationError::HitCountOverflow
        ))
    ));
}
