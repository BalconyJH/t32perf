use t32perf_trace32::{
    ClockDomainRegistry, ClockDomainSpec, ClockError, KWayMerge, MergeError, ObservationSource,
    RationalTickScale, SourceError, SyntheticConfig, SyntheticSource, TimestampNormalizer,
    TimestampUnwrapper,
};

fn boxed(config: SyntheticConfig) -> Box<dyn ObservationSource + Send> {
    Box::new(SyntheticSource::new(config).unwrap())
}

fn collect_ids(
    mut source: impl ObservationSource,
) -> Result<Vec<(String, i64, Option<u64>)>, SourceError> {
    let mut result = Vec::new();
    while let Some(record) = source.next_observation()? {
        let timestamp = record.observation.ts_ns();
        result.push((record.observation.source_id, timestamp, record.order_key));
    }
    Ok(result)
}

#[test]
fn rational_tick_conversion_is_integer_and_drift_free() {
    let scale = RationalTickScale::from_hz(3).unwrap();
    assert_eq!(scale.ticks_to_ns(1).unwrap(), 333_333_333);
    assert_eq!(scale.ticks_to_ns(3).unwrap(), 1_000_000_000);
    assert_eq!(scale.ticks_to_ns(3_000_000).unwrap(), 1_000_000_000_000_000);
    assert_eq!(scale.timestamp_ns(3, 6, 100).unwrap(), -999_999_900);

    let scale = RationalTickScale::new(2, 3).unwrap();
    let expected = (u128::MAX / 3) * 2;
    assert_eq!(scale.ticks_to_ns(u128::MAX).unwrap(), expected);
}

#[test]
fn timestamp_wrap_expands_once_and_rejects_ambiguous_steps() {
    assert!(matches!(
        ClockDomainSpec::new(
            "unbounded-wrap",
            RationalTickScale::new(1, 1).unwrap(),
            Some(256),
            None,
        ),
        Err(ClockError::MissingForwardLimit)
    ));

    let mut unwrap = TimestampUnwrapper::new(256, 20).unwrap();
    assert_eq!(unwrap.expand(250).unwrap(), 250);
    assert_eq!(unwrap.expand(255).unwrap(), 255);
    assert_eq!(unwrap.expand(3).unwrap(), 259);
    assert!(matches!(
        unwrap.expand(2),
        Err(ClockError::ForwardStepTooLarge { .. })
    ));

    let domain = ClockDomainSpec::new(
        "timer8",
        RationalTickScale::new(10, 1).unwrap(),
        Some(256),
        Some(20),
    )
    .unwrap();
    let mut normalizer = TimestampNormalizer::new(domain, Some(250), -50).unwrap();
    assert_eq!(normalizer.normalize(250).unwrap(), -50);
    assert_eq!(normalizer.normalize(255).unwrap(), 0);
    assert_eq!(normalizer.normalize(3).unwrap(), 40);

    let domain = ClockDomainSpec::new(
        "monotonic",
        RationalTickScale::new(1, 1).unwrap(),
        None,
        None,
    )
    .unwrap();
    let mut normalizer = TimestampNormalizer::new(domain, None, 0).unwrap();
    assert_eq!(normalizer.normalize(10).unwrap(), 0);
    assert!(matches!(
        normalizer.normalize(9),
        Err(ClockError::RawTimestampOutOfOrder { .. })
    ));
}

#[test]
fn clock_domain_registry_rejects_mixing() {
    let mut registry = ClockDomainRegistry::new();
    registry
        .register(
            ClockDomainSpec::new(
                "trace",
                RationalTickScale::from_hz(100_000_000).unwrap(),
                None,
                None,
            )
            .unwrap(),
        )
        .unwrap();
    registry
        .register(
            ClockDomainSpec::new(
                "wall",
                RationalTickScale::from_hz(1_000).unwrap(),
                None,
                None,
            )
            .unwrap(),
        )
        .unwrap();
    assert!(registry.require_same("trace", "trace").is_ok());
    assert!(matches!(
        registry.require_same("trace", "wall"),
        Err(ClockError::DomainMismatch { .. })
    ));
}

#[test]
fn same_tick_without_explicit_cross_source_order_is_ambiguous() {
    let mut left = SyntheticConfig::new("left", 2);
    left.start_ns = 0;
    left.step_ns = 1;
    let mut right = SyntheticConfig::new("right", 1);
    right.start_ns = 1;
    let mut merge = KWayMerge::new(vec![boxed(left), boxed(right)]).unwrap();
    assert_eq!(
        merge
            .next_observation()
            .unwrap()
            .unwrap()
            .observation
            .ts_ns(),
        0
    );
    let error = merge.next_observation().unwrap_err();
    assert!(matches!(
        error,
        SourceError::Merge(MergeError::AmbiguousTick { timestamp: 1, .. })
    ));
}

#[test]
fn explicit_order_keys_make_merge_deterministic_across_source_order() {
    let mut left = SyntheticConfig::new("left", 3);
    left.step_ns = 1;
    left.order_key_start = Some(0);
    let mut right = SyntheticConfig::new("right", 3);
    right.step_ns = 1;
    right.order_key_start = Some(100);

    let forward =
        collect_ids(KWayMerge::new(vec![boxed(left.clone()), boxed(right.clone())]).unwrap())
            .unwrap();
    let reverse = collect_ids(KWayMerge::new(vec![boxed(right), boxed(left)]).unwrap()).unwrap();
    assert_eq!(forward, reverse);
    assert_eq!(
        forward
            .iter()
            .map(|(source, timestamp, _)| (source.as_str(), *timestamp))
            .collect::<Vec<_>>(),
        vec![
            ("left", 0),
            ("right", 0),
            ("left", 1),
            ("right", 1),
            ("left", 2),
            ("right", 2),
        ]
    );
}

#[test]
fn duplicate_explicit_order_keys_are_ambiguous() {
    let mut left = SyntheticConfig::new("left", 1);
    left.order_key_start = Some(7);
    let mut right = SyntheticConfig::new("right", 1);
    right.order_key_start = Some(7);
    let mut merge = KWayMerge::new(vec![boxed(left), boxed(right)]).unwrap();
    assert!(matches!(
        merge.next_observation(),
        Err(SourceError::Merge(MergeError::AmbiguousTick { .. }))
    ));
}

#[test]
fn merge_rejects_clock_domain_mismatch_before_consuming() {
    let left = SyntheticConfig::new("left", 1);
    let mut right = SyntheticConfig::new("right", 1);
    right.clock_domain = "other".to_owned();
    let error = KWayMerge::new(vec![boxed(left), boxed(right)])
        .err()
        .expect("domain mismatch");
    assert!(matches!(
        error,
        SourceError::Merge(MergeError::ClockDomainMismatch { .. })
    ));
}
