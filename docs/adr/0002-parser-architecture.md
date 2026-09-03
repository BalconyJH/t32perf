# ADR 0002: Layer Observations and Derived Models

Status: Accepted

## Decision

Input adapters produce observations only, such as function entry/exit, task switches, ISR entry/exit, samples, counters, and trace gaps. The analysis layer derives spans, running intervals, hotspots, and resource metrics from observations.

Canonical artifacts use versioned NDJSON. The parser, analyzer, and exporter are connected through synchronous pull/sink interfaces and never load the complete event set into memory. Multiple ordered inputs use a k-way merge; unordered input reports its precise location and is never sorted implicitly.

## Rationale

Sampling, instrumentation, and complete program flow have different accuracy characteristics. If an adapter constructs duration slices directly, it hides provenance and can make statistical results appear exact. Layering lets metric support express the confidence of each conclusion independently.
