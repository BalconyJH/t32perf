# Sample trace boundary

The software golden fixture is [`fixtures/golden/observations.jsonl`](../fixtures/golden/observations.jsonl). It is a canonical synthetic observation stream, not a TRACE32 export.

A real integration must retain at least the following in this directory or in a controlled artifact store:

```text
raw-trace.<validated format>
task-events.csv
isr-events.<validated format>
trace32-native-statistics.json
health-evidence.json
```

Before adding a real fixture, record the TRACE32 release/build, export command, time base, ELF/MAP/ORTI/ARTI SHA-256 values, and redaction statement. A parser adapter must not infer column semantics from an unlabelled sample source.
