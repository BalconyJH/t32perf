# Deployment-Owned Fault Scenarios

- `perf_configure_sampling_buffer_full.cmm` configures a 32-record SNOOPer Stack. The external workload owner continues target execution until SNOOPer automatically enters `break`; the fixed Stop script records `STATE=break` and `RECORDS=SIZE=32` before `OFF`. Health V2 derives `sampling_buffer_full` only from this immutable Stop evidence.
- SNOOPer PC has no flow decoder, so `flow_error` is explicitly unsupported and has no fabricated injector.
- TRACE32/driver disconnect is performed by the deployment Controller at the fixed phase specified by `fault-scenarios.json`.
- `perf_start_cmm_abort_target.cmm` enters the fixed abort window after SNOOPer Arm is confirmed. The deployment Controller invokes only official two-phase `abort_practice_skill`. `perf_recover_cmm_abort.cmm` binds abort receipt/profile/binding, restores canonical SNOOPer baseline, and never resumes the failed Session.

Public scenario strings cannot address these scripts. HIL configuration may select only pre-registered exact scenario IDs and repository-owned script paths.
