# Golden Firmware contract

The repository does not fabricate MCU-independent “Golden Firmware”. Real firmware is supplied by the target platform and must expose all of the following:

- A known number of nested function calls, with recursion or at least three levels of depth.
- At least two Tasks, including idle, preemption, and resumption.
- Controllable ISRs and nested ISRs.
- Triggerable trace overflow or equivalent data loss.
- Custom instant, span, and counter events.
- Independently verifiable heap peak, Task stack watermark, and static RAM.
- A fixed workload seed and completion condition.

Deliver the ELF, MAP, ORTI/ARTI, compiler stack-usage files, firmware image, build command, and SHA-256. Proprietary binaries may remain in a laboratory artifact store, but the manifest must retain immutable references and digests.
