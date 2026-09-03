# ARM Thumb ELF fixture

`arm-thumb-et-exec.elf` is a minimal ARM Cortex-M0+ executable used to test
`PT_LOAD`, `STT_FUNC`, Thumb-address normalization, and exact symbol aliases.
It contains no vendor code.

It was generated with Arm GNU Toolchain 15.3.Rel1, Binutils 2.45.1.20260126:

```powershell
arm-none-eabi-as -mcpu=cortex-m0plus -mthumb arm-thumb-et-exec.S -o arm-thumb-et-exec.o
arm-none-eabi-ld -T arm-thumb-et-exec.ld -o arm-thumb-et-exec.elf arm-thumb-et-exec.o
arm-none-eabi-readelf -h -l -s arm-thumb-et-exec.elf
```

The object file is an intermediate and is not retained. The checked-in ELF is
the immutable test input; tests assert its SHA-256:

```text
466facf0c04484b88d07e7c33dac47cc049e154b8741bd8f5dd18a1d0ea49baf
```
