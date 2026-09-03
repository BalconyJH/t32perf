OUTPUT_ARCH(arm)
ENTRY(_start)

MEMORY {
    FLASH (rx) : ORIGIN = 0x00000100, LENGTH = 0x100
}

PHDRS {
    text PT_LOAD FLAGS(5);
}

SECTIONS {
    .text : {
        KEEP(*(.text._start))
        KEEP(*(.text.first))
        KEEP(*(.text.second))
    } > FLASH :text
}
