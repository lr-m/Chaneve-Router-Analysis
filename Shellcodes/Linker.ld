OUTPUT_ARCH(mips:isa32r2)

__base = 0x8026b870;

ENTRY(_start)

PHDRS {
    start_seg PT_LOAD FLAGS(7);
}

SECTIONS {
    . = __base;
    __self_start = .;

    .start : { *(.start) } :start_seg = 0

    . = ALIGN(32);
    .text : {
        *(.text)
        *(.text.*)
    }
    .rodata : {
        *(.rodata)
        *(.rodata.*)
    }
    .data : {
        *(.data)
        *(.data.*)
        *(.sdata)
        *(.sdata.*)
    }
    .bss : {
        *(.sbss)
        *(.sbss.*)
        *(COMMON)
        *(.bss)
        *(.bss.*)
        LONG(0)
    }
}
