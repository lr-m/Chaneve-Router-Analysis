.text
.section .start,"ax",@progbits
.align 1
.global _start
.type   _start, @function

.extern PayloadEntry

_start:
    # Save registers to stack
    addiu $sp, $sp, -16

    # Jump to entry
    jal PayloadEntry
    nop

    # Restore registers from stack
    addiu $sp, $sp, 16

    # Return
    jr $ra
    nop

    .align 2
