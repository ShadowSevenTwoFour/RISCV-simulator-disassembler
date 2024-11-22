.section .text
.globl _start
_start:
    # Wait for input
    li t0, 0xFFFF0004        # MMIO address for input status
wait_input:
    lw t1, 0(t0)             # Load status
    beqz t1, wait_input      # Loop until input is available

    # Read the input
    li t0, 0xFFFF0000        # MMIO address for input register
    lb a0, 0(t0)             # Load input character
    li a7, 11                # Print character syscall
    ecall

    # Clear input status
    li t0, 0xFFFF0004        # Status register
    sw zero, 0(t0)           # Clear status
    j wait_input             # Loop to wait for next input
