    .section .text
    .global _start
_start:
    # Addresses
    li t0, 0xFFFF0000         # MMIO output
    li t1, 0xFFFF0004         # MMIO input
    li t2, 0xFFFF0008         # MMIO status

    # Print prompt "Enter a char: "
    li a0, 'E'
    sb a0, 0(t0)
    li a0, 'n'
    sb a0, 0(t0)
    li a0, 't'
    sb a0, 0(t0)
    li a0, 'e'
    sb a0, 0(t0)
    li a0, 'r'
    sb a0, 0(t0)
    li a0, ' '
    sb a0, 0(t0)
    li a0, 'a'
    sb a0, 0(t0)
    li a0, ' '
    sb a0, 0(t0)
    li a0, 'c'
    sb a0, 0(t0)
    li a0, 'h'
    sb a0, 0(t0)
    li a0, 'a'
    sb a0, 0(t0)
    li a0, 'r'
    sb a0, 0(t0)
    li a0, ':'
    sb a0, 0(t0)
    li a0, ' '
    sb a0, 0(t0)

    # Loop until input is ready
wait_input:
    ld a1, 0(t2)    # read status register (8 bytes)
    beqz a1, wait_input

    # Input ready, read character
    ld a1, 0(t1)    # read input char from 0xFFFF0004
                    # a1 now has the ASCII code

    # Print "You typed: "
    li a0, 'Y'
    sb a0, 0(t0)
    li a0, 'o'
    sb a0, 0(t0)
    li a0, 'u'
    sb a0, 0(t0)
    li a0, ' '
    sb a0, 0(t0)
    li a0, 't'
    sb a0, 0(t0)
    li a0, 'y'
    sb a0, 0(t0)
    li a0, 'p'
    sb a0, 0(t0)
    li a0, 'e'
    sb a0, 0(t0)
    li a0, 'd'
    sb a0, 0(t0)
    li a0, ':'
    sb a0, 0(t0)
    li a0, ' '
    sb a0, 0(t0)

    # Print the character typed
    sb a1, 0(t0)

    # Print newline
    li a0, 10
    sb a0, 0(t0)

    # Infinite loop
    j .
