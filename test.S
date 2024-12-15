    .section .text
    .global _start
_start:
    # Put 'H' in a0
    li a0, 'H'
    # Store byte to 0xFFFF0000
    li t0, 0xFFFF0000
    sb a0, 0(t0)

    # Put 'i' in a0
    li a0, 'i'
    sb a0, 0(t0)

    # Put '\n' in a0 (newline)
    li a0, 10
    sb a0, 0(t0)

    # Endless loop
1:  j 1b
