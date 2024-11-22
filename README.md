RISC-V Simulator and Disassembler

Overview
riscv-simulator-disassembler is a Python-based RISC-V RV64I simulator and disassembler designed to execute RISC-V programs, debug them, and analyze their behavior. It supports ELF binary execution, MMIO (memory-mapped I/O), and instruction tracing for learning, debugging, or testing.

With this project, you can:

Simulate RISC-V programs written in assembly or compiled to ELF binaries.
Disassemble RISC-V binaries to understand their instruction-level behavior.
Use interactive MMIO to provide input and process output in real time.
Features
Simulator
RV64I Instruction Set: Full implementation of the base RV64I instruction set, including arithmetic, memory, branching, and system calls.
ELF Binary Support: Parses ELF binaries and loads their segments into simulated memory.
MMIO Integration:
Keyboard Input Register (0xFFFF0000): Simulates reading user input.
Status Register (0xFFFF0004): Tracks input availability for polling.
Trace Mode: Logs detailed execution information, including fetched instructions, decoded fields, and register states.
Interactive Input: Simulates user interaction for real-time input processing.
Disassembler
Converts RISC-V binaries or individual instructions into human-readable assembly.
Helps debug and analyze programs without external tools.
Getting Started
Prerequisites
Python 3.7+

RISC-V GNU Toolchain

Install the toolchain on Linux/Debian:
bash
Copy code
sudo apt install gcc-riscv64-unknown-elf binutils-riscv64-unknown-elf
Follow the RISC-V Toolchain Installation Guide.
PyELFTools (for parsing ELF binaries):

bash
Copy code
pip install pyelftools
Usage
Compile and Run a RISC-V Program
Write your RISC-V program in assembly (e.g., program.S).

Example program (mmio_test.S):

asm
Copy code
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
Assemble and link the program:

bash
Copy code
riscv64-unknown-elf-as -o mmio_test.o mmio_test.S
riscv64-unknown-elf-ld -o mmio_test.elf mmio_test.o --entry=_start
Run the program in the simulator:

bash
Copy code
python simulator.py --elf mmio_test.elf --trace
Command-Line Options
--elf <file>: Path to the ELF binary to load.
--steps <number>: Limit the number of executed instructions.
--trace: Enable detailed execution tracing.
Disassembler
The disassembler converts RISC-V binaries into readable assembly instructions. Use it to inspect compiled binaries or analyze execution traces.

Usage
To disassemble an ELF binary:

bash
Copy code
python disassembler.py --elf program.elf
Expected output:

makefile
Copy code
0x100b0: lui t0, 0x10
0x100b4: addiw t0, t0, -1
0x100b8: slli t0, t0, 16
...
Development
Supported Instructions
RV64I Base Instructions: All integer, load/store, branching, and system-level instructions (ecall, ebreak).
Custom MMIO:
0xFFFF0000: Keyboard input register.
0xFFFF0004: Status register.
Planned Features
Support for RISC-V extensions (M, F, etc.).
Enhanced debugging tools, including memory dumps.
Integrated disassembler in the simulator's trace mode.
Example: MMIO Input/Output Simulation
Run the provided mmio_test.elf:

bash
Copy code
python simulator.py --elf mmio_test.elf --trace
Simulator output:

plaintext
Copy code
MMIO Input (single character): a
aMMIO Input (single character): b
bMMIO Input (single character): c
c
Contributing
Contributions are welcome! Feel free to fork the repository, submit issues, or create pull requests to improve the simulator and disassembler.

License
This project is licensed under the MIT License. See the LICENSE file for details.

Acknowledgments
RISC-V Foundation for the open and extensible instruction set.
PyELFTools for simplifying ELF parsing in Python.
The broader RISC-V community for open-source tools and resources.
