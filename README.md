# RISC-V Simulator and Disassembler

## Overview

`riscv-simulator-disassembler` is a Python-based **RISC-V RV64I simulator and disassembler** designed to execute RISC-V programs, debug them, and analyze their behavior. It supports ELF binary execution, MMIO (memory-mapped I/O), and instruction tracing for learning, debugging, or testing.

With this project, you can:
- Simulate RISC-V programs written in assembly or compiled to ELF binaries.
- Disassemble RISC-V binaries to understand their instruction-level behavior.
- Use interactive MMIO to provide input and process output in real time.

---

## Features

### Simulator
- **RV64I Instruction Set**: Full implementation of the base RV64I instruction set, including arithmetic, memory, branching, and system calls.
- **ELF Binary Support**: Parses ELF binaries and loads their segments into simulated memory.
- **Trace Mode**: Logs detailed execution information, including fetched instructions, decoded fields, and register states.
- **Interactive Input**: Simulates user interaction for real-time input processing.

### Disassembler
- Converts ELF binaries into human-readable assembly.
- Helps debug and analyze programs without external tools.

---

## Getting Started

### Prerequisites

1. **Python 3.7+**
2. **RISC-V GNU Toolchain**
   - Install the toolchain on Linux/Debian:
     ```bash
     sudo apt install gcc-riscv64-unknown-elf binutils-riscv64-unknown-elf
     ```
   - Follow the [RISC-V Toolchain Installation Guide](https://github.com/riscv-collab/riscv-gnu-toolchain).
3. **PyELFTools** (for parsing ELF binaries):
   ```bash
   pip install pyelftools


## Contributing
Contributions are welcome! Feel free to fork the repository, submit issues, or create pull requests to improve the simulator and disassembler. Currently trying to implement MMIO, which is a WIP.


