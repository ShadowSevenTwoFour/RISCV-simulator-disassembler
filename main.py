from simulator import RV64Simulator
from disassembler import RISCVDissasembler
import argparse
import sys

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bare-metal RISC-V RV64I Simulator and Disassembler with MMIO")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--elf", type=str, help="Path to ELF binary to simulate")
    group.add_argument("--disassemble", type=str, help="Path to ELF binary to disassemble")
    parser.add_argument("--steps", type=int, help="Number of steps to execute (simulation mode only)", default=None)
    parser.add_argument("--trace", action="store_true", help="Enable trace mode (simulation mode only)")
    args = parser.parse_args()

    if args.elf:
        sim = RV64Simulator()

        try:
            sim.load_elf_binary(args.elf)
        except Exception as e:
            print(f"Error loading ELF binary: {e}")
            sys.exit(1)

        sim.run(steps=args.steps, trace=args.trace)
    elif args.disassemble:
        try:
            disassembler = RISCVDissasembler(args.disassemble)
            disassembler.disassemble()
        except Exception as e:
            print(f"Error disassembling ELF binary: {e}")
            sys.exit(1)
