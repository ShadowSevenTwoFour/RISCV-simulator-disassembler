from elftools.elf.elffile import ELFFile
import argparse
import sys

class RV64Simulator:
    def __init__(self, mem_size=128 * 1024 * 1024):  # Larger memory size for realistic programs
        self.registers = [0] * 32  # General-purpose registers (x0-x31)
        self.pc = 0  # Program counter
        self.memory = bytearray(mem_size)  # Allocated memory
        self.mmio_start = 0xFFFFFFFFFFFF0000  # MMIO base address
        self.mmio = {
            0xFFFFFFFFFFFF0000: 0,  # Keyboard input register
            0xFFFFFFFFFFFF0004: 0,  # Status register (input available flag)
        }

        self.mem_size = mem_size

    def load_elf_binary(self, filepath):
        """Load an ELF binary into the simulator's memory."""
        with open(filepath, "rb") as f:
            elffile = ELFFile(f)
            entry_point = elffile.header["e_entry"]
            self.pc = entry_point

            # Base translation offset for high virtual addresses
            vaddr_offset = 0x00000000  # Starting virtual address in the ELF file
            base_translation = 0  # Map to physical address 0

            # Load program segments into memory
            for segment in elffile.iter_segments():
                if segment["p_type"] == "PT_LOAD":  # Loadable segment
                    addr = segment["p_vaddr"] - vaddr_offset + base_translation
                    if addr < 0 or addr + len(segment.data()) > self.mem_size:
                        raise MemoryError(
                            f"Segment at virtual address {segment['p_vaddr']:#x} "
                            f"maps to out-of-bounds memory."
                        )
                    data = segment.data()
                    self.memory[addr:addr + len(data)] = data
                    if segment["p_memsz"] > segment["p_filesz"]:  # Handle .bss section
                        bss_start = addr + len(data)
                        bss_end = addr + segment["p_memsz"]
                        for i in range(bss_start, bss_end):
                            self.memory[i] = 0

            print(f"Loaded ELF binary '{filepath}' with entry point: {entry_point:#x}")


    def dump_registers(self, dump=32):
        """Print the contents of all registers."""
        print("Registers:")
        for i in range(dump):
            print(f"x{i:02}: {self.registers[i]:#018x}")

    def fetch(self):
        """Fetch the next instruction."""
        instruction = int.from_bytes(self.memory[self.pc:self.pc + 4], "little")
        self.pc += 4
        return instruction

    def decode(self, instruction):
        """Decode a 32-bit instruction."""
        opcode = instruction & 0x7F
        rd = (instruction >> 7) & 0x1F
        funct3 = (instruction >> 12) & 0x7
        rs1 = (instruction >> 15) & 0x1F
        rs2 = (instruction >> 20) & 0x1F
        funct7 = (instruction >> 25) & 0x7F
        imm_i = self.sign_extend(instruction >> 20, 12)
        imm_s = self.sign_extend((((instruction >> 25) & 0x7F) << 5) | ((instruction >> 7) & 0x1F), 12)
        imm_b = self.sign_extend(
            ((instruction >> 31) << 12) | (((instruction >> 7) & 0x1) << 11) |
            (((instruction >> 25) & 0x3F) << 5) | ((instruction >> 8) & 0xF), 13)
        imm_u = instruction & 0xFFFFF000
        imm_j = self.sign_extend(
            ((instruction >> 31) << 20) | (((instruction >> 12) & 0xFF) << 12) |
            (((instruction >> 20) & 0x1) << 11) | ((instruction >> 21) & 0x3FF), 21)
        return opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_s, imm_b, imm_u, imm_j

    def sign_extend(self, value, bits):
        """Sign-extend an immediate value."""
        if value & (1 << (bits - 1)):
            value -= 1 << bits
        return value

    def mmio_read(self, address):
        """Handle MMIO reads."""
        if address == 0xFFFFFFFFFFFF0000:  # Input register
            print(f"MMIO read: Input register, value={self.mmio[address]}")
            return self.mmio[address]
        elif address == 0xFFFFFFFFFFFF0004:  # Status register
            print(f"MMIO read: Status register, value={self.mmio[address]}")
            return self.mmio[address]
        else:
            raise ValueError(f"Invalid MMIO read from address 0x{address:x}")


    def mmio_write(self, address, value):
        """Handle MMIO writes."""
        if address == 0xFFFFFFFFFFFF0000:  # Input register
            self.mmio[address] = value
            print(f"MMIO write: Input register, value={value}")
        elif address == 0xFFFFFFFFFFFF0004:  # Status register
            self.mmio[address] = value
            print(f"MMIO write: Status register, value={value}")
        else:
            raise ValueError(f"Invalid MMIO write to address 0x{address:x}")



    def execute(self, opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_s, imm_b, imm_u, imm_j):
        """Execute a decoded instruction."""
        if opcode == 0x0:  # NOP or uninitialized memory
            # No operation; just advance the PC
            print("NOP: No operation")
            return
        elif opcode == 0x1B:  # RV64I: Integer Register-Immediate Word Instructions
            if funct3 == 0x0:  # ADDIW: Add Immediate Word
                self.registers[rd] = (self.registers[rs1] + imm_i) & 0xFFFFFFFF
                # Sign-extend the result to 64 bits
                self.registers[rd] = self.sign_extend(self.registers[rd], 32)
                print(f"ADDIW: x{rd} = (x{rs1} + {imm_i}) = {self.registers[rd]:#x}")

        elif funct3 == 0x1:  # SLLIW: Shift Left Logical Immediate Word
            self.registers[rd] = (self.registers[rs1] << (imm_i & 0x1F)) & 0xFFFFFFFF
            # Sign-extend the result to 64 bits
            self.registers[rd] = self.sign_extend(self.registers[rd], 32)
            print(f"SLLIW: x{rd} = (x{rs1} << {imm_i & 0x1F}) = {self.registers[rd]:#x}")

        elif funct3 == 0x5:  # SRLIW/SRAIW: Shift Right Logical/Arithmetic Word
            if funct7 == 0x00:  # SRLIW: Shift Right Logical Immediate Word
                self.registers[rd] = (self.registers[rs1] & 0xFFFFFFFF) >> (imm_i & 0x1F)
                self.registers[rd] = self.sign_extend(self.registers[rd], 32)
                print(f"SRLIW: x{rd} = (x{rs1} >> {imm_i & 0x1F}) = {self.registers[rd]:#x}")
            elif funct7 == 0x20:  # SRAIW: Shift Right Arithmetic Immediate Word
                word = self.registers[rs1] & 0xFFFFFFFF
                self.registers[rd] = self.sign_extend(word >> (imm_i & 0x1F), 32)
                print(f"SRAIW: x{rd} = (x{rs1} >> {imm_i & 0x1F}) (arithmetic) = {self.registers[rd]:#x}")

        elif opcode == 0x33:  # R-Type: Register-Register operations
            if funct3 == 0x0:  # ADD or SUB
                if funct7 == 0x00:  # ADD
                    self.registers[rd] = (self.registers[rs1] + self.registers[rs2]) & 0xFFFFFFFFFFFFFFFF
                elif funct7 == 0x20:  # SUB
                    self.registers[rd] = (self.registers[rs1] - self.registers[rs2]) & 0xFFFFFFFFFFFFFFFF
            elif funct3 == 0x7:  # AND
                self.registers[rd] = self.registers[rs1] & self.registers[rs2]
            elif funct3 == 0x6:  # OR
                self.registers[rd] = self.registers[rs1] | self.registers[rs2]
            elif funct3 == 0x4:  # XOR
                self.registers[rd] = self.registers[rs1] ^ self.registers[rs2]
            elif funct3 == 0x1:  # SLL (Shift Left Logical)
                self.registers[rd] = (self.registers[rs1] << (self.registers[rs2] & 0x3F)) & 0xFFFFFFFFFFFFFFFF
            elif funct3 == 0x5:  # SRL or SRA
                if funct7 == 0x00:  # SRL (Shift Right Logical)
                    self.registers[rd] = self.registers[rs1] >> (self.registers[rs2] & 0x3F)
                elif funct7 == 0x20:  # SRA (Shift Right Arithmetic)
                    self.registers[rd] = (self.registers[rs1] >> (self.registers[rs2] & 0x3F)) | (
                        (self.registers[rs1] & (1 << 63)) * ((1 << (self.registers[rs2] & 0x3F)) - 1))

        elif opcode == 0x13:  # I-Type: Register-Immediate operations
            if funct3 == 0x0:  # ADDI
                self.registers[rd] = (self.registers[rs1] + imm_i) & 0xFFFFFFFFFFFFFFFF
            elif funct3 == 0x7:  # ANDI
                self.registers[rd] = self.registers[rs1] & imm_i
            elif funct3 == 0x6:  # ORI
                self.registers[rd] = self.registers[rs1] | imm_i
            elif funct3 == 0x4:  # XORI
                self.registers[rd] = self.registers[rs1] ^ imm_i
            elif funct3 == 0x1:  # SLLI (Shift Left Logical Immediate)
                self.registers[rd] = (self.registers[rs1] << (imm_i & 0x3F)) & 0xFFFFFFFFFFFFFFFF
            elif funct3 == 0x5:  # SRLI or SRAI
                if funct7 == 0x00:  # SRLI (Shift Right Logical Immediate)
                    self.registers[rd] = self.registers[rs1] >> (imm_i & 0x3F)
                elif funct7 == 0x20:  # SRAI (Shift Right Arithmetic Immediate)
                    self.registers[rd] = (self.registers[rs1] >> (imm_i & 0x3F)) | (
                        (self.registers[rs1] & (1 << 63)) * ((1 << (imm_i & 0x3F)) - 1))

        elif opcode == 0x63:  # B-Type: Conditional branches
            target = self.pc + imm_b - 4  # Adjust for PC increment during fetch
            if funct3 == 0x0:  # BEQ
                if self.registers[rs1] == self.registers[rs2]:
                    self.pc = target
            elif funct3 == 0x1:  # BNE
                if self.registers[rs1] != self.registers[rs2]:
                    self.pc = target
            elif funct3 == 0x4:  # BLT
                if self.registers[rs1] < self.registers[rs2]:
                    self.pc = target
            elif funct3 == 0x5:  # BGE
                if self.registers[rs1] >= self.registers[rs2]:
                    self.pc = target

        elif opcode == 0x6F:  # JAL (Jump and Link)
            self.registers[rd] = self.pc
            self.pc += imm_j - 4

        elif opcode == 0x67:  # JALR (Jump and Link Register)
            self.registers[rd] = self.pc
            self.pc = (self.registers[rs1] + imm_i) & ~1

        elif opcode == 0x37:  # LUI (Load Upper Immediate)
            self.registers[rd] = imm_u

        elif opcode == 0x17:  # AUIPC (Add Upper Immediate to PC)
            self.registers[rd] = self.pc + imm_u - 4

        elif opcode == 0x03:  # Load
            address = self.registers[rs1] + imm_i
            if self.mmio_start <= address:
                self.registers[rd] = self.mmio_read(address)
            else:
                self.registers[rd] = int.from_bytes(self.memory[address:address + 8], "little")

        elif opcode == 0x23:  # Store
            address = self.registers[rs1] + imm_s
            value = self.registers[rs2]
            if self.mmio_start <= address:
                self.mmio_write(address, value)
            else:
                self.memory[address:address + 8] = value.to_bytes(8, "little")

        elif opcode == 0x73:  # ECALL
            self.handle_ecall()

        else:  # Unhandled instruction
            print(f"Unhandled instruction with opcode: {opcode:#x}")
            raise NotImplementedError(f"Opcode {opcode:#x} not implemented.")


    def handle_ecall(self):
        """Handle RISC-V system calls."""
        syscall_code = self.registers[17]  # a7 contains the syscall code
        if syscall_code == 10:  # Exit
            print("Program exited.")
            sys.exit(self.registers[10])  # a0 contains the exit code
        elif syscall_code == 11:  # Print character
            char = chr(self.registers[10])  # a0 contains the character
            print(char, end="")
        elif syscall_code == 13:  # Read keyboard input
            user_input = input("Input: ")
            self.mmio[0xFFFF0000] = ord(user_input[0]) if user_input else 0
            self.mmio[0xFFFF0004] = 1  # Set input available flag
        else:
            print(f"Unhandled system call: {syscall_code}")

    def run(self, steps=None, trace=False):
        """Run the simulator."""
        count = 0
        while steps is None or count < steps:
            if trace:
                print(f"PC: {self.pc:#x}")
            instruction = self.fetch()
            if trace:
                print(f"Fetched instruction: {instruction:#010x}")
            opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_s, imm_b, imm_u, imm_j = self.decode(instruction)
            if trace:
                print(f"Decoded: opcode={opcode:#x}, rd=x{rd}, rs1=x{rs1}, rs2=x{rs2}")
            self.execute(opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_s, imm_b, imm_u, imm_j)

            # Simulate MMIO Input
            if self.mmio[0xFFFFFFFFFFFF0004] == 0:  # Status register: no input available
                user_input = input("MMIO Input (single character): ")
                if user_input:
                    self.mmio[0xFFFFFFFFFFFF0000] = ord(user_input[0])  # Store input character
                    self.mmio[0xFFFFFFFFFFFF0004] = 1  # Set input available flag
            count += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RISC-V RV64I Simulator with MMIO")
    parser.add_argument("--elf", type=str, help="Path to ELF binary")
    parser.add_argument("--steps", type=int, help="Number of steps to execute", default=None)
    parser.add_argument("--trace", action="store_true", help="Enable trace mode")
    args = parser.parse_args()

    sim = RV64Simulator()

    if args.elf:
        sim.load_elf_binary(args.elf)
    else:
        print("No ELF binary provided. Use --elf to specify a file.")
        exit(1)

    sim.run(steps=args.steps, trace=args.trace)

