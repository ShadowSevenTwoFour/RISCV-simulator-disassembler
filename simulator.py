from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section
import argparse
import sys
import binascii

class RV64Simulator:
    def __init__(self, mem_size=128 * 1024 * 1024):
        self.registers = [0] * 32  # x0-x31
        self.pc = 0
        self.memory = bytearray(mem_size)
        self.mem_size = mem_size

        # MMIO addresses
        self.mmio_output_addr = 0xFFFF0000
        self.mmio_input_request_addr = 0xFFFF0002
        self.mmio_input_addr = 0xFFFF0004
        self.mmio_status_addr = 0xFFFF0008
        self.mmio_exit_addr = 0xFFFF0001
        self.mmio_start = 0xFFFF0000

        # Input handling flags
        self.mmio_input_ready = False
        self.mmio_input_value = 0

    def load_elf_binary(self, filepath):
        """Load an ELF binary into the simulator's memory."""
        with open(filepath, "rb") as f:
            elffile = ELFFile(f)
            entry_point = elffile.header["e_entry"]
            self.pc = entry_point

            for segment in elffile.iter_segments():
                if segment["p_type"] == "PT_LOAD":
                    vaddr = segment["p_vaddr"]
                    size = segment["p_memsz"]
                    fsize = segment["p_filesz"]

                    if vaddr + size > self.mem_size:
                        raise MemoryError(f"Segment at {vaddr:#x} too large for allocated memory.")

                    data = segment.data()
                    self.memory[vaddr:vaddr+fsize] = data
                    # Zero-fill BSS
                    if size > fsize:
                        self.memory[vaddr+fsize:vaddr+size] = b'\x00' * (size - fsize)

            print(f"Loaded ELF binary '{filepath}' with entry point: {entry_point:#x}")

    def dump_registers(self, dump=32):
        print("Registers:")
        for i in range(dump):
            print(f"x{i:02}: {self.registers[i]:#018x}")

    def fetch(self):
        """Fetch the next 32-bit instruction."""
        if self.pc + 4 > self.mem_size:
            raise MemoryError(f"PC out of range: {self.pc:#x}")

        instruction = int.from_bytes(self.memory[self.pc:self.pc+4], "little")
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

        imm_i = self.sign_extend((instruction >> 20) & 0xFFF, 12)
        imm_s = self.sign_extend(((instruction >> 25) << 5) | ((instruction >> 7) & 0x1F), 12)
        imm_b = self.sign_extend(((instruction >> 31) << 12) |
                                 (((instruction >> 7) & 0x1) << 11) |
                                 (((instruction >> 25) & 0x3F) << 5) |
                                 ((instruction >> 8) & 0xF), 13)
        imm_u = (instruction & 0xFFFFF000)
        imm_j = self.sign_extend(((instruction >> 31) << 20) |
                                 (((instruction >> 12) & 0xFF) << 12) |
                                 (((instruction >> 20) & 0x1) << 11) |
                                 ((instruction >> 21) & 0x3FF), 21)
        return opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_s, imm_b, imm_u, imm_j

    def sign_extend(self, value, bits):
        """Sign-extend an immediate value."""
        mask = 1 << (bits - 1)
        return (value ^ mask) - mask

    def set_register(self, rd, val):
        """Set register rd to val, ensuring x0 is always 0."""
        if rd != 0:
            self.registers[rd] = val & 0xFFFFFFFFFFFFFFFF

    def memory_read(self, address, size, signed=False):
        # Handle MMIO input and status
        if address == self.mmio_input_addr and size == 8:
            # Reading the input register
            if self.mmio_input_ready:
                # Consume the input and mark no longer ready
                val = self.mmio_input_value
                self.mmio_input_ready = False
                if signed:
                    return self.sign_extend(val, 64)
                return val
            else:
                # No input ready
                return 0
        elif address == self.mmio_status_addr and size == 8:
            # Status register: 1 if input ready, else 0
            return 1 if self.mmio_input_ready else 0

        # Normal memory read
        if address >= self.mmio_start:
            # No other MMIO reads defined
            return 0
        else:
            if address + size > self.mem_size:
                raise MemoryError(f"Memory read out of range: {address:#x}")
            data = self.memory[address:address+size]
            val = int.from_bytes(data, 'little')
            if signed:
                return self.sign_extend(val, size*8)
            return val

    def memory_write(self, address, value, size):
        if address == self.mmio_output_addr and size == 1:
            # Print a character
            sys.stdout.write(chr(value & 0xFF))
            sys.stdout.flush()
        elif address == self.mmio_input_request_addr and size == 1:
            # Guest requests input by writing 0x1
            if value == 0x1:
                # Prompt user for a line of input
                user_input = input("Enter a line of input: ")
                # Store input in buffer at 0x2000 (fixed address)
                buffer_address = 0x2000
                data = user_input.encode('ascii')
                for i, ch in enumerate(data):
                    if buffer_address + i < self.mem_size:
                        self.memory[buffer_address + i] = ch
                    else:
                        raise MemoryError("Input string buffer out of range")
                # Add null terminator
                if buffer_address + len(data) < self.mem_size:
                    self.memory[buffer_address + len(data)] = 0
                # Set input ready flag
                self.mmio_input_ready = True
        elif address == self.mmio_exit_addr and size == 1:
            # Guest signals exit by writing 0xFF
            if value == 0xFF:
                print("\nProgram exited.")
                sys.exit(0)
        else:
            if address >= self.mmio_start:
                # Undefined MMIO writes are ignored or can raise an error
                pass  # You can choose to print a warning or ignore
            else:
                if address + size > self.mem_size:
                    raise MemoryError(f"Memory write out of range: {address:#x}")
                self.memory[address:address+size] = value.to_bytes(size, 'little')

    def execute(self, opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_s, imm_b, imm_u, imm_j):
        R = self.registers

        def signed64(val):
            return (val ^ (1 << 63)) - (1 << 63) if (val & (1 << 63)) else val

        def slt(a, b):
            return 1 if signed64(a) < signed64(b) else 0

        def sltu(a, b):
            return 1 if a < b else 0

        if opcode == 0x33:
            # R-type
            if funct3 == 0x0:
                if funct7 == 0x00:  # ADD
                    self.set_register(rd, R[rs1] + R[rs2])
                elif funct7 == 0x20:  # SUB
                    self.set_register(rd, R[rs1] - R[rs2])
            elif funct3 == 0x1:  # SLL
                shamt = R[rs2] & 0x3F
                self.set_register(rd, (R[rs1] << shamt) & 0xFFFFFFFFFFFFFFFF)
            elif funct3 == 0x2:  # SLT
                self.set_register(rd, slt(R[rs1], R[rs2]))
            elif funct3 == 0x3:  # SLTU
                self.set_register(rd, sltu(R[rs1], R[rs2]))
            elif funct3 == 0x4:  # XOR
                self.set_register(rd, R[rs1] ^ R[rs2])
            elif funct3 == 0x5:
                shamt = R[rs2] & 0x3F
                if funct7 == 0x00:  # SRL
                    self.set_register(rd, R[rs1] >> shamt)
                elif funct7 == 0x20:  # SRA
                    self.set_register(rd, (signed64(R[rs1]) >> shamt) & 0xFFFFFFFFFFFFFFFF)
            elif funct3 == 0x6:  # OR
                self.set_register(rd, R[rs1] | R[rs2])
            elif funct3 == 0x7:  # AND
                self.set_register(rd, R[rs1] & R[rs2])

        elif opcode == 0x13:  # I-type
            if funct3 == 0x0:  # ADDI
                self.set_register(rd, R[rs1] + imm_i)
            elif funct3 == 0x2:  # SLTI
                self.set_register(rd, slt(R[rs1], imm_i))
            elif funct3 == 0x3:  # SLTIU
                self.set_register(rd, sltu(R[rs1], imm_i & 0xFFFFFFFFFFFFFFFF))
            elif funct3 == 0x4:  # XORI
                self.set_register(rd, R[rs1] ^ imm_i)
            elif funct3 == 0x6:  # ORI
                self.set_register(rd, R[rs1] | imm_i)
            elif funct3 == 0x7:  # ANDI
                self.set_register(rd, R[rs1] & imm_i)
            elif funct3 == 0x1:  # SLLI
                shamt = imm_i & 0x3F
                self.set_register(rd, (R[rs1] << shamt) & 0xFFFFFFFFFFFFFFFF)
            elif funct3 == 0x5:
                shamt = imm_i & 0x3F
                if funct7 == 0x00:  # SRLI
                    self.set_register(rd, R[rs1] >> shamt)
                elif funct7 == 0x20:  # SRAI
                    self.set_register(rd, (signed64(R[rs1]) >> shamt) & 0xFFFFFFFFFFFFFFFF)

        elif opcode == 0x1B:  # RV64I word instructions (ADDIW, SLLIW, SRLIW, SRAIW)
            wmask = 0xFFFFFFFF
            if funct3 == 0x0:  # ADDIW
                val = ((R[rs1] & wmask) + imm_i) & wmask
                val = self.sign_extend(val, 32)
                self.set_register(rd, val)
            elif funct3 == 0x1:  # SLLIW
                shamt = imm_i & 0x1F
                val = (R[rs1] << shamt) & wmask
                val = self.sign_extend(val, 32)
                self.set_register(rd, val)
            elif funct3 == 0x5:
                shamt = imm_i & 0x1F
                if funct7 == 0x00:  # SRLIW
                    val = (R[rs1] & wmask) >> shamt
                    val = self.sign_extend(val, 32)
                    self.set_register(rd, val)
                elif funct7 == 0x20:  # SRAIW
                    sw = self.sign_extend(R[rs1] & wmask, 32)
                    val = (sw >> shamt) & wmask
                    val = self.sign_extend(val, 32)
                    self.set_register(rd, val)

        elif opcode == 0x03:  # Loads
            address = R[rs1] + imm_i
            if funct3 == 0x0:  # LB
                val = self.memory_read(address, 1, signed=True)
            elif funct3 == 0x1:  # LH
                val = self.memory_read(address, 2, signed=True)
            elif funct3 == 0x2:  # LW
                val = self.memory_read(address, 4, signed=True)
            elif funct3 == 0x3:  # LD
                val = self.memory_read(address, 8, signed=True)
            elif funct3 == 0x4:  # LBU
                val = self.memory_read(address, 1, signed=False)
            elif funct3 == 0x5:  # LHU
                val = self.memory_read(address, 2, signed=False)
            elif funct3 == 0x6:  # LWU
                val = self.memory_read(address, 4, signed=False)
            self.set_register(rd, val)

        elif opcode == 0x23:  # Stores
            address = R[rs1] + imm_s
            if funct3 == 0x0:  # SB
                self.memory_write(address, R[rs2], 1)
            elif funct3 == 0x1:  # SH
                self.memory_write(address, R[rs2], 2)
            elif funct3 == 0x2:  # SW
                self.memory_write(address, R[rs2], 4)
            elif funct3 == 0x3:  # SD
                self.memory_write(address, R[rs2], 8)

        elif opcode == 0x63:  # Branches
            target = self.pc + imm_b - 4
            taken = False
            if funct3 == 0x0:  # BEQ
                taken = (R[rs1] == R[rs2])
            elif funct3 == 0x1:  # BNE
                taken = (R[rs1] != R[rs2])
            elif funct3 == 0x4:  # BLT
                taken = (signed64(R[rs1]) < signed64(R[rs2]))
            elif funct3 == 0x5:  # BGE
                taken = (signed64(R[rs1]) >= signed64(R[rs2]))
            elif funct3 == 0x6:  # BLTU
                taken = (R[rs1] < R[rs2])
            elif funct3 == 0x7:  # BGEU
                taken = (R[rs1] >= R[rs2])
            if taken:
                self.pc = target

        elif opcode == 0x6F:  # JAL
            self.set_register(rd, self.pc)
            self.pc += imm_j - 4

        elif opcode == 0x67:  # JALR
            temp = self.pc
            self.pc = (R[rs1] + imm_i) & ~1
            self.set_register(rd, temp)

        elif opcode == 0x37:  # LUI
            self.set_register(rd, imm_u)

        elif opcode == 0x17:  # AUIPC
            self.set_register(rd, self.pc + imm_u - 4)

        elif opcode == 0x73:  # ECALL/EBREAK
            # In bare-metal mode, just ignore or handle specific signals
            pass

        else:
            print(f"Unhandled instruction with opcode: {opcode:#x}")
            raise NotImplementedError(f"Opcode {opcode:#x} not implemented.")

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

            try:
                self.execute(opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_s, imm_b, imm_u, imm_j)
            except NotImplementedError as e:
                print(e)
                sys.exit(1)

            count += 1

class RISCVDissasembler:
    def __init__(self, filepath):
        self.filepath = filepath

    def disassemble(self):
        """Disassemble the ELF binary and print assembly instructions."""
        with open(self.filepath, "rb") as f:
            elffile = ELFFile(f)
            entry_point = elffile.header["e_entry"]
            print(f"Disassembly of '{self.filepath}' starting at entry point {entry_point:#x}:")

            # Iterate over sections
            for section in elffile.iter_sections():
                if not isinstance(section, Section):
                    continue
                # Check if the section is executable
                if section['sh_flags'] & 0x4:  # Executable flag
                    print(f"\nDisassembly of section {section.name}:")
                    code = section.data()
                    addr = section['sh_addr']

                    # Disassemble the instructions
                    self.disassemble_code(addr, code)

    def disassemble_code(self, address, code):
        """Disassemble raw binary code starting from a given address."""
        for i in range(0, len(code), 4):
            instruction = int.from_bytes(code[i:i + 4], byteorder="little")
            try:
                # Decode the instruction
                opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_s, imm_b, imm_u, imm_j = self.decode(instruction)

                # Format the instruction into human-readable assembly
                formatted_instruction = self.format_instruction(opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_s, imm_b, imm_u, imm_j)
            except Exception as e:
                # Handle decoding or formatting errors
                formatted_instruction = f".word {instruction:08x}  # [Error: {str(e)}]"

            # Print the disassembled instruction
            print(f"  {address + i:#x}: {instruction:08x}  {formatted_instruction}")

    def format_instruction(self, opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_s, imm_b, imm_u, imm_j):
        """Format a decoded instruction into its equivalent assembly."""
        def reg_name(reg):  # Helper to format register names
            return f"x{reg}"

        if opcode == 0x33:  # R-type
            if funct3 == 0x0:
                if funct7 == 0x00:  # ADD
                    return f"add {reg_name(rd)}, {reg_name(rs1)}, {reg_name(rs2)}"
                elif funct7 == 0x20:  # SUB
                    return f"sub {reg_name(rd)}, {reg_name(rs1)}, {reg_name(rs2)}"
            elif funct3 == 0x1:  # SLL
                return f"sll {reg_name(rd)}, {reg_name(rs1)}, {reg_name(rs2)}"
            elif funct3 == 0x2:  # SLT
                return f"slt {reg_name(rd)}, {reg_name(rs1)}, {reg_name(rs2)}"
            elif funct3 == 0x3:  # SLTU
                return f"sltu {reg_name(rd)}, {reg_name(rs1)}, {reg_name(rs2)}"
            elif funct3 == 0x4:  # XOR
                return f"xor {reg_name(rd)}, {reg_name(rs1)}, {reg_name(rs2)}"
            elif funct3 == 0x5:
                if funct7 == 0x00:  # SRL
                    return f"srl {reg_name(rd)}, {reg_name(rs1)}, {reg_name(rs2)}"
                elif funct7 == 0x20:  # SRA
                    return f"sra {reg_name(rd)}, {reg_name(rs1)}, {reg_name(rs2)}"
            elif funct3 == 0x6:  # OR
                return f"or {reg_name(rd)}, {reg_name(rs1)}, {reg_name(rs2)}"
            elif funct3 == 0x7:  # AND
                return f"and {reg_name(rd)}, {reg_name(rs1)}, {reg_name(rs2)}"

        elif opcode == 0x13:  # I-type
            if funct3 == 0x0:  # ADDI
                return f"addi {reg_name(rd)}, {reg_name(rs1)}, {imm_i}"
            elif funct3 == 0x2:  # SLTI
                return f"slti {reg_name(rd)}, {reg_name(rs1)}, {imm_i}"
            elif funct3 == 0x3:  # SLTIU
                return f"sltiu {reg_name(rd)}, {reg_name(rs1)}, {imm_i}"
            elif funct3 == 0x4:  # XORI
                return f"xori {reg_name(rd)}, {reg_name(rs1)}, {imm_i}"
            elif funct3 == 0x6:  # ORI
                return f"ori {reg_name(rd)}, {reg_name(rs1)}, {imm_i}"
            elif funct3 == 0x7:  # ANDI
                return f"andi {reg_name(rd)}, {reg_name(rs1)}, {imm_i}"
            elif funct3 == 0x1:  # SLLI
                return f"slli {reg_name(rd)}, {reg_name(rs1)}, {imm_i & 0x3F}"
            elif funct3 == 0x5:
                if funct7 == 0x00:  # SRLI
                    return f"srli {reg_name(rd)}, {reg_name(rs1)}, {imm_i & 0x3F}"
                elif funct7 == 0x20:  # SRAI
                    return f"srai {reg_name(rd)}, {reg_name(rs1)}, {imm_i & 0x3F}"

        elif opcode == 0x1B:  # RV64I word instructions (ADDIW, SLLIW, SRLIW, SRAIW)
            if funct3 == 0x0:  # ADDIW
                return f"addiw {reg_name(rd)}, {reg_name(rs1)}, {imm_i}"
            elif funct3 == 0x1:  # SLLIW
                return f"slliw {reg_name(rd)}, {reg_name(rs1)}, {imm_i & 0x1F}"
            elif funct3 == 0x5:
                if funct7 == 0x00:  # SRLIW
                    return f"srliw {reg_name(rd)}, {reg_name(rs1)}, {imm_i & 0x1F}"
                elif funct7 == 0x20:  # SRAIW
                    return f"sraiw {reg_name(rd)}, {reg_name(rs1)}, {imm_i & 0x1F}"

        elif opcode == 0x03:  # Loads
            if funct3 == 0x0:  # LB
                return f"lb {reg_name(rd)}, {imm_i}({reg_name(rs1)})"
            elif funct3 == 0x1:  # LH
                return f"lh {reg_name(rd)}, {imm_i}({reg_name(rs1)})"
            elif funct3 == 0x2:  # LW
                return f"lw {reg_name(rd)}, {imm_i}({reg_name(rs1)})"
            elif funct3 == 0x3:  # LD
                return f"ld {reg_name(rd)}, {imm_i}({reg_name(rs1)})"
            elif funct3 == 0x4:  # LBU
                return f"lbu {reg_name(rd)}, {imm_i}({reg_name(rs1)})"
            elif funct3 == 0x5:  # LHU
                return f"lhu {reg_name(rd)}, {imm_i}({reg_name(rs1)})"
            elif funct3 == 0x6:  # LWU
                return f"lwu {reg_name(rd)}, {imm_i}({reg_name(rs1)})"

        elif opcode == 0x23:  # Stores
            if funct3 == 0x0:  # SB
                return f"sb {reg_name(rs2)}, {imm_s}({reg_name(rs1)})"
            elif funct3 == 0x1:  # SH
                return f"sh {reg_name(rs2)}, {imm_s}({reg_name(rs1)})"
            elif funct3 == 0x2:  # SW
                return f"sw {reg_name(rs2)}, {imm_s}({reg_name(rs1)})"
            elif funct3 == 0x3:  # SD
                return f"sd {reg_name(rs2)}, {imm_s}({reg_name(rs1)})"

        elif opcode == 0x63:  # Branches
            if funct3 == 0x0:  # BEQ
                return f"beq {reg_name(rs1)}, {reg_name(rs2)}, {imm_b}"
            elif funct3 == 0x1:  # BNE
                return f"bne {reg_name(rs1)}, {reg_name(rs2)}, {imm_b}"
            elif funct3 == 0x4:  # BLT
                return f"blt {reg_name(rs1)}, {reg_name(rs2)}, {imm_b}"
            elif funct3 == 0x5:  # BGE
                return f"bge {reg_name(rs1)}, {reg_name(rs2)}, {imm_b}"
            elif funct3 == 0x6:  # BLTU
                return f"bltu {reg_name(rs1)}, {reg_name(rs2)}, {imm_b}"
            elif funct3 == 0x7:  # BGEU
                return f"bgeu {reg_name(rs1)}, {reg_name(rs2)}, {imm_b}"

        elif opcode == 0x6F:  # JAL
            return f"jal {reg_name(rd)}, {imm_j}"

        elif opcode == 0x67:  # JALR
            return f"jalr {reg_name(rd)}, {imm_i}({reg_name(rs1)})"

        elif opcode == 0x37:  # LUI
            return f"lui {reg_name(rd)}, {imm_u >> 12}"

        elif opcode == 0x17:  # AUIPC
            return f"auipc {reg_name(rd)}, {imm_u >> 12}"

        elif opcode == 0x73:  # ECALL/EBREAK
            return "ecall" if funct3 == 0 else "ebreak"

        return f".word {opcode:08x}"  # Fallback for unrecognized instructions


    def decode(self, instruction):
        """Decode a 32-bit instruction."""
        opcode = instruction & 0x7F
        rd = (instruction >> 7) & 0x1F
        funct3 = (instruction >> 12) & 0x7
        rs1 = (instruction >> 15) & 0x1F
        rs2 = (instruction >> 20) & 0x1F
        funct7 = (instruction >> 25) & 0x7F

        imm_i = self.sign_extend((instruction >> 20) & 0xFFF, 12)
        imm_s = self.sign_extend(((instruction >> 25) << 5) | ((instruction >> 7) & 0x1F), 12)
        imm_b = self.sign_extend(((instruction >> 31) << 12) |
                                 (((instruction >> 7) & 0x1) << 11) |
                                 (((instruction >> 25) & 0x3F) << 5) |
                                 ((instruction >> 8) & 0xF), 13)
        imm_u = (instruction & 0xFFFFF000)
        imm_j = self.sign_extend(((instruction >> 31) << 20) |
                                 (((instruction >> 12) & 0xFF) << 12) |
                                 (((instruction >> 20) & 0x1) << 11) |
                                 ((instruction >> 21) & 0x3FF), 21)
        return opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_s, imm_b, imm_u, imm_j

    def sign_extend(self, value, bits):
        """Sign-extend an immediate value."""
        mask = 1 << (bits - 1)
        return (value ^ mask) - mask
    

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
