class RV64Simulator:
    def __init__(self, mem_size=1024):
        self.registers = [0] * 32  # General-purpose registers (x0-x31)
        self.registers[2] = mem_size  # Stack pointer set to memory size
        self.pc = 0  # Program counter
        self.memory = bytearray(mem_size)  # Allocated memory

    def load_program_binary(self, program, base_address=0):
        """Load a binary program into the simulator's memory."""
        for i, byte in enumerate(program):
            self.memory[base_address + i] = byte

    def load_program_assembly(self, assembly, base_address=0):
        """Load an assembly program into the simulator's memory."""
        lines = assembly.strip().split("\n")
        for i, line in enumerate(lines):
            line = line.split("#")[0].strip()  # Strip comments
            if not line:  # Skip empty lines
                continue
            try:
                instruction = self.assemble_instruction(line)
                self.memory[base_address + i * 4:base_address + (i + 1) * 4] = instruction.to_bytes(4, "little")
            except NotImplementedError as e:
                print(f"Error parsing line {i + 1}: {line}")
                raise e

    def assemble_instruction(self, instruction):
        """Assemble a RISC-V instruction from a string."""
        parts = instruction.split(maxsplit=1)  # Split the mnemonic and operands
        mnemonic = parts[0].lower()
        operands = parts[1] if len(parts) > 1 else ""

        # Maps for opcode, funct3, and funct7
        opcode_map = {
            "addi": 0x13, "add": 0x33, "sub": 0x33, "andi": 0x13, "ori": 0x13, "xori": 0x13,
            "jal": 0x6F, "jalr": 0x67, "beq": 0x63, "bne": 0x63, "blt": 0x63, "bge": 0x63,
            "ld": 0x03, "lw": 0x03, "lb": 0x03, "lh": 0x03,
            "sd": 0x23, "sw": 0x23, "sh": 0x23, "sb": 0x23,
            "lui": 0x37, "auipc": 0x17
        }
        funct3_map = {
            "addi": 0x0, "andi": 0x7, "ori": 0x6, "xori": 0x4,
            "add": 0x0, "sub": 0x0, "ld": 0x3, "lw": 0x2, "lb": 0x0, "lh": 0x1,
            "sd": 0x3, "sw": 0x2, "sh": 0x1, "sb": 0x0,
            "jalr": 0x0, "beq": 0x0, "bne": 0x1, "blt": 0x4, "bge": 0x5
        }
        funct7_map = {"add": 0x00, "sub": 0x20}

        if mnemonic in ("addi", "andi", "ori", "xori"):
            rd, rs1, imm = map(str.strip, operands.split(","))
            rd, rs1, imm = int(rd[1:]), int(rs1[1:]), int(imm)
            return (imm & 0xFFF) << 20 | (rs1 & 0x1F) << 15 | (funct3_map[mnemonic] & 0x7) << 12 | (rd & 0x1F) << 7 | opcode_map[mnemonic]

        elif mnemonic in ("add", "sub"):
            rd, rs1, rs2 = map(str.strip, operands.split(","))
            rd, rs1, rs2 = int(rd[1:]), int(rs1[1:]), int(rs2[1:])
            return (funct7_map[mnemonic] & 0x7F) << 25 | (rs2 & 0x1F) << 20 | (rs1 & 0x1F) << 15 | (funct3_map[mnemonic] & 0x7) << 12 | (rd & 0x1F) << 7 | opcode_map[mnemonic]

        elif mnemonic in ("ld", "lw", "lb", "lh"):
            rd, offset_base = map(str.strip, operands.split(","))
            rd, offset, rs1 = int(rd[1:]), *map(int, offset_base.strip("()").split("x"))
            return (offset & 0xFFF) << 20 | (rs1 & 0x1F) << 15 | (funct3_map[mnemonic] & 0x7) << 12 | (rd & 0x1F) << 7 | opcode_map[mnemonic]

        elif mnemonic in ("sd", "sw", "sh", "sb"):
            rs2, offset_base = map(str.strip, operands.split(","))
            rs2, offset, rs1 = int(rs2[1:]), *map(int, offset_base.strip("()").split("x"))
            imm_4_0 = offset & 0x1F
            imm_11_5 = (offset >> 5) & 0x7F
            return (imm_11_5 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3_map[mnemonic] & 0x7) << 12 | (imm_4_0 << 7) | opcode_map[mnemonic]

        elif mnemonic == "jal":
            rd, imm = map(str.strip, operands.split(","))
            rd, imm = int(rd[1:]), int(imm)
            imm_20 = (imm >> 20) & 0x1
            imm_10_1 = (imm >> 1) & 0x3FF
            imm_11 = (imm >> 11) & 0x1
            imm_19_12 = (imm >> 12) & 0xFF
            return (imm_20 << 31) | (imm_19_12 << 12) | (imm_11 << 20) | (imm_10_1 << 21) | (rd << 7) | opcode_map[mnemonic]

        elif mnemonic == "jalr":
            rd, rs1, imm = map(str.strip, operands.split(","))
            rd, rs1, imm = int(rd[1:]), int(rs1[1:]), int(imm)
            return (imm & 0xFFF) << 20 | (rs1 & 0x1F) << 15 | (funct3_map[mnemonic] & 0x7) << 12 | (rd & 0x1F) << 7 | opcode_map[mnemonic]

        elif mnemonic in ("beq", "bne", "blt", "bge"):
            rs1, rs2, offset = map(str.strip, operands.split(","))
            rs1, rs2, offset = int(rs1[1:]), int(rs2[1:]), int(offset)
            imm_11 = (offset >> 11) & 0x1
            imm_4_1 = (offset >> 1) & 0xF
            imm_10_5 = (offset >> 5) & 0x3F
            imm_12 = (offset >> 12) & 0x1
            return (imm_12 << 31) | (imm_10_5 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3_map[mnemonic] << 12) | (imm_4_1 << 8) | (imm_11 << 7) | opcode_map[mnemonic]

        elif mnemonic == "lui":
            rd, imm = map(str.strip, operands.split(","))
            rd, imm = int(rd[1:]), int(imm)
            return (imm & 0xFFFFF) << 12 | (rd << 7) | opcode_map[mnemonic]

        elif mnemonic == "auipc":
            rd, imm = map(str.strip, operands.split(","))
            rd, imm = int(rd[1:]), int(imm)
            return (imm & 0xFFFFF) << 12 | (rd << 7) | opcode_map[mnemonic]

        else:
            raise NotImplementedError(f"Unsupported instruction: {mnemonic}")


    def dump_registers(self, dump):
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
        imm_i = self.sign_extend(instruction >> 20, 12)  # Immediate for I-type
        imm_b = self.sign_extend(
            ((instruction >> 31) << 12) |
            (((instruction >> 7) & 0x1) << 11) |
            (((instruction >> 25) & 0x3F) << 5) |
            ((instruction >> 8) & 0xF), 13)  # Immediate for B-type
        imm_u = instruction & 0xFFFFF000  # Immediate for U-type
        imm_j = self.sign_extend(
            ((instruction >> 31) << 20) |
            (((instruction >> 12) & 0xFF) << 12) |
            (((instruction >> 20) & 0x1) << 11) |
            ((instruction >> 21) & 0x3FF), 21)  # Immediate for J-type
        imm_s = self.sign_extend(
            (((instruction >> 25) & 0x7F) << 5) |
            ((instruction >> 7) & 0x1F), 12)  # Immediate for S-type
        return opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_b, imm_u, imm_j, imm_s

    def sign_extend(self, value, bits):
        """Sign-extend an immediate value."""
        if value & (1 << (bits - 1)):
            value -= 1 << bits
        return value

    def execute(self, opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_b, imm_u, imm_j, imm_s):
        """Execute a decoded instruction."""
        if opcode == 0x33:  # R-type
            if funct3 == 0x0:  # ADD/SUB
                if funct7 == 0x00:  # ADD
                    self.registers[rd] = (self.registers[rs1] + self.registers[rs2]) & 0xFFFFFFFFFFFFFFFF
                elif funct7 == 0x20:  # SUB
                    self.registers[rd] = (self.registers[rs1] - self.registers[rs2]) & 0xFFFFFFFFFFFFFFFF

        elif opcode == 0x13:  # I-type
            if funct3 == 0x0:  # ADDI
                self.registers[rd] = (self.registers[rs1] + imm_i) & 0xFFFFFFFFFFFFFFFF

        elif opcode == 0x63:  # B-type
            if funct3 == 0x0 and self.registers[rs1] == self.registers[rs2]:  # BEQ
                self.pc += imm_b - 4

        elif opcode == 0x6F:  # J-type
            self.registers[rd] = self.pc
            self.pc += imm_j - 4

        elif opcode == 0x67:  # JALR
            self.registers[rd] = self.pc
            self.pc = (self.registers[rs1] + imm_i) & ~1

        elif opcode == 0x03:  # Load
            address = self.registers[rs1] + imm_i
            if funct3 == 0x3:  # LD
                self.registers[rd] = int.from_bytes(self.memory[address:address + 8], "little")

        elif opcode == 0x23:  # Store
            address = self.registers[rs1] + imm_s
            if funct3 == 0x3:  # SD
                self.memory[address:address + 8] = self.registers[rs2].to_bytes(8, "little")

    def run(self, steps=10, dump=32):
        """Run the simulator."""
        for step in range(steps):
            print(f"Step {step}")
            instruction = self.fetch()
            opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_b, imm_u, imm_j, imm_s = self.decode(instruction)
            self.execute(opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_b, imm_u, imm_j, imm_s)
            self.dump_registers(dump)


if __name__ == "__main__":
    # Assembly program example
    assembly_program = """
        addi x1, x0, 10       # Load the value 10 into x1
        addi x2, x0, 20       # Load the value 20 into x2
        add  x3, x1, x2       # Add x1 and x2 into x3
        beq  x3, x2, 8        # Branch if x3 == x2
        addi x4, x0, 40       # Load 40 into x4
        sub  x5, x3, x1       # Subtract x1 from x3 into x5
    """
    sim = RV64Simulator()
    sim.load_program_assembly(assembly_program)
    sim.run(steps=7, dump=6)
