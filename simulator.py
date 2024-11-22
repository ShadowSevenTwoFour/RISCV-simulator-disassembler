

class RV64Simulator:
    def __init__(self, mem_size=1024):
        self.registers = [0] * 32  # general purpose regs (x0-31)
        self.registers[2] = mem_size # setting stack ptr to mem size
        self.pc = 0  # set pc
        self.memory = bytearray(mem_size)  # allocating mem space

    def load_program_binary(self, program, base_address=0):
        """Loads a binary program into the simulator's memory space."""
        for i, byte in enumerate(program):
            self.memory[base_address + i] = byte

    def load_program_assembly(self, assembly, base_address=0):
        """Loads a string-based assembly program into the simulator's memory space."""
        lines = assembly.strip().split("\n")
        for i, line in enumerate(lines):
            # Remove comments and strip whitespace
            line = line.split("#")[0].strip()
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
            "addi": 0x13,
            "add": 0x33,
            "sub": 0x33,
            "ld": 0x03,
            "sd": 0x23,
            "beq": 0x63,
            "jal": 0x6F,
        }
        funct3_map = {
            "addi": 0x0,
            "add": 0x0,
            "sub": 0x0,
            "ld": 0x3,
            "sd": 0x3,
            "beq": 0x0,
        }
        funct7_map = {"add": 0x00, "sub": 0x20}

        if mnemonic == "addi":
            rd, rs1, imm = map(str.strip, operands.split(","))
            rd, rs1, imm = int(rd[1:]), int(rs1[1:]), int(imm)  # Convert to integers
            return (imm & 0xFFF) << 20 | (rs1 & 0x1F) << 15 | (funct3_map[mnemonic] & 0x7) << 12 | (rd & 0x1F) << 7 | opcode_map[mnemonic]
        elif mnemonic in ("add", "sub"):
            rd, rs1, rs2 = map(str.strip, operands.split(","))
            rd, rs1, rs2 = int(rd[1:]), int(rs1[1:]), int(rs2[1:])  # Convert to integers
            return (funct7_map[mnemonic] & 0x7F) << 25 | (rs2 & 0x1F) << 20 | (rs1 & 0x1F) << 15 | (funct3_map[mnemonic] & 0x7) << 12 | (rd & 0x1F) << 7 | opcode_map[mnemonic]
        elif mnemonic == "beq":
            rs1, rs2, offset = map(str.strip, operands.split(","))
            rs1, rs2, offset = int(rs1[1:]), int(rs2[1:]), int(offset)  # Convert to integers
            imm_11 = (offset >> 11) & 0x1
            imm_4_1 = (offset >> 1) & 0xF
            imm_10_5 = (offset >> 5) & 0x3F
            imm_12 = (offset >> 12) & 0x1
            return (imm_12 << 31) | (imm_10_5 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3_map[mnemonic] << 12) | (imm_4_1 << 8) | (imm_11 << 7) | opcode_map[mnemonic]
        else:
            raise NotImplementedError(f"Unsupported instruction: {mnemonic}")


    def dump_registers(self):
        """Prints whatever is stored in all of the regs. """
        print("Registers:") 
        for i in range(32):
            print(f"x{i:02}: {self.registers[i]:#018x}") # 018x to store 18 hex vals --> 0x + (64 bit instruction)


    def fetch(self):
        """Fetch the next instruction."""
        instruction = int.from_bytes(self.memory[self.pc:self.pc + 4], "little")
        self.pc += 4
        return instruction

    def decode(self, instruction):
        """
        Decode a 32-bit instruction.
        
        The format is as:
        | 31-25  | 24-20 | 19-15 | 14-12  | 11-7 |  6-0   |
        | funct7 |  rs2  |  rs1  | funct3 |  rd  | opcode |
        
        """
        opcode = instruction & 0x7F 
        rd = (instruction >> 7) & 0x1F
        funct3 = (instruction >> 12) & 0x7
        rs1 = (instruction >> 15) & 0x1F
        rs2 = (instruction >> 20) & 0x1F
        funct7 = (instruction >> 25) & 0x7F
        imm_i = self.sign_extend(instruction >> 20, 12)
        imm_b = self.sign_extend(((instruction >> 31) << 12) | (((instruction >> 7) & 0x1) << 11) |
                                 (((instruction >> 25) & 0x3F) << 5) | ((instruction >> 8) & 0xF), 13)
        return opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_b

    def sign_extend(self, value, bits):
        """Sign-extend an immediate value in binary."""
        if value & (1 << (bits - 1)):
            value -= 1 << bits
        return value

    def execute(self, opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_b):
        """Execute a decoded instruction. Only implemented basic instructions like add, sub, and branch."""
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

    def run(self, steps=10):
        """Run the simulator."""
        for _ in range(steps):
            instruction = self.fetch()
            opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_b = self.decode(instruction)
            self.execute(opcode, rd, funct3, rs1, rs2, funct7, imm_i, imm_b)
            self.dump_registers()


if __name__ == "__main__":
    assembly_program = """
        # Test Program: Basic Arithmetic and Branching
        addi x1, x0, 10       # Load the value 10 into x1
        addi x2, x0, 20       # Load the value 20 into x2
        sub  x3, x1, x2       # Subtract x2 from x1, store the result in x3
    """

    # Load and run the program
    sim = RV64Simulator()
    sim.load_program_assembly(assembly_program)
    sim.run(steps=6)
