from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section

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