#!/usr/bin/env python3
"""
Minimal RISC-V RV64I simulator that:
 - Initializes registers from Table 5 (photos).
 - Initializes memory from Table 6 (photos).
   * Some entries are textual instructions (e.g. 'add x0, x12, x14')
   * Others are 32-bit hex (e.g. '0xFFD1AE23').
 - Decodes each line accordingly and executes.
 - Traces until we reach 0x00000000000300C8 or run out of recognized instructions.
"""

import sys

# ------------------------------------------------------------------------------
# 1) Define initial registers from Table 5
#    Replace these placeholders with the exact values from your "Table 5" photo.
# ------------------------------------------------------------------------------
# For example, from your screenshot:
#   x0 = 0x0000_0000_0000_0000
#   x1 = 0x0000_0000_0000_0000
#   x2 = 0x0000_00??_????_????
#   ...
#   x30= 0x????
#   x31= 0x????
# etc.
# Make sure to use the EXACT hex from your Table 5.

initial_regs_hex = {
    0: "0x0000000000000000",
    1: "0x000000000000F0B0",
    2: "0x0000003EFF008000",
    3: "0x0000002E00400018",
    4: "0x00000000003DBB30",
    5: "0x000000000000001F",
    6: "0x000000000000003F",
    7: "0x0000002E00400000",
    8: "0x0000002E00400038",
    9: "0x0000002E00400020",
    10: "0xA45198CCDA458000",
    11: "0x5022A875966DFF04",
    12: "0x0000000133F000A0",
    13: "0x00000000000000F0",
    14: "0x0000000040108200",
    15: "0x033F00AF0000E523",
    16: "0x007736706C4A8054",
    17: "0xE980675D8AEE99C0",
    18: "0xBA8877514322C3AD",
    19: "0xFFFFFFA060008720",
    20: "0xFFA000008000A000",
    21: "0xFFFFFFFFFFFFA100",
    22: "0xFFFFD800AE800000",
    23: "0x0000000000200A00",
    24: "0x0000000002000F10",
    25: "0xFFFFE80ED800A900",
    26: "0xFFFF40003200E000",
    27: "0x00000000000300A0",
    28: "0x0000000133F0A000",
    29: "0x0000000000000000",
    30: "0x000000000000000A",
    31: "0x00000000000010A0",
}

# We'll store them in a Python list `regs[0..31]` as 64-bit integers.
regs = [0]*32
for r, hexval in initial_regs_hex.items():
    regs[r] = int(hexval, 16) & 0xFFFFFFFFFFFFFFFF

# Initialize memory directly with merged dictionaries
memory = {
    # table6_main
    0x0000000000030098: "0x01FF0EB3",       # raw hex
    0x000000000003009C: "0xFFD1AE23",       # raw hex
    0x00000000000300A0: "add x0, x12, x14", # textual
    0x00000000000300A4: "sll x12, x12, x5",
    0x00000000000300A8: "bge x12, x15, GE",
    0x00000000000300AC: "jalr x1, 0(x3)",
    0x00000000000300B0: "xor x14, x3, x14",
    0x00000000000300B4: "jalr x1, 12(x3)",
    0x00000000000300B8: "srai x14, x12, 8",
    0x00000000000300BC: "sra x18, x18, x5",
    0x00000000000300C0: "lb x19, -6(x3)",
    0x00000000000300C4: "0xFF31BC23",       # raw hex
    0x00000000000300C8: "nop",
    0x00000000000300CC: "nop",
    0x00000000000300D0: "nop",
    0x00000000000300D4: "add x0, x0, x0",
    
    # table6_sub
    0x0000002E00400000: "0x4202D613",
    0x0000002E00400004: "0xFE060613",
    0x0000002E00400008: "0xFD870713",
    0x0000002E0040000C: "0x0040006F",
    0x0000002E00400010: "0x0083CC00",
    0x0000002E00400014: "0x00000000",
    0x0000002E00400018: "0xFF918603",
    0x0000002E0040001C: "0x00D67633",
    0x0000002E00400020: "0x00C18F23",
    0x0000002E00400024: "0x0181A603",
    0x0000002E00400028: "0x00C74633",
    0x0000002E0040002C: "0x00C1AC23",
    0x0000002E00400030: "0x404205B3",
    0x0000002E00400034: "0x00008067",
    0x0000002E00400038: "0x000080E7",
    0x0000002E0040003C: "0xFF8080E7",
}

# ------------------------------------------------------------------------------
# 3) Utility: sign extension, get/set reg, etc.
# ------------------------------------------------------------------------------
def sign_extend(val, bits=32):
    """Sign extend a value from specified bit width to 64 bits using 2's complement"""
    mask = (1 << bits) - 1
    val &= mask
    sign_bit = 1 << (bits - 1)
    if val & sign_bit:
        val = val - (1 << bits)
    return val & 0xFFFFFFFFFFFFFFFF

def get_reg(r):
    if r == 0:
        return 0
    return regs[r]

def set_reg(r, val):
    if r == 0:
        return
    regs[r] = val & 0xFFFFFFFFFFFFFFFF

# ------------------------------------------------------------------------------
# 4) Parsing textual instructions vs. hex instructions
# ------------------------------------------------------------------------------
def parse_textual_instruction(instr_str):
    """
    If 'instr_str' is something like "add x0, x12, x14",
    parse it and return a canonical tuple, e.g. ('ADD', rd=0, rs1=12, rs2=14).

    If 'instr_str' is something like 'nop', handle that, etc.
    We'll do minimal coverage for the instructions we see in Table 6.
    """
    # Quick tokenize:
    tokens = instr_str.replace(",", " ").split()
    # e.g. ["add", "x0", "x12", "x14"]
    op = tokens[0].lower()

    def regnum(x):
        # x is "x0" or "x14"
        return int(x[1:])

    if op == "add":
        # add x0, x12, x14
        rd = regnum(tokens[1])
        rs1= regnum(tokens[2])
        rs2= regnum(tokens[3])
        return ("ADD", rd, rs1, rs2)
    elif op == "sw":
        # sw x29, -4(x3)
        # tokens = ["sw","x29","-4(x3)"]
        rs2 = regnum(tokens[1])
        # parse "-4(x3)"
        offset, paren = tokens[2].split("(")
        offset = int(offset,0)
        base = regnum(paren[:-1]) # remove ")"
        return ("SW", base, rs2, offset)
    elif op == "lb":
        # lb x19, -6(x3)
        rd = regnum(tokens[1])
        offset_paren = tokens[2]
        off, paren = offset_paren.split("(")
        off = int(off,0)
        base = regnum(paren[:-1])
        return ("LB", rd, base, off)
    elif op == "sll":
        # sll x12, x12, x5
        rd = regnum(tokens[1])
        rs1= regnum(tokens[2])
        rs2= regnum(tokens[3])
        return ("SLL", rd, rs1, rs2)
    elif op == "bge":
        # bge x12, x15, GE
        # We can't parse the label offset easily here. We'll do a partial approach:
        rs1 = regnum(tokens[1])
        rs2 = regnum(tokens[2])
        # We'll store the label in the 4th field for now, the executor can fix it
        label = tokens[3]  # "GE"
        return ("BGE_LABEL", rs1, rs2, label)
    elif op == "jalr":
        # jalr x1, 0(x3)
        rd = regnum(tokens[1])
        offset_paren = tokens[2]
        off, paren = offset_paren.split("(")
        off = int(off,0)
        base = regnum(paren[:-1])
        return ("JALR", rd, base, off)
    elif op == "xor":
        # xor x14, x3, x14
        rd = regnum(tokens[1])
        rs1= regnum(tokens[2])
        rs2= regnum(tokens[3])
        return ("XOR", rd, rs1, rs2)
    elif op == "srai":
        # srai x14, x12, 8
        rd = regnum(tokens[1])
        rs1= regnum(tokens[2])
        shamt= int(tokens[3],0)
        return ("SRAI", rd, rs1, shamt)
    elif op == "sra":
        # sra x18, x18, x5
        rd = regnum(tokens[1])
        rs1= regnum(tokens[2])
        rs2= regnum(tokens[3])
        return ("SRA", rd, rs1, rs2)
    elif op == "nop":
        return ("NOP",)
    elif op == "add" and len(tokens)==4 and tokens[1]=="x0":
        # e.g. "add x0, x0, x0"
        rd = regnum(tokens[1])
        rs1= regnum(tokens[2])
        rs2= regnum(tokens[3])
        return ("ADD", rd, rs1, rs2)
    else:
        return ("UNIMPLEMENTED_TEXT", instr_str)

def parse_hex_instruction(hex_str):
    """
    Convert hex_str (e.g. '0xFFD1AE23') to an int,
    then decode partially (like we did in previous script).
    We'll handle only the known patterns from Table 6.
    """
    val = int(hex_str, 16) & 0xFFFFFFFF
    
    opcode = val & 0x7F
    rd     = (val >> 7) & 0x1F
    funct3 = (val >> 12) & 0x7
    rs1    = (val >> 15) & 0x1F
    rs2    = (val >> 20) & 0x1F
    funct7 = (val >> 25) & 0x7F

    # We'll do a small subset:
    if opcode==0x33 and funct3==0x0 and funct7==0x00:
        # add
        return ("ADD", rd, rs1, rs2)
    elif opcode==0x33 and funct3==0x0 and funct7==0x40:
        # sub
        return ("SUB", rd, rs1, rs2)
    elif opcode==0x33 and funct3==0x4 and funct7==0x00:
        # xor
        return ("XOR", rd, rs1, rs2)
    elif opcode==0x33 and funct3==0x1 and funct7==0x00:
        # sll
        return ("SLL", rd, rs1, rs2)
    elif opcode==0x33 and funct3==0x5 and funct7==0x00:
        # srl
        return ("SRL", rd, rs1, rs2)
    elif opcode==0x33 and funct3==0x5 and funct7==0x20:
        # sra
        return ("SRA", rd, rs1, rs2)
    elif opcode==0x33 and funct3==0x7 and funct7==0x00:
        # and
        return ("AND", rd, rs1, rs2)
    elif opcode==0x33 and funct3==0x6 and funct7==0x00:
        # or
        return ("OR", rd, rs1, rs2)
    elif opcode==0x23 and funct3==0x2:
        # sw
        # S-type immediate
        imm_s  = sign_extend(((val >> 25) << 5) | ((val >> 7) & 0x1F), 12)
        return ("SW", rs1, rs2, imm_s)
    elif opcode==0x23 and funct3==0x7 or (opcode==0x23 and funct3==0x3):
        # sd - support both standard (0x7) and non-standard (0x3) encodings
        # S-type immediate
        imm_s  = sign_extend(((val >> 25) << 5) | ((val >> 7) & 0x1F), 12)
        return ("SD", rs1, rs2, imm_s)
    elif opcode==0x23 and funct3==0x0:
        # sb - Add this case for store byte
        # S-type immediate
        imm_s  = sign_extend(((val >> 25) << 5) | ((val >> 7) & 0x1F), 12)
        return ("SB", rs1, rs2, imm_s)
    elif opcode==0x67 and funct3==0x0:
        # jalr
        # I-type immediate
        imm_i = sign_extend(val >> 20, 12)
        return ("JALR", rd, rs1, imm_i)
    elif opcode==0x03 and funct3==0x0:
        # lb
        # I-type immediate
        imm_i = sign_extend(val >> 20, 12)
        return ("LB", rd, rs1, imm_i)
    elif opcode==0x03 and funct3==0x3:
        # ld
        # I-type immediate
        imm_i = sign_extend(val >> 20, 12)
        return ("LD", rd, rs1, imm_i)
    elif opcode==0x03 and funct3==0x2:
        # lw
        # I-type immediate
        imm_i = sign_extend(val >> 20, 12)
        return ("LW", rd, rs1, imm_i)
    elif opcode==0x13 and funct3==0x0:
        # addi
        # I-type immediate
        imm_i = sign_extend(val >> 20, 12)
        return ("ADDI", rd, rs1, imm_i)
    elif opcode==0x13 and funct3==0x7:
        # andi
        # I-type immediate
        imm_i = sign_extend(val >> 20, 12)
        return ("ANDI", rd, rs1, imm_i)
    elif opcode==0x13 and funct3==0x1:
        # slli
        # I-type immediate, but only bottom 6 bits used as shift amount
        shamt = (val >> 20) & 0x3F
        return ("SLLI", rd, rs1, shamt)
    elif opcode==0x13 and funct3==0x5 and ((val >> 20) & 0xFE0) == 0x000:
        # srli
        # I-type immediate, but only bottom 6 bits used as shift amount
        shamt = (val >> 20) & 0x3F
        return ("SRLI", rd, rs1, shamt)
    elif opcode==0x13 and funct3==0x5 and ((val >> 20) & 0xFE0) == 0x400:
        # srai
        # I-type immediate, but only bottom 6 bits used as shift amount
        shamt = (val >> 20) & 0x3F
        return ("SRAI", rd, rs1, shamt)
    elif opcode==0x1B and funct3==0x0:
        # addiw
        # I-type immediate
        imm_i = sign_extend(val >> 20, 12)
        return ("ADDIW", rd, rs1, imm_i)
    elif opcode==0x3B and funct3==0x0 and funct7==0x00:
        # addw
        return ("ADDW", rd, rs1, rs2)
    elif opcode==0x3B and funct3==0x0 and funct7==0x20:
        # subw
        return ("SUBW", rd, rs1, rs2)

    return ("UNIMPLEMENTED_HEX", val)

def decode_any(addr, item):
    """
    If 'item' is a string starting with '0x' => parse_hex_instruction
    Else => parse_textual_instruction
    Returns a tuple describing the instruction.
    """
    if isinstance(item, tuple):
        # Already decoded
        return item
        
    s = item.strip()
    if s.lower().startswith("0x"):
        return parse_hex_instruction(s)
    else:
        return parse_textual_instruction(s)

# ------------------------------------------------------------------------------
# 5) Executor
# ------------------------------------------------------------------------------
def pc_relative_label_to_addr(pc, label):
    """
    We only have one label: 'GE' => 0x00000000000300B4
    or 'ST' => 0x00000000000300AC, etc. We can store them in a dict if needed.
    """
    label_map = {
        "GE": 0x00000000000300B4,
        "ST": 0x00000000000300AC,
    }
    if label in label_map:
        return label_map[label]
    else:
        # unknown label => do nothing
        return pc+4

def execute(instr, pc):
    """
    Execute a single RISC-V instruction and return the next program counter
    
    Args:
        instr: Tuple containing the instruction and its operands
        pc: Current program counter
        
    Returns:
        Next program counter value
    """
    op = instr[0]
    next_pc = pc+4

    if op=="ADD":
        _, rd, rs1, rs2 = instr
        set_reg(rd, get_reg(rs1)+get_reg(rs2))

    elif op=="SUB":
        _, rd, rs1, rs2 = instr
        set_reg(rd, get_reg(rs1)-get_reg(rs2))

    elif op=="SW":
        # SW, S-type => (base, rs2, imm)
        _, base, rs2, imm = instr
        addr = (get_reg(base)+imm) & 0xFFFFFFFFFFFFFFFF
        data_32 = get_reg(rs2)&0xFFFFFFFF
        # Store as 2's complement representation
        memory[addr] = f"0x{data_32:08X}"  # store as a hex string

    elif op=="SD":
        # SD, S-type => (base, rs2, imm)
        _, base, rs2, imm = instr
        addr = (get_reg(base)+imm) & 0xFFFFFFFFFFFFFFFF
        data_64 = get_reg(rs2)
        # Store as 2's complement representation
        memory[addr] = f"0x{data_64:016X}"  # store as a hex string

    elif op=="SB":
        # SB, S-type => (base, rs2, imm)
        _, base, rs2, imm = instr
        addr = (get_reg(base)+imm) & 0xFFFFFFFFFFFFFFFF
        data_8 = get_reg(rs2) & 0xFF  # Take only the least significant byte
        
        # For SB, we need to check if we have existing data at the word-aligned address
        word_addr = addr & ~0x3  # Align to word boundary
        byte_offset = addr & 0x3  # Get byte position within word (0-3)
        
        if word_addr in memory:
            # Get existing word
            val_s = memory[word_addr]
            if val_s.lower().startswith("0x"):
                existing_word = int(val_s, 16)
                # Clear the byte position
                mask = ~(0xFF << (byte_offset * 8))
                existing_word &= mask
                # Insert the new byte
                existing_word |= (data_8 << (byte_offset * 8))
                # Store the updated word
                memory[word_addr] = f"0x{existing_word:08X}"
            else:
                # If memory location has textual content, just overwrite it
                memory[addr] = f"0x{data_8:02X}"
        else:
            # If no existing memory at that location, create a new word
            memory[word_addr] = f"0x{data_8 << (byte_offset * 8):08X}"

    elif op=="LB":
        # LB => (rd, base, imm)
        _, rd, base, imm = instr
        addr = (get_reg(base)+imm) & 0xFFFFFFFFFFFFFFFF
        # Calculate the word-aligned address and byte offset
        word_addr = addr & ~0x3  # Align to word boundary
        byte_offset = addr & 0x3  # Get byte position within word (0-3)
        
        # read the word if available, or 0 if none
        if word_addr in memory:
            val_s = memory[word_addr]
            if val_s.lower().startswith("0x"):
                raw = int(val_s,16)
                # Extract the specific byte from the word (each byte is 8 bits)
                shift_amount = byte_offset * 8
                rawbyte = (raw >> shift_amount) & 0xFF
                # sign extend from 8 to 64 bits
                if rawbyte & 0x80:
                    rawbyte = rawbyte | 0xFFFFFFFFFFFFFF00
                set_reg(rd, rawbyte)
            else:
                # textual => treat as 0
                set_reg(rd, 0)
        else:
            # no data => 0
            set_reg(rd, 0)

    elif op=="LD":
        # LD => (rd, base, imm)
        _, rd, base, imm = instr
        addr = (get_reg(base)+imm) & 0xFFFFFFFFFFFFFFFF
        if addr in memory:
            val_s = memory[addr]
            if val_s.lower().startswith("0x"):
                raw = int(val_s,16)
                # Load full 64-bit value with 2's complement representation
                set_reg(rd, raw & 0xFFFFFFFFFFFFFFFF)
            else:
                set_reg(rd, 0)
        else:
            set_reg(rd, 0)

    elif op=="LW":
        # LW => (rd, base, imm)
        _, rd, base, imm = instr
        addr = (get_reg(base)+imm) & 0xFFFFFFFFFFFFFFFF
        if addr in memory:
            val_s = memory[addr]
            if val_s.lower().startswith("0x"):
                raw = int(val_s,16)
                # In 2's complement format, we take the lower 32 bits of the value
                raw32 = raw & 0xFFFFFFFF
                # Sign-extend from 32 to 64 bits using 2's complement
                if raw32 & 0x80000000:
                    raw32 = raw32 | 0xFFFFFFFF00000000
                set_reg(rd, raw32)
            else:
                set_reg(rd, 0)
        else:
            set_reg(rd, 0)

    elif op=="ADDI":
        # ADDI => (rd, rs1, imm)
        _, rd, rs1, imm = instr
        set_reg(rd, (get_reg(rs1) + imm) & 0xFFFFFFFFFFFFFFFF)

    elif op=="ANDI":
        # ANDI => (rd, rs1, imm)
        _, rd, rs1, imm = instr
        set_reg(rd, get_reg(rs1) & imm)

    elif op=="SLLI":
        # SLLI => (rd, rs1, shamt)
        _, rd, rs1, shamt = instr
        set_reg(rd, (get_reg(rs1) << shamt) & 0xFFFFFFFFFFFFFFFF)

    elif op=="SRLI":
        # SRLI => (rd, rs1, shamt)
        _, rd, rs1, shamt = instr
        set_reg(rd, (get_reg(rs1) >> shamt) & 0xFFFFFFFFFFFFFFFF)

    elif op=="ADDIW":
        # ADDIW => (rd, rs1, imm)
        _, rd, rs1, imm = instr
        result = (get_reg(rs1) + imm) & 0xFFFFFFFF
        # Sign extend from 32 to 64 bits using 2's complement
        if result & 0x80000000:
            result = result | 0xFFFFFFFF00000000
        set_reg(rd, result)

    elif op=="ADDW":
        # ADDW => (rd, rs1, rs2)
        _, rd, rs1, rs2 = instr
        result = (get_reg(rs1) + get_reg(rs2)) & 0xFFFFFFFF
        # Sign extend from 32 to 64 bits using 2's complement
        if result & 0x80000000:
            result = result | 0xFFFFFFFF00000000
        set_reg(rd, result)

    elif op=="SUBW":
        # SUBW => (rd, rs1, rs2)
        _, rd, rs1, rs2 = instr
        result = (get_reg(rs1) - get_reg(rs2)) & 0xFFFFFFFF
        # Sign extend from 32 to 64 bits using 2's complement
        if result & 0x80000000:
            result = result | 0xFFFFFFFF00000000
        set_reg(rd, result)

    elif op=="SLL":
        _, rd, rs1, rs2 = instr
        shamt = get_reg(rs2)&0x3F
        set_reg(rd, get_reg(rs1)<<shamt)

    elif op=="SRL":
        _, rd, rs1, rs2 = instr
        shamt = get_reg(rs2)&0x3F
        set_reg(rd, (get_reg(rs1) >> shamt) & 0xFFFFFFFFFFFFFFFF)

    elif op=="BGE_LABEL":
        # bge x12, x15, GE
        _, rs1, rs2, label = instr
        val1 = get_reg(rs1)
        val2 = get_reg(rs2)
        # Interpret as signed values in 2's complement
        if val1 & (1<<63):  # Negative
            val1_signed = val1 - (1<<64)
        else:
            val1_signed = val1
            
        if val2 & (1<<63):  # Negative
            val2_signed = val2 - (1<<64)
        else:
            val2_signed = val2
            
        if val1_signed >= val2_signed:
            next_pc = pc_relative_label_to_addr(pc, label)

    elif op=="JALR":
        # jalr x1, 0(x3)
        _, rd, base, imm = instr
        ra = pc+4
        set_reg(rd, ra)
        target = (get_reg(base)+imm)&0xFFFFFFFFFFFFFFFE
        next_pc = target

    elif op=="XOR":
        _, rd, rs1, rs2 = instr
        set_reg(rd, get_reg(rs1)^get_reg(rs2))

    elif op=="AND":
        _, rd, rs1, rs2 = instr
        set_reg(rd, get_reg(rs1)&get_reg(rs2))

    elif op=="OR":
        _, rd, rs1, rs2 = instr
        set_reg(rd, get_reg(rs1)|get_reg(rs2))

    elif op=="SRAI":
        # SRAI => (rd, rs1, shamt)
        _, rd, rs1, shamt = instr
        val = get_reg(rs1)
        # Arithmetic right shift with 2's complement
        if val & (1<<63):  # If negative
            # Ensure sign extension during shift
            shifted = (val >> shamt) | (~0 << (64 - shamt))
        else:
            shifted = val >> shamt
        set_reg(rd, shifted & 0xFFFFFFFFFFFFFFFF)

    elif op=="SRA":
        # SRA => (rd, rs1, rs2)
        _, rd, rs1, rs2 = instr
        shamt = get_reg(rs2) & 0x3F
        val = get_reg(rs1)
        # Arithmetic right shift with 2's complement
        if val & (1<<63):  # If negative
            # Ensure sign extension during shift
            shifted = (val >> shamt) | (~0 << (64 - shamt))
        else:
            shifted = val >> shamt
        set_reg(rd, shifted & 0xFFFFFFFFFFFFFFFF)

    elif op=="NOP":
        pass

    elif op=="UNIMPLEMENTED_TEXT":
        print(f"[Warning] Unimplemented textual instruction: {instr[1]}")
    elif op=="UNIMPLEMENTED_HEX":
        print(f"[Warning] Unimplemented hex instruction: 0x{instr[1]:08X}")
    else:
        print(f"[Warning] Unknown op: {op}")

    return next_pc

def format_immediate(imm):
    """
    Format immediate values correctly with 2's complement representation
    
    Args:
        imm: Immediate value to format
        
    Returns:
        String representation of the immediate value
    """
    # For negative values like -4, -8, etc., just return the value as-is
    if imm < 0:
        return str(imm)
    # Check if this is actually a 12-bit negative value represented as a large positive
    if imm > 0xFFFFFFFFFFFFF000:  # Likely a negative 12-bit immediate
        return str(imm - 0x10000000000000000)
    return str(imm)

def format_instruction(instr):
    """
    Format instruction in a readable way with 2's complement for immediates
    
    Args:
        instr: Tuple containing the instruction and its operands
        
    Returns:
        Formatted string representation of the instruction
    """
    op = instr[0]
    
    if op == "ADD" or op == "SUB" or op == "XOR" or op == "AND" or op == "OR" or op == "SLL" or op == "SRL" or op == "SRA":
        rd, rs1, rs2 = instr[1], instr[2], instr[3]
        return f"{op} x{rd}, x{rs1}, x{rs2}"
    elif op == "SW" or op == "SD" or op == "SB":
        base, rs2, imm = instr[1], instr[2], instr[3]
        # Fix very large immediates that are actually small negatives
        if imm > 0xFFFFFFFFFFFFF000:  # Likely a negative 12-bit immediate
            imm = imm - 0x10000000000000000
        return f"{op} x{rs2}, {format_immediate(imm)}(x{base})"
    elif op == "LB" or op == "LD" or op == "LW":
        rd, base, imm = instr[1], instr[2], instr[3]
        # Fix very large immediates that are actually small negatives
        if imm > 0xFFFFFFFFFFFFF000:  # Likely a negative 12-bit immediate
            imm = imm - 0x10000000000000000
        return f"{op} x{rd}, {format_immediate(imm)}(x{base})"
    elif op == "ADDI" or op == "ANDI" or op == "SLLI" or op == "SRLI" or op == "SRAI" or op == "ADDIW":
        rd, rs1, imm = instr[1], instr[2], instr[3]
        return f"{op} x{rd}, x{rs1}, {format_immediate(imm)}"
    elif op == "JALR":
        rd, base, imm = instr[1], instr[2], instr[3]
        # Fix very large immediates that are actually small negatives
        if imm > 0xFFFFFFFFFFFFF000:  # Likely a negative 12-bit immediate
            imm = imm - 0x10000000000000000
        return f"{op} x{rd}, {format_immediate(imm)}(x{base})"
    elif op == "BGE_LABEL":
        rs1, rs2, label = instr[1], instr[2], instr[3]
        return f"BGE x{rs1}, x{rs2}, {label}"
    elif op.startswith("UNIMPLEMENTED"):
        return f"UNIMPLEMENTED: {instr[1]}"
    else:
        return str(instr)

# ------------------------------------------------------------------------------
# 6) Simulation main loop
# ------------------------------------------------------------------------------
def run_sim():
    """
    Run the RISC-V simulator - main simulation loop that executes instructions
    and displays results until reaching endpoint or an error
    """
    pc = 0x0000000000030098
    instr_count = 0
    max_instrs = 1000  # Safety limit to prevent infinite loops
    
    # Track potential cycles
    cycle_detection = {}
    
    print("RISC-V Simulator - Execution Log")
    print("-" * 60)
    
    while instr_count < max_instrs:
        instr_count += 1
        
        if pc==0x00000000000300C8:
            print("\nSimulation complete: reached endpoint at 0x00000000000300C8.")
            break
        
        # Check for cycles - more general approach
        if pc in cycle_detection:
            cycle_detection[pc] += 1
            # If we've seen this PC more than 10 times, it's likely an infinite loop
            if cycle_detection[pc] > 10:
                print(f"\n[Warning] Detected cycle at PC=0x{pc:016X}, halting simulation")
                # We could implement a more complex decision tree here, but for simplicity
                # let's just break out of potentially infinite loops
                break
        else:
            cycle_detection[pc] = 1

        if pc not in memory:
            print(f"\nSimulation halted: No instruction at address 0x{pc:016X}")
            break

        # Take a snapshot of memory before execution for comparison
        mem_snapshot = memory.copy()
        
        item = memory[pc]
        instr = decode_any(pc, item)
        
        old_regs = regs[:]
        new_pc = execute(instr, pc)

        # Find memory updates
        mem_updates = {}
        for addr in memory:
            if addr not in mem_snapshot or memory[addr] != mem_snapshot[addr]:
                mem_updates[addr] = memory[addr]

        # Build a string for updated registers
        reg_updates = []
        for r in range(32):
            if regs[r]!=old_regs[r]:
                reg_updates.append(f"x{r}=0x{regs[r]:016X}")
        
        # Format the instruction and its details
        instr_text = item if isinstance(item, str) else ""
            
        # Print in a cleaner format
        print(f"\nInstruction {instr_count}:")
        print(f"  PC: 0x{pc:016X}")
        
        # Format the instruction
        formatted_instr = format_instruction(instr)
        print(f"  Instruction: {formatted_instr}")
            
        # Print hex instruction if available
        if instr_text and instr_text.startswith("0x"):
            print(f"  Raw: {instr_text}")
        
        # Print register updates
        if reg_updates:
            print("  Register updates:")
            for update in reg_updates:
                print(f"    {update}")
        else:
            print("  No register updates")
            
        # Print memory updates
        if mem_updates:
            print("  Memory updates:")
            for addr, value in mem_updates.items():
                if isinstance(value, str) and value.startswith("0x"):
                    try:
                        value_int = int(value, 16)
                        if instr[0] == "SW":
                            print(f"    MEM[0x{addr:016X}] = 0x{value_int:08X} (32-bit)")
                        elif instr[0] == "SD":
                            print(f"    MEM[0x{addr:016X}] = 0x{value_int:016X} (64-bit)")
                        elif instr[0] == "SB":
                            print(f"    MEM[0x{addr:016X}] = 0x{value_int:08X} (8-bit)")
                        else:
                            print(f"    MEM[0x{addr:016X}] = 0x{value_int:X}")
                    except ValueError:
                        print(f"    MEM[0x{addr:016X}] = {value}")
                else:
                    print(f"    MEM[0x{addr:016X}] = {value}")
        else:
            print("  No memory updates")

        if new_pc==pc:
            print("\n[ERROR] PC didn't change => infinite loop, simulation halted.")
            break
            
        # Check for jumps back to main program in a general way
        if new_pc < pc and abs(new_pc - pc) > 0x1000:  # Large backward jump
            print(f"  Detected jump back to PC=0x{new_pc:016X}")
        
        pc = new_pc

# ------------------------------------------------------------------------------
# 7) Entry point
# ------------------------------------------------------------------------------
if __name__=="__main__":
    run_sim()