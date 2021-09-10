# Adapted from https://github.com/solana-labs/rbpf/blob/main/src/disassembler.rs

from . import ebpf


def format_off(off):
    if off >= 0:
        return f"+0x{off:x}"
    else:
        return f"-0x{abs(off):x}"


def alu_imm_str(name, insn):
    return f"{name} r{insn.dst}, {insn.imm}"


def alu_reg_str(name, insn):
    return f"{name} r{insn.dst}, r{insn.src}"


def byteswap_str(name, insn):
    return f"{name}{insn.imm} r{insn.dst}"


def ld_st_imm_str(name, insn):
    return f"{name} [r{insn.dst}{format_off(insn.off)}], {insn.imm}"


def ld_reg_str(name, insn):
    return f"{name} r{insn.dst}, [r{insn.src}{format_off(insn.off)}]"


def st_reg_str(name, insn):
    return f"{name} [r{insn.dst}{format_off(insn.off)}], r{insn.src}"


def ldabs_str(name, insn):
    return f"{name} {insn.imm}"


def ldind_str(name, insn):
    return f"{name} r{insn.src}, {insn.imm}"


def jmp_imm_str(name, insn):
    return f"{name} r{insn.dst}, {insn.imm}, NOT_IMPLEMENTED"


def jmp_reg_str(name, insn):
    return f"{name} r{insn.dst}, r{insn.src}, NOT_IMPLEMENTED"


MATCH = {
    ebpf.LD_ABS_B: lambda x: ldabs_str("ldabsb", x),
    ebpf.LD_ABS_H: lambda x: ldabs_str("ldabsh", x),
    ebpf.LD_ABS_W: lambda x: ldabs_str("ldabsw", x),
    ebpf.LD_ABS_DW: lambda x: ldabs_str("ldabsdw", x),
    ebpf.LD_IND_B: lambda x: ldind_str("ldindb", x),
    ebpf.LD_IND_H: lambda x: ldind_str("ldindh", x),
    ebpf.LD_IND_W: lambda x: ldind_str("ldindw", x),
    ebpf.LD_IND_DW: lambda x: ldind_str("ldinddw", x),
    ebpf.LD_DW_IMM: lambda x: "NOT_IMPLEMENTED",
    ebpf.LD_B_REG: lambda x: ld_reg_str("ldxb", x),
    ebpf.LD_H_REG: lambda x: ld_reg_str("ldxh", x),
    ebpf.LD_W_REG: lambda x: ld_reg_str("ldxw", x),
    ebpf.LD_DW_REG: lambda x: ld_reg_str("ldxdw", x),
    ebpf.ST_B_IMM: lambda x: ld_st_imm_str("stb", x),
    ebpf.ST_H_IMM: lambda x: ld_st_imm_str("sth", x),
    ebpf.ST_W_IMM: lambda x: ld_st_imm_str("stw", x),
    ebpf.ST_DW_IMM: lambda x: ld_st_imm_str("stdw", x),
    ebpf.ST_B_REG: lambda x: st_reg_str("stxb", x),
    ebpf.ST_H_REG: lambda x: st_reg_str("stxh", x),
    ebpf.ST_W_REG: lambda x: st_reg_str("stxw", x),
    ebpf.ST_DW_REG: lambda x: st_reg_str("stxdw", x),
    ebpf.ST_W_XADD: lambda x: st_reg_str("stxxaddw", x),
    ebpf.ST_DW_XADD: lambda x: st_reg_str("stxxadddw", x),
    ebpf.ADD32_IMM: lambda x: alu_imm_str("add32", x),
    ebpf.ADD32_REG: lambda x: alu_reg_str("add32", x),
    ebpf.SUB32_IMM: lambda x: alu_imm_str("sub32", x),
    ebpf.SUB32_REG: lambda x: alu_reg_str("sub32", x),
    ebpf.MUL32_IMM: lambda x: alu_imm_str("mul32", x),
    ebpf.MUL32_REG: lambda x: alu_reg_str("mul32", x),
    ebpf.DIV32_IMM: lambda x: alu_imm_str("div32", x),
    ebpf.DIV32_REG: lambda x: alu_reg_str("div32", x),
    ebpf.OR32_IMM: lambda x: alu_imm_str("or32", x),
    ebpf.OR32_REG: lambda x: alu_reg_str("or32", x),
    ebpf.AND32_IMM: lambda x: alu_imm_str("and32", x),
    ebpf.AND32_REG: lambda x: alu_reg_str("and32", x),
    ebpf.LSH32_IMM: lambda x: alu_imm_str("lsh32", x),
    ebpf.LSH32_REG: lambda x: alu_reg_str("lsh32", x),
    ebpf.RSH32_IMM: lambda x: alu_imm_str("rsh32", x),
    ebpf.RSH32_REG: lambda x: alu_reg_str("rsh32", x),
    ebpf.NEG32: lambda x: "NOT_IMPLEMENTED",
    ebpf.MOD32_IMM: lambda x: alu_imm_str("mod32", x),
    ebpf.MOD32_REG: lambda x: alu_reg_str("mod32", x),
    ebpf.XOR32_IMM: lambda x: alu_imm_str("xor32", x),
    ebpf.XOR32_REG: lambda x: alu_reg_str("xor32", x),
    ebpf.MOV32_IMM: lambda x: alu_imm_str("mov32", x),
    ebpf.MOV32_REG: lambda x: alu_reg_str("mov32", x),
    ebpf.ARSH32_IMM: lambda x: alu_imm_str("arsh32", x),
    ebpf.ARSH32_REG: lambda x: alu_reg_str("arsh32", x),
    ebpf.LE: lambda x: byteswap_str("le", x),
    ebpf.BE: lambda x: byteswap_str("be", x),
    ebpf.ADD64_IMM: lambda x: alu_imm_str("add64", x),
    ebpf.ADD64_REG: lambda x: alu_reg_str("add64", x),
    ebpf.SUB64_IMM: lambda x: alu_imm_str("sub64", x),
    ebpf.SUB64_REG: lambda x: alu_reg_str("sub64", x),
    ebpf.MUL64_IMM: lambda x: alu_imm_str("mul64", x),
    ebpf.MUL64_REG: lambda x: alu_reg_str("mul64", x),
    ebpf.DIV64_IMM: lambda x: alu_imm_str("div64", x),
    ebpf.DIV64_REG: lambda x: alu_reg_str("div64", x),
    ebpf.OR64_IMM: lambda x: alu_imm_str("or64", x),
    ebpf.OR64_REG: lambda x: alu_reg_str("or64", x),
    ebpf.AND64_IMM: lambda x: alu_imm_str("and64", x),
    ebpf.AND64_REG: lambda x: alu_reg_str("and64", x),
    ebpf.LSH64_IMM: lambda x: alu_imm_str("lsh64", x),
    ebpf.LSH64_REG: lambda x: alu_reg_str("lsh64", x),
    ebpf.RSH64_IMM: lambda x: alu_imm_str("rsh64", x),
    ebpf.RSH64_REG: lambda x: alu_reg_str("rsh64", x),
    ebpf.NEG64: lambda x: "NOT_IMPLEMENTED",
    ebpf.MOD64_IMM: lambda x: alu_imm_str("mod64", x),
    ebpf.MOD64_REG: lambda x: alu_reg_str("mod64", x),
    ebpf.XOR64_IMM: lambda x: alu_imm_str("xor64", x),
    ebpf.XOR64_REG: lambda x: alu_reg_str("xor64", x),
    ebpf.MOV64_IMM: lambda x: alu_imm_str("mov64", x),
    ebpf.MOV64_REG: lambda x: alu_reg_str("mov64", x),
    ebpf.ARSH64_IMM: lambda x: alu_imm_str("arsh64", x),
    ebpf.ARSH64_REG: lambda x: alu_reg_str("arsh64", x),
    ebpf.JA: lambda x: "NOT_IMPLEMENTED",
    ebpf.JEQ_IMM: lambda x: jmp_imm_str("jeq", x),
    ebpf.JEQ_REG: lambda x: jmp_reg_str("jeq", x),
    ebpf.JGT_IMM: lambda x: jmp_imm_str("jgt", x),
    ebpf.JGT_REG: lambda x: jmp_reg_str("jgt", x),
    ebpf.JGE_IMM: lambda x: jmp_imm_str("jge", x),
    ebpf.JGE_REG: lambda x: jmp_reg_str("jge", x),
    ebpf.JLT_IMM: lambda x: jmp_imm_str("jlt", x),
    ebpf.JLT_REG: lambda x: jmp_reg_str("jlt", x),
    ebpf.JLE_IMM: lambda x: jmp_imm_str("jle", x),
    ebpf.JLE_REG: lambda x: jmp_reg_str("jle", x),
    ebpf.JSET_IMM: lambda x: jmp_imm_str("jset", x),
    ebpf.JSET_REG: lambda x: jmp_reg_str("jset", x),
    ebpf.JNE_IMM: lambda x: jmp_imm_str("jne", x),
    ebpf.JNE_REG: lambda x: jmp_reg_str("jne", x),
    ebpf.JSGT_IMM: lambda x: jmp_imm_str("jsgt", x),
    ebpf.JSGT_REG: lambda x: jmp_reg_str("jsgt", x),
    ebpf.JSGE_IMM: lambda x: jmp_imm_str("jsge", x),
    ebpf.JSGE_REG: lambda x: jmp_reg_str("jsge", x),
    ebpf.JSLT_IMM: lambda x: jmp_imm_str("jslt", x),
    ebpf.JSLT_REG: lambda x: jmp_reg_str("jslt", x),
    ebpf.JSLE_IMM: lambda x: jmp_imm_str("jsle", x),
    ebpf.JSLE_REG: lambda x: jmp_reg_str("jsle", x),
    ebpf.CALL_IMM: lambda x: "NOT_IMPLEMENTED",
    ebpf.CALL_REG: lambda x: "NOT_IMPLEMENTED",
    ebpf.EXIT: lambda x: "NOT_IMPLEMENTED"
}


def disassemble(data):
    insn = ebpf.EBPFInstruction(data)

    return MATCH.get(insn.opc, lambda x: "NOT_IMPLEMENTED")(insn)

