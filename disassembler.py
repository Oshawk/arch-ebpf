# Adapted from https://github.com/solana-labs/rbpf/blob/main/src/disassembler.rs

from struct import pack, unpack

from binaryninja.enums import InstructionTextTokenType
from binaryninja.function import InstructionTextToken

from . import ebpf


def do_off(off):
    if off <= -16:
        return (
            InstructionTextToken(InstructionTextTokenType.TextToken, "-"),
            InstructionTextToken(InstructionTextTokenType.IntegerToken, f"{-off:#x}")
        )
    elif off < 0:
        return (
            InstructionTextToken(InstructionTextTokenType.TextToken, "-"),
            InstructionTextToken(InstructionTextTokenType.IntegerToken, f"{-off}")
        )
    elif off == 0:
        return tuple()
    elif off < 16:
        return (
            InstructionTextToken(InstructionTextTokenType.TextToken, "+"),
            InstructionTextToken(InstructionTextTokenType.IntegerToken, f"{off}")
        )
    else:
        return (
            InstructionTextToken(InstructionTextTokenType.TextToken, "+"),
            InstructionTextToken(InstructionTextTokenType.IntegerToken, f"{off:#x}")
        )


def do_imm(imm):
    if abs(imm) < 16:
        return InstructionTextToken(InstructionTextTokenType.IntegerToken, f"{imm}"),
    else:
        return InstructionTextToken(InstructionTextTokenType.IntegerToken, f"{imm:#x}"),


def alu_imm(name, insn):
    return [
        InstructionTextToken(InstructionTextTokenType.InstructionToken, name),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, f"r{insn.dst}"),
        InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        *do_imm(insn.imm)
    ]


def alu_reg(name, insn):
    return [
        InstructionTextToken(InstructionTextTokenType.InstructionToken, name),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, f"r{insn.dst}"),
        InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, f"r{insn.src}")
    ]


def neg(name, insn):
    return [
        InstructionTextToken(InstructionTextTokenType.InstructionToken, name),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, f"r{insn.dst}"),
    ]

def byteswap(name, insn):
    return [
        InstructionTextToken(InstructionTextTokenType.InstructionToken, f"{name}{insn.imm}"),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, f"r{insn.dst}"),
    ]


def ld_st_imm(name, insn):
    return [
        InstructionTextToken(InstructionTextTokenType.InstructionToken, name),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "["),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, f"r{insn.dst}"),
        *do_off(insn.off),
        InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, "]"),
        InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        *do_imm(insn.imm)
    ]


def ld_reg(name, insn):
    return [
        InstructionTextToken(InstructionTextTokenType.InstructionToken, name),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, f"r{insn.dst}"),
        InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "["),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, f"r{insn.src}"),
        *do_off(insn.off),
        InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, "]")
    ]


def st_reg(name, insn):
    return [
        InstructionTextToken(InstructionTextTokenType.InstructionToken, name),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, "["),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, f"r{insn.dst}"),
        *do_off(insn.off),
        InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, "]"),
        InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, f"r{insn.src}")
    ]


def ldabs(name, insn):
    return [
        InstructionTextToken(InstructionTextTokenType.InstructionToken, name),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        *do_imm(*unpack("<I", pack("<i", insn.imm)))  # imm is unsigned in this context
    ]


def ldind(name, insn):
    return [
        InstructionTextToken(InstructionTextTokenType.InstructionToken, name),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, f"r{insn.src}"),
        InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        *do_imm(*unpack("<I", pack("<i", insn.imm)))  # imm is unsigned in this context
    ]


def jmp(name, insn):
    return [
        InstructionTextToken(InstructionTextTokenType.InstructionToken, name),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, f"{insn.ptr + insn.off + 8:#x}")
    ]


def jmp_imm(name, insn):
    return [
        InstructionTextToken(InstructionTextTokenType.InstructionToken, name),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, f"r{insn.dst}"),
        InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        *do_imm(insn.imm),
        InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, f"{insn.ptr+insn.off+8:#x}")
    ]


def jmp_reg(name, insn):
    return [
        InstructionTextToken(InstructionTextTokenType.InstructionToken, name),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, f"r{insn.dst}"),
        InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, f"r{insn.src}"),
        InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, f"{insn.ptr+insn.off+8:#x}")
    ]


MATCH = {
    ebpf.LD_ABS_B: lambda insn: ldabs("ldabsb", insn),
    ebpf.LD_ABS_H: lambda insn: ldabs("ldabsh", insn),
    ebpf.LD_ABS_W: lambda insn: ldabs("ldabsw", insn),
    ebpf.LD_ABS_DW: lambda insn: ldabs("ldabsdw", insn),
    ebpf.LD_IND_B: lambda insn: ldind("ldindb", insn),
    ebpf.LD_IND_H: lambda insn: ldind("ldindh", insn),
    ebpf.LD_IND_W: lambda insn: ldind("ldindw", insn),
    ebpf.LD_IND_DW: lambda insn: ldind("ldinddw", insn),
    ebpf.LD_DW_IMM: lambda insn: [
        InstructionTextToken(InstructionTextTokenType.InstructionToken, "lddw"),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, f"r{insn.dst}"),
        InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ","),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        *do_imm(insn.imm)
    ],
    ebpf.LD_B_REG: lambda insn: ld_reg("ldxb", insn),
    ebpf.LD_H_REG: lambda insn: ld_reg("ldxh", insn),
    ebpf.LD_W_REG: lambda insn: ld_reg("ldxw", insn),
    ebpf.LD_DW_REG: lambda insn: ld_reg("ldxdw", insn),
    ebpf.ST_B_IMM: lambda insn: ld_st_imm("stb", insn),
    ebpf.ST_H_IMM: lambda insn: ld_st_imm("sth", insn),
    ebpf.ST_W_IMM: lambda insn: ld_st_imm("stw", insn),
    ebpf.ST_DW_IMM: lambda insn: ld_st_imm("stdw", insn),
    ebpf.ST_B_REG: lambda insn: st_reg("stxb", insn),
    ebpf.ST_H_REG: lambda insn: st_reg("stxh", insn),
    ebpf.ST_W_REG: lambda insn: st_reg("stxw", insn),
    ebpf.ST_DW_REG: lambda insn: st_reg("stxdw", insn),
    ebpf.ST_W_XADD: lambda insn: st_reg("stxxaddw", insn),
    ebpf.ST_DW_XADD: lambda insn: st_reg("stxxadddw", insn),
    ebpf.ADD32_IMM: lambda insn: alu_imm("add32", insn),
    ebpf.ADD32_REG: lambda insn: alu_reg("add32", insn),
    ebpf.SUB32_IMM: lambda insn: alu_imm("sub32", insn),
    ebpf.SUB32_REG: lambda insn: alu_reg("sub32", insn),
    ebpf.MUL32_IMM: lambda insn: alu_imm("mul32", insn),
    ebpf.MUL32_REG: lambda insn: alu_reg("mul32", insn),
    ebpf.DIV32_IMM: lambda insn: alu_imm("div32", insn),
    ebpf.DIV32_REG: lambda insn: alu_reg("div32", insn),
    ebpf.OR32_IMM: lambda insn: alu_imm("or32", insn),
    ebpf.OR32_REG: lambda insn: alu_reg("or32", insn),
    ebpf.AND32_IMM: lambda insn: alu_imm("and32", insn),
    ebpf.AND32_REG: lambda insn: alu_reg("and32", insn),
    ebpf.LSH32_IMM: lambda insn: alu_imm("lsh32", insn),
    ebpf.LSH32_REG: lambda insn: alu_reg("lsh32", insn),
    ebpf.RSH32_IMM: lambda insn: alu_imm("rsh32", insn),
    ebpf.RSH32_REG: lambda insn: alu_reg("rsh32", insn),
    ebpf.NEG32: lambda insn: neg("neg32", insn),
    ebpf.MOD32_IMM: lambda insn: alu_imm("mod32", insn),
    ebpf.MOD32_REG: lambda insn: alu_reg("mod32", insn),
    ebpf.XOR32_IMM: lambda insn: alu_imm("xor32", insn),
    ebpf.XOR32_REG: lambda insn: alu_reg("xor32", insn),
    ebpf.MOV32_IMM: lambda insn: alu_imm("mov32", insn),
    ebpf.MOV32_REG: lambda insn: alu_reg("mov32", insn),
    ebpf.ARSH32_IMM: lambda insn: alu_imm("arsh32", insn),
    ebpf.ARSH32_REG: lambda insn: alu_reg("arsh32", insn),
    ebpf.LE: lambda insn: byteswap("le", insn),
    ebpf.BE: lambda insn: byteswap("be", insn),
    ebpf.ADD64_IMM: lambda insn: alu_imm("add64", insn),
    ebpf.ADD64_REG: lambda insn: alu_reg("add64", insn),
    ebpf.SUB64_IMM: lambda insn: alu_imm("sub64", insn),
    ebpf.SUB64_REG: lambda insn: alu_reg("sub64", insn),
    ebpf.MUL64_IMM: lambda insn: alu_imm("mul64", insn),
    ebpf.MUL64_REG: lambda insn: alu_reg("mul64", insn),
    ebpf.DIV64_IMM: lambda insn: alu_imm("div64", insn),
    ebpf.DIV64_REG: lambda insn: alu_reg("div64", insn),
    ebpf.OR64_IMM: lambda insn: alu_imm("or64", insn),
    ebpf.OR64_REG: lambda insn: alu_reg("or64", insn),
    ebpf.AND64_IMM: lambda insn: alu_imm("and64", insn),
    ebpf.AND64_REG: lambda insn: alu_reg("and64", insn),
    ebpf.LSH64_IMM: lambda insn: alu_imm("lsh64", insn),
    ebpf.LSH64_REG: lambda insn: alu_reg("lsh64", insn),
    ebpf.RSH64_IMM: lambda insn: alu_imm("rsh64", insn),
    ebpf.RSH64_REG: lambda insn: alu_reg("rsh64", insn),
    ebpf.NEG64: lambda insn: neg("neg64", insn),
    ebpf.MOD64_IMM: lambda insn: alu_imm("mod64", insn),
    ebpf.MOD64_REG: lambda insn: alu_reg("mod64", insn),
    ebpf.XOR64_IMM: lambda insn: alu_imm("xor64", insn),
    ebpf.XOR64_REG: lambda insn: alu_reg("xor64", insn),
    ebpf.MOV64_IMM: lambda insn: alu_imm("mov64", insn),
    ebpf.MOV64_REG: lambda insn: alu_reg("mov64", insn),
    ebpf.ARSH64_IMM: lambda insn: alu_imm("arsh64", insn),
    ebpf.ARSH64_REG: lambda insn: alu_reg("arsh64", insn),
    ebpf.JA: lambda insn: jmp("ja", insn),
    ebpf.JEQ_IMM: lambda insn: jmp_imm("jeq", insn),
    ebpf.JEQ_REG: lambda insn: jmp_reg("jeq", insn),
    ebpf.JGT_IMM: lambda insn: jmp_imm("jgt", insn),
    ebpf.JGT_REG: lambda insn: jmp_reg("jgt", insn),
    ebpf.JGE_IMM: lambda insn: jmp_imm("jge", insn),
    ebpf.JGE_REG: lambda insn: jmp_reg("jge", insn),
    ebpf.JLT_IMM: lambda insn: jmp_imm("jlt", insn),
    ebpf.JLT_REG: lambda insn: jmp_reg("jlt", insn),
    ebpf.JLE_IMM: lambda insn: jmp_imm("jle", insn),
    ebpf.JLE_REG: lambda insn: jmp_reg("jle", insn),
    ebpf.JSET_IMM: lambda insn: jmp_imm("jset", insn),
    ebpf.JSET_REG: lambda insn: jmp_reg("jset", insn),
    ebpf.JNE_IMM: lambda insn: jmp_imm("jne", insn),
    ebpf.JNE_REG: lambda insn: jmp_reg("jne", insn),
    ebpf.JSGT_IMM: lambda insn: jmp_imm("jsgt", insn),
    ebpf.JSGT_REG: lambda insn: jmp_reg("jsgt", insn),
    ebpf.JSGE_IMM: lambda insn: jmp_imm("jsge", insn),
    ebpf.JSGE_REG: lambda insn: jmp_reg("jsge", insn),
    ebpf.JSLT_IMM: lambda insn: jmp_imm("jslt", insn),
    ebpf.JSLT_REG: lambda insn: jmp_reg("jslt", insn),
    ebpf.JSLE_IMM: lambda insn: jmp_imm("jsle", insn),
    ebpf.JSLE_REG: lambda insn: jmp_reg("jsle", insn),
    ebpf.CALL_IMM: lambda insn: jmp("call", insn),
    ebpf.CALL_REG: lambda insn: [
        InstructionTextToken(InstructionTextTokenType.InstructionToken, "callx"),
        InstructionTextToken(InstructionTextTokenType.TextToken, " "),
        InstructionTextToken(InstructionTextTokenType.RegisterToken, f"r{insn.dst}")
    ],
    ebpf.EXIT: lambda insn: [
        InstructionTextToken(InstructionTextTokenType.InstructionToken, "exit")
    ]
}


def disassemble(addr, data):
    insn = ebpf.EBPFInstruction(addr, data)

    if insn.opc in MATCH:
        return MATCH[insn.opc](insn)
    else:
        return [
            InstructionTextToken(InstructionTextTokenType.InstructionToken, "undefined")
        ]
