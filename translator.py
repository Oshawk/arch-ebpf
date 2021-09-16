# Adapted from https://github.com/solana-labs/rbpf/blob/main/src/vm.rs
# TODO: Work out what lddw does. The VM seems to load a qword.

from struct import pack, unpack

from binaryninja.lowlevelil import LowLevelILFunction, LowLevelILLabel

from . import ebpf


def ldx(il: LowLevelILFunction, insn, size):
    tmp_a = il.reg(8, f"r{insn.src}")
    tmp_b = il.const(8, insn.off)
    tmp = il.add(8, tmp_a, tmp_b)
    tmp = il.load(size, tmp)

    if size != 8:
        tmp = il.zero_extend(8, tmp)

    il.append(il.set_reg(8, f"r{insn.dst}", tmp))


def st(il: LowLevelILFunction, insn, size):
    tmp_a = il.reg(8, f"r{insn.dst}")
    tmp_b = il.const(8, insn.off)
    tmp_a = il.add(8, tmp_a, tmp_b)
    tmp_b = il.const(size, *unpack("<I", pack("<i", insn.imm)))  # Unsigned makes things simpler.
    il.append(il.store(size, tmp_a, tmp_b))


def stx(il: LowLevelILFunction, insn, size):
    tmp_a = il.reg(8, f"r{insn.dst}")
    tmp_b = il.const(8, insn.off)
    tmp_a = il.add(8, tmp_a, tmp_b)
    tmp_b = il.reg(8, f"r{insn.src}")

    if size != 8:
        tmp_b = il.low_part(size, tmp_b)

    il.append(il.store(size, tmp_a, tmp_b))


def alu64(il: LowLevelILFunction, insn, op, imm):
    tmp_a = il.reg(8, f"r{insn.dst}")

    if op == il.neg_expr:
        tmp_b = op(8, tmp_a)
    else:
        if imm:
            tmp_b = il.const(8, *unpack("<I", pack("<i", insn.imm)))  # Unsigned makes things simpler.
        else:
            tmp_b = il.reg(8, f"r{insn.src}")

        tmp_b = op(8, tmp_a, tmp_b)

    il.append(il.set_reg(8, f"r{insn.dst}", tmp_b))


def jmp(il: LowLevelILFunction, insn, op, imm):
    if op is not None:
        tmp_a = il.reg(8, f"r{insn.dst}")

        if imm:
            tmp_b = il.const(8, *unpack("<I", pack("<i", insn.imm)))  # Unsigned makes things simpler.
        else:
            tmp_b = il.reg(8, f"r{insn.src}")

            tmp_a = op(8, tmp_a, tmp_b)

    tmp_b = il.const(8, ebpf.get_memory_address(insn))

    if op is not None:
        t = LowLevelILLabel()
        f = LowLevelILLabel()
        il.append(il.if_expr(tmp_a, t, f))
        il.mark_label(t)

    il.append(il.jump(tmp_b))

    if op is not None:
        il.mark_label(f)


def call(il: LowLevelILFunction, insn, imm):
    for tmp in range(ebpf.FIRST_SCRATCH_REG, ebpf.FIRST_SCRATCH_REG + ebpf.SCRATCH_REGS):
        tmp = il.reg(8, f"r{tmp}")
        il.append(il.push(8, tmp))

    if imm:
        tmp = il.const(8, ebpf.get_memory_address(insn, False))
    else:
        tmp = il.reg(8, f"r{insn.imm}")

    il.append(il.call(tmp))

    for tmp_a in range(ebpf.FIRST_SCRATCH_REG + ebpf.SCRATCH_REGS - 1, ebpf.FIRST_SCRATCH_REG - 1, -1):
        tmp_b = il.pop(8)
        il.append(il.set_reg(8, f"r{tmp_a}", tmp_b))


def exit_(il: LowLevelILFunction):
    tmp = il.pop(8)
    il.append(il.ret(tmp))


MAP = {
    ebpf.LD_B_REG: lambda il, insn: ldx(il, insn, 1),
    ebpf.LD_H_REG: lambda il, insn: ldx(il, insn, 2),
    ebpf.LD_W_REG: lambda il, insn: ldx(il, insn, 4),
    ebpf.LD_DW_REG: lambda il, insn: ldx(il, insn, 8),
    ebpf.ST_B_IMM: lambda il, insn: st(il, insn, 1),
    ebpf.ST_H_IMM: lambda il, insn: st(il, insn, 2),
    ebpf.ST_W_IMM: lambda il, insn: st(il, insn, 4),
    ebpf.ST_DW_IMM: lambda il, insn: st(il, insn, 8),
    ebpf.ST_B_REG: lambda il, insn: stx(il, insn, 1),
    ebpf.ST_H_REG: lambda il, insn: stx(il, insn, 2),
    ebpf.ST_W_REG: lambda il, insn: stx(il, insn, 4),
    ebpf.ST_DW_REG: lambda il, insn: stx(il, insn, 8),
    ebpf.ADD64_IMM: lambda il, insn: alu64(il, insn, il.add, True),
    ebpf.ADD64_REG: lambda il, insn: alu64(il, insn, il.add, False),
    ebpf.SUB64_IMM: lambda il, insn: alu64(il, insn, il.sub, True),
    ebpf.SUB64_REG: lambda il, insn: alu64(il, insn, il.sub, False),
    ebpf.MUL64_IMM: lambda il, insn: alu64(il, insn, il.mult, True),
    ebpf.MUL64_REG: lambda il, insn: alu64(il, insn, il.mult, False),
    ebpf.DIV64_IMM: lambda il, insn: alu64(il, insn, il.div_unsigned, True),
    ebpf.DIV64_REG: lambda il, insn: alu64(il, insn, il.div_unsigned, False),
    ebpf.OR64_IMM: lambda il, insn: alu64(il, insn, il.or_expr, True),
    ebpf.OR64_REG: lambda il, insn: alu64(il, insn, il.or_expr, False),
    ebpf.AND64_IMM: lambda il, insn: alu64(il, insn, il.and_expr, True),
    ebpf.AND64_REG: lambda il, insn: alu64(il, insn, il.and_expr, False),
    ebpf.LSH64_IMM: lambda il, insn: alu64(il, insn, il.shift_left, True),
    ebpf.LSH64_REG: lambda il, insn: alu64(il, insn, il.shift_left, False),
    ebpf.RSH64_IMM: lambda il, insn: alu64(il, insn, il.logical_shift_right, True),
    ebpf.RSH64_REG: lambda il, insn: alu64(il, insn, il.logical_shift_right, False),
    ebpf.NEG64: lambda il, insn: alu64(il, insn, il.neg_expr, False),
    ebpf.MOD64_IMM: lambda il, insn: alu64(il, insn, il.mod_unsigned, True),
    ebpf.MOD64_REG: lambda il, insn: alu64(il, insn, il.mod_unsigned, False),
    ebpf.XOR64_IMM: lambda il, insn: alu64(il, insn, il.xor_expr, True),
    ebpf.XOR64_REG: lambda il, insn: alu64(il, insn, il.xor_expr, False),
    ebpf.MOV64_IMM: lambda il, insn: alu64(il, insn, lambda a, b, c: c, True),
    ebpf.MOV64_REG: lambda il, insn: alu64(il, insn, lambda a, b, c: c, False),
    ebpf.ARSH64_IMM: lambda il, insn: alu64(il, insn, il.arith_shift_right, True),
    ebpf.ARSH64_REG: lambda il, insn: alu64(il, insn, il.arith_shift_right, False),
    ebpf.JA: lambda il, insn: jmp(il, insn, None, True),
    ebpf.JEQ_IMM: lambda il, insn: jmp(il, insn, il.compare_equal, True),
    ebpf.JEQ_REG: lambda il, insn: jmp(il, insn, il.compare_equal, False),
    ebpf.JGT_IMM: lambda il, insn: jmp(il, insn, il.compare_unsigned_greater_than, True),
    ebpf.JGT_REG: lambda il, insn: jmp(il, insn, il.compare_unsigned_greater_than, False),
    ebpf.JGE_IMM: lambda il, insn: jmp(il, insn, il.compare_unsigned_greater_equal, True),
    ebpf.JGE_REG: lambda il, insn: jmp(il, insn, il.compare_unsigned_greater_equal, False),
    ebpf.JLT_IMM: lambda il, insn: jmp(il, insn, il.compare_unsigned_less_than, True),
    ebpf.JLT_REG: lambda il, insn: jmp(il, insn, il.compare_unsigned_less_than, False),
    ebpf.JLE_IMM: lambda il, insn: jmp(il, insn, il.compare_unsigned_less_equal, True),
    ebpf.JLE_REG: lambda il, insn: jmp(il, insn, il.compare_unsigned_less_equal, False),
    ebpf.JSET_IMM: lambda il, insn: jmp(il, insn, il.and_expr, True),
    ebpf.JSET_REG: lambda il, insn: jmp(il, insn, il.and_expr, False),
    ebpf.JNE_IMM: lambda il, insn: jmp(il, insn, il.compare_not_equal, True),
    ebpf.JNE_REG: lambda il, insn: jmp(il, insn, il.compare_not_equal, False),
    ebpf.JSGT_IMM: lambda il, insn: jmp(il, insn, il.compare_signed_greater_than, True),
    ebpf.JSGT_REG: lambda il, insn: jmp(il, insn, il.compare_signed_greater_than, False),
    ebpf.JSGE_IMM: lambda il, insn: jmp(il, insn, il.compare_signed_greater_equal, True),
    ebpf.JSGE_REG: lambda il, insn: jmp(il, insn, il.compare_signed_greater_equal, False),
    ebpf.JSLT_IMM: lambda il, insn: jmp(il, insn, il.compare_signed_less_than, True),
    ebpf.JSLT_REG: lambda il, insn: jmp(il, insn, il.compare_signed_less_than, False),
    ebpf.JSLE_IMM: lambda il, insn: jmp(il, insn, il.compare_signed_less_equal, True),
    ebpf.JSLE_REG: lambda il, insn: jmp(il, insn, il.compare_signed_less_equal, False),
    ebpf.CALL_IMM: lambda il, insn: call(il, insn, True),
    ebpf.CALL_REG: lambda il, insn: call(il, insn, False),
    ebpf.EXIT: lambda il, insn: exit_(il)
}


def translate(il: LowLevelILFunction, addr, data):
    insn = ebpf.EBPFInstruction(addr, data)

    if insn.opc in MAP:
        MAP[insn.opc](il, insn)
    else:
        il.append(il.unimplemented())
