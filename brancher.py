from binaryninja.enums import BranchType
from binaryninja.function import InstructionInfo

from . import ebpf


def jmp_cond(insn, result):
    result.add_branch(BranchType.TrueBranch, ebpf.get_memory_address(insn))
    result.add_branch(BranchType.FalseBranch, insn.ptr + 8)


MATCH = {
    ebpf.JA: lambda insn, result: result.add_branch(BranchType.UnconditionalBranch, ebpf.get_memory_address(insn)),
    ebpf.JEQ_IMM: jmp_cond,
    ebpf.JEQ_REG: jmp_cond,
    ebpf.JGT_IMM: jmp_cond,
    ebpf.JGT_REG: jmp_cond,
    ebpf.JGE_IMM: jmp_cond,
    ebpf.JGE_REG: jmp_cond,
    ebpf.JLT_IMM: jmp_cond,
    ebpf.JLT_REG: jmp_cond,
    ebpf.JLE_IMM: jmp_cond,
    ebpf.JLE_REG: jmp_cond,
    ebpf.JSET_IMM: jmp_cond,
    ebpf.JSET_REG: jmp_cond,
    ebpf.JNE_IMM: jmp_cond,
    ebpf.JNE_REG: jmp_cond,
    ebpf.JSGT_IMM: jmp_cond,
    ebpf.JSGT_REG: jmp_cond,
    ebpf.JSGE_IMM: jmp_cond,
    ebpf.JSGE_REG: jmp_cond,
    ebpf.JSLT_IMM: jmp_cond,
    ebpf.JSLT_REG: jmp_cond,
    ebpf.JSLE_IMM: jmp_cond,
    ebpf.JSLE_REG: jmp_cond,
    ebpf.CALL_IMM: lambda insn, result: result.add_branch(BranchType.CallDestination, ebpf.get_memory_address(insn, False)),
    ebpf.CALL_REG: lambda _, result: result.add_branch(BranchType.IndirectBranch),
    ebpf.EXIT: lambda _, result: result.add_branch(BranchType.FunctionReturn)
}


def branch(addr, data):
    insn = ebpf.EBPFInstruction(addr, data)

    result = InstructionInfo()
    result.length = ebpf.INSN_SIZE

    if insn.opc in MATCH:
        MATCH[insn.opc](insn, result)

    return result
