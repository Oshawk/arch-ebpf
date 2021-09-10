from binaryninja.architecture import Architecture
from binaryninja.enums import InstructionTextTokenType
from binaryninja.function import InstructionInfo, RegisterInfo, InstructionTextToken

from .disassembler import disassemble
from . import ebpf


class EBPFArchitecture(Architecture):
    name = "eBPF"

    address_size = 8
    default_int_size = 8
    instr_alignment = ebpf.INSN_SIZE
    max_instr_length = ebpf.INSN_SIZE

    regs = {
        "r0": RegisterInfo("r0", 8),
        "r1": RegisterInfo("r1", 8),
        "r2": RegisterInfo("r2", 8),
        "r3": RegisterInfo("r3", 8),
        "r4": RegisterInfo("r4", 8),
        "r5": RegisterInfo("r5", 8),
        "r6": RegisterInfo("r6", 8),
        "r7": RegisterInfo("r7", 8),
        "r8": RegisterInfo("r8", 8),
        "r9": RegisterInfo("r9", 8),
        "r10": RegisterInfo("r10", 8)
    }

    stack_pointer = "r10"

    def get_instruction_info(self, data, addr):
        result = InstructionInfo()
        result.length = ebpf.INSN_SIZE
        return result

    def get_instruction_text(self, data, addr):
        return disassemble(addr, data), ebpf.INSN_SIZE

    def get_instruction_low_level_il(self, data, addr, il):
        return None
