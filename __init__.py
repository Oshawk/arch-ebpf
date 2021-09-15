# https://binary.ninja/2020/01/08/guide-to-architecture-plugins-part1.html
# https://github.com/Vector35/Z80
# https://docs.binary.ninja/dev/plugins.html
# https://api.binary.ninja/binaryninja.lowlevelil-module.html#binaryninja.lowlevelil.LowLevelILFunction

import binaryninja

from .architecture import EBPFArchitecture

EBPFArchitecture.register()
binaryninja.BinaryViewType["ELF"].register_arch(0xf7, binaryninja.enums.Endianness.LittleEndian, binaryninja.Architecture["eBPF"])
