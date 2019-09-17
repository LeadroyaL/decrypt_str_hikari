from elftools.elf.constants import P_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN, UC_PROT_WRITE, UC_PROT_READ, UC_PROT_EXEC, UC_HOOK_CODE, \
    UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_WRITE, UC_MEM_READ
from unicorn.arm_const import *
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CsInsn
from keystone import Ks, KS_MODE_THUMB, KS_ARCH_ARM, KS_MODE_ARM
import struct
import json

# 加载so文件
filename = "./libnative-lib.so"
fd = open(filename, 'r+b')
elf = ELFFile(fd)


def align(addr, size, align):
    fr_addr = addr // align * align
    to_addr = (addr + size + align - 1) // align * align
    return fr_addr, to_addr - fr_addr


def pflags2prot(p_flags):
    ret = 0
    if p_flags & P_FLAGS.PF_R != 0:
        ret |= UC_PROT_READ
    if p_flags & P_FLAGS.PF_W != 0:
        ret |= UC_PROT_WRITE
    if p_flags & P_FLAGS.PF_X != 0:
        ret |= UC_PROT_EXEC
    return ret


load_base = 0
emu = Uc(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)
load_segments = [x for x in elf.iter_segments() if x.header.p_type == 'PT_LOAD']
for segment in load_segments:
    fr_addr, size = align(load_base + segment.header.p_vaddr, segment.header.p_memsz, segment.header.p_align)
    emu.mem_map(fr_addr, size, pflags2prot(segment.header.p_flags))
    emu.mem_write(load_base + segment.header.p_vaddr, segment.data())

STACK_ADDR = 0x7F000000
STACK_SIZE = 1024 * 1024
start_addr = None
emu.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)

bss_section_header = elf.get_section_by_name('.bss').header
bss_section_start, bss_section_end = bss_section_header.sh_addr, bss_section_header.sh_addr + bss_section_header.sh_size
data_section_header = elf.get_section_by_name('.data').header
data_section_start, data_section_end = data_section_header.sh_addr, data_section_header.sh_addr + data_section_header.sh_size


def dbg_hook_memory_access(uc: Uc, access, address, size, value, data):
    if access == UC_MEM_WRITE:
        print("Write: addr=0x{0:016x} size={1} data=0x{2:016x}"
              .format(address, size, value))
    elif access == UC_HOOK_MEM_READ:
        print("Read: addr=0x{0:016x} size={1} data=0x{2:016x}"
              .format(address, size, struct.unpack("B", uc.mem_read(address, size))[0]))
    print(access, address, size, value, data)


def hook_bss_access(uc: Uc, access, address, size, value, data):
    # check rwdata range
    if bss_section_start <= address < bss_section_end:
        if stage == 0:
            # entryBB
            if access == UC_MEM_READ and size == 4 and struct.unpack("<I", uc.mem_read(address, size))[0] == 0:
                decryptStatus.add(address)
                print("READ: address:0x{0:016x} is decryptStatus".format(address))
        elif stage == 1:
            # decryptBB
            pass
        elif stage == 2:
            # originalBB
            if access == UC_MEM_WRITE and size == 4 and value == 1:
                print("WRITE: address:0x{0:016x} is decryptStatus".format(address))
                if address in decryptStatus:
                    decryptStatus.remove(address)
                uc.emu_stop()


def hook_rwdata_backup(uc: Uc, access, address, size, value, data):
    if data_section_start <= address < data_section_end and access == UC_MEM_WRITE:
        data_backup.append((address, uc.mem_read(address, size)))


# 添加内存读写hook
emu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_bss_access)
# 添加内存恢复hook
emu.hook_add(UC_HOOK_MEM_WRITE, hook_rwdata_backup)

cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
ks_thumb = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
ks_arm = Ks(KS_ARCH_ARM, KS_MODE_ARM)

# 模拟执行各个函数
j_result = json.load(open('./result.json'))
for entryBB, decryptBB, originalBB, in j_result:
    emu.reg_write(UC_ARM_REG_SP, STACK_ADDR + STACK_SIZE)
    print("Emulating entryBB")
    stage = 0
    decryptStatus = set()
    data_backup = []
    emu.emu_start(entryBB, decryptBB & 0xFFFFFFFE)
    print("Emulating decryptBB")
    stage = 1
    emu.emu_start(decryptBB, originalBB & 0xFFFFFFFE)
    print("Emulating originalBB")
    stage = 2
    emu.emu_start(originalBB, 0)
    if len(decryptStatus) == 0:
        print("Decrypt correctly!")
        # Patch decryptBB jump to original BB
        if decryptBB & 1 == 1:
            ks = ks_thumb
        else:
            ks = ks_arm
        fd.seek(decryptBB & 0xFFFFFFFE)
        if originalBB - decryptBB >= 0:
            bs = ks.asm("B.W $+" + str(originalBB - decryptBB))[0]
        else:
            bs = ks.asm("B.W $" + str(originalBB - decryptBB))[0]
        for _ in bs:
            fd.write(struct.pack("B", _))
    else:
        print("Current emulating seems incorrect, so restore patched data.")
        # 逆序恢复，防止由于读写顺序错乱引起的恢复失败
        for _a, data in data_backup[::-1]:
            emu.mem_write(_a, bytes(data))

# Patch data
print("Patch data")
new_data = emu.mem_read(data_section_header.sh_addr, data_section_header.sh_size)
fd.seek(data_section_header.sh_offset)
fd.write(new_data)

fd.close()
print("done!")
