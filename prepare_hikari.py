import idaapi
import idc
import idautils
from idaapi import *
from idc import *
from idautils import *

import json


def format_bb(bb):
    bbtype = {0: "fcb_normal", 1: "fcb_indjump", 2: "fcb_ret", 3: "fcb_cndret",
              4: "fcb_noret", 5: "fcb_enoret", 6: "fcb_extern", 7: "fcb_error"}
    return ("ID: %d, Start: 0x%x, End: 0x%x, Last instruction: 0x%x, Size: %d, "
            "Type: %s" % (bb.id, bb.startEA, bb.endEA, idc.PrevHead(bb.endEA),
                          (bb.endEA - bb.startEA), bbtype[bb.type]))


def isFrTo(frBB, toBB):
    assert frBB._fc == toBB._fc
    _fc = frBB._fc
    _ret = False
    currentBB = frBB
    while not _ret:
        if _fc._q.nsucc(currentBB.id) != 1:
            break
        _ = next(currentBB.succs())
        if _.start_ea == toBB.start_ea:
            _ret = True
            break
        currentBB = _
    return _ret


text_seg = idaapi.get_segm_by_name('.text')
text_start = text_seg.startEA
text_end = text_seg.endEA

result = []
for ea in Functions(text_start, text_end):
    f = get_func(ea)
    fc = FlowChart(f)
    entryBB = fc[0]
    if fc._q.nsucc(entryBB.id) != 2:
        print "Not Decrypt Header. PIN1"
        continue
    decryptBB, originalBB = None, None
    trueBB, falseBB = entryBB.succs()
    # check trueBB->falseBB
    if isFrTo(trueBB, falseBB):
        decryptBB, originalBB = trueBB, falseBB
        print "GOT1!", hex(ea)
    elif isFrTo(falseBB, trueBB):
        decryptBB, originalBB = falseBB, trueBB
        print "GOT2!", hex(ea)
    else:
        print "No Decrypt Header. PIN2"
    if decryptBB and originalBB:
        '''
        https://www.hex-rays.com/products/ida/support/idadoc/1350.shtml
        Since architecture version v4 (introduced in ARM7 cores), ARM processors have a new 16-bit instruction set called Thumb (the original 32-bit set is referred to as "ARM"). Since these two sets have different instruction encodings and can be mixed in one segment, we need a way to specify how to disassemble instructions.
        For this purpose, IDA uses a virtual segment register named 'T'. If its value is 0, then ARM mode is used. Otherwise, Thumb mode is used. ARM is the default mode. Please note that if you change the value of T register for a range, IDA will destroy all instructions in that range because their disassembly is no longer correct.
        '''
        isThumb = GetReg(entryBB.start_ea, 't')
        result.append((entryBB.start_ea + isThumb, decryptBB.start_ea + isThumb, originalBB.start_ea + isThumb,))
j_result = json.dumps(result)
print j_result
