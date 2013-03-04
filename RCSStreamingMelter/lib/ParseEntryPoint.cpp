/*
 * ParseTextSection.cpp
 *
 *  Created on: May 4, 2010
 *      Author: daniele
 */

#include "Parsing.h"

void ParseEntryPoint::init()
{
    ImageSectionHeader& textSection = context<StreamingMelter>().textSection();
    
    // we process 1k of entry point
    triggeringOffset() = context<StreamingMelter>().currentOffset();
    neededBytes() = 0x400;
    offsetToNext() = 0;

    if (textSection->Misc.VirtualSize < bytesToDisasm_) {
        bytesToDisasm_ = textSection->Misc.VirtualSize;
    }
}

StateResult ParseEntryPoint::parse()
{
    PEInfo& pe = context<StreamingMelter > ().pe();
    ImageSectionHeader& textSection = context<StreamingMelter > ().textSection();
    
    currentOffset_ = context<StreamingMelter > ().currentOffset();
    DWORD RVA = textSection->VirtualAddress + (currentOffset_ - textSection->PointerToRawData);
    DWORD imageBase = pe.ntHeader.OptionalHeader.ImageBase;
    virtualAddress_ = imageBase + RVA;

    importAddress_ = imageBase + pe.ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    importSize_ = pe.ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    iatAddress_ = imageBase + pe.ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
    iatSize_ = pe.ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;

    DEBUG_MSG(D_VERBOSE, "Import table VA   : %08x", importAddress_);
    DEBUG_MSG(D_VERBOSE, "Import table size : %08x", importSize_);
    DEBUG_MSG(D_VERBOSE, "IAT VA            : &08x", iatAddress_);
    DEBUG_MSG(D_VERBOSE, "IAT size          : %08x", iatSize_);
    DEBUG_MSG(D_VERBOSE, "Disassembling VA  : %08x", virtualAddress_);

    EIPstart_ = (DWORD) context<StreamingMelter > ().buffer()->data();
    EIPend_ = (DWORD) EIPstart_ + bytesToDisasm_;

    disassembled_instruction instr;
    instr.d.EIP = EIPstart_;
    instr.d.VirtualAddr = (long long) virtualAddress_;
    instr.d.Archi = 0;
    instr.d.Options = MasmSyntax | NoTabulation | SuffixedNumeral | ShowSegmentRegs;
    
    instr.d.SecurityBlock = (int) EIPend_ - EIPstart_;
    //long long endVA = virtualAddress_ + ((long) EIPend_ - (long) EIPstart_);
    
    DEBUG_MSG(D_DEBUG, "starting disassembling from VA %08x", instr.d.VirtualAddr);
    printf("starting disassembling from EIP %08x, VA %08x", instr.d.EIP, instr.d.VirtualAddr);
    
    
    while ( (long)instr.d.EIP < (long) EIPend_) {
        // disassemble current instruction
        int len = Disasm(&instr.d);
        instr.len = len;
	printf("\n%.8X(%02d) %s                             \n", (int) instr.d.VirtualAddr, instr.len, (char*)&instr.d.CompleteInstr);

        if (len == OUT_OF_BLOCK || len == UNKNOWN_OPCODE)
            break;

        instructions_.push_back(instr);

        // go to next instruction
        instr.d.EIP = instr.d.EIP + len;
        instr.d.VirtualAddr = instr.d.VirtualAddr + len;
    }
    
    DEBUG_MSG(D_DEBUG, "disassembled %d instructions.", instructions_.size());
    
    return PARSED;
}

StateResult ParseEntryPoint::process()
{
    printf("ParseEntryPoint::process\n");
    std::vector<disassembled_instruction>::iterator iter = instructions_.begin();
    for (; iter != instructions_.end(); iter++) {
        // hook jmp opcodes of length 5
        disassembled_instruction instr = *iter;
        printf("\n%.8X(%02d) %s [%x=>%x|%x]                \n", (int) instr.d.VirtualAddr, instr.len, (char*)&instr.d.CompleteInstr, instr.d.Instruction.BranchType, JmpType, CallType);
        switch (instr.d.Instruction.BranchType) {
            case JmpType:
                if (instr.len >= STAGE1_STUB_SIZE) {
                    //printf("\n%.8X(%02d) %s                   \n", (int) instr.d.VirtualAddr, instr.len, (char*)&instr.d.CompleteInstr);
                    printf("!!! valid hook found at VA %08x (JMP)\n", (unsigned int) instr.d.VirtualAddr);
                    
                    context<StreamingMelter>().dropper().hookedInstruction() = instr;
                    context<StreamingMelter>().stage1().va = instr.d.VirtualAddr;
                    context<StreamingMelter>().stage1().offset = instr.d.VirtualAddr - virtualAddress_ + currentOffset_;
                    context<StreamingMelter>().stage1().size = instr.len;

                    offsetToNext() = context<StreamingMelter>().stage1().offset;
                    
                    return PROCESSED;
                }
                break;
            case CallType:
                if (instr.len >= STAGE1_STUB_SIZE) {
                    //printf("\n");
                    //printf("%.8X(%02d) %s\n", (int) instr.d.VirtualAddr, instr.len, (char*)&instr.d.CompleteInstr);
                    printf("!!! potential hook found at VA %08x\n", (unsigned int) instr.d.VirtualAddr);
                    printf("!!! displacement %08x\n", (unsigned int) instr.d.Argument1.Memory.Displacement);
                    
                    context<StreamingMelter>().dropper().hookedInstruction() = instr;
                    context<StreamingMelter>().stage1().va = instr.d.VirtualAddr;
                    context<StreamingMelter>().stage1().offset = instr.d.VirtualAddr - virtualAddress_ + currentOffset_;
                    context<StreamingMelter>().stage1().size = instr.len;

                    offsetToNext() = context<StreamingMelter>().stage1().offset;
                    
                    return PROCESSED;
                }
                break;
        }
        
        (void) printf("\r%.8X(%02d) %s", (int) instr.d.VirtualAddr, instr.len, (char*) &instr.d.CompleteInstr);
    }
    
    if (offsetToNext() == 0)
        throw parsing_error("Cannot find a suitable hooking point for stage1 jumper.");
    
    return PROCESSED;
}

sc::result ParseEntryPoint::transitToNext()
{
    return transit<InjectStage1Trampoline > ();
}

ParseEntryPoint::ParseEntryPoint()
: DataState<ParseEntryPoint, Parsing> (), bytesToDisasm_(maxDisasmBytes_)
{
}
