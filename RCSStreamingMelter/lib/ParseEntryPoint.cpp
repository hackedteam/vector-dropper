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
	neededBytes() = 1024;
	offsetToNext() = 0;

	if (textSection->Misc.VirtualSize < bytesToDisasm_)
		bytesToDisasm_ = textSection->Misc.VirtualSize;

	// XXX suppose we have all 1 bytes opcodes ...
	instruction_.reset(new DISASM[bytesToDisasm_]);
}

StateResult ParseEntryPoint::parse()
{
	PEInfo& pe = context<StreamingMelter>().pe();
	ImageSectionHeader& textSection = context<StreamingMelter>().textSection();

	currentOffset_ = context<StreamingMelter>().currentOffset();
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

	EIPstart_ = (DWORD) context<StreamingMelter>().buffer()->data();
	EIPend_ = (DWORD) EIPstart_ + bytesToDisasm_;

	unsigned int i = 0;
	instruction_[i].EIP = EIPstart_;
	instruction_[i].VirtualAddr = (long long) virtualAddress_;

	bool done = false;
	while ( !done )
	{
		instruction_[i].Archi = 0;
		instruction_[i].Options = MasmSyntax | NoTabulation | SuffixedNumeral | ShowSegmentRegs;
		instruction_[i].SecurityBlock = (int) EIPend_ - instruction_[i].EIP;

		int len = Disasm(&instruction_[i]);
		if (len != OUT_OF_BLOCK && len != UNKNOWN_OPCODE)
		{
			// (void) printf("%03d. %.8X(%02d) %s\n", i, (int) instruction_[i].VirtualAddr, len, (char*)&instruction_[i].CompleteInstr);

			++i;
			instruction_[i].EIP = instruction_[i - 1].EIP + len;
			instruction_[i].VirtualAddr = instruction_[i - 1].VirtualAddr + len;
			if (instruction_[i].EIP >= EIPend_) {
				done = true;
			}
		}
		else
		{
			done = true;
		}
	}
	disassembledInstructions_ = i;

	DEBUG_MSG(D_DEBUG, "disassembled %d instructions.", disassembledInstructions_);

	return PARSED;
}

StateResult ParseEntryPoint::process()
{
	for (unsigned int i = 0; i < disassembledInstructions_; ++i)
	{
		DISASM& disasm = instruction_[i];

		switch (disasm.Instruction.BranchType)
		{
			case CallType:
			{
				std::size_t va = 0;

				DWORD arg1type = disasm.Argument1.ArgType & 0xFFFF0000;
				switch (arg1type)
				{
				case MEMORY_TYPE:
					// call dword ptr ds:[01001194h]

					DEBUG_MSG(D_VERBOSE, "\t-> MEMORY_TYPE");
					DEBUG_MSG(D_VERBOSE, "\t-> address %08x", (DWORD) disasm.Argument1.Memory.Displacement);
					va = (DWORD) disasm.Argument1.Memory.Displacement;
					break;

				case CONSTANT_TYPE + RELATIVE_:
					// call 01004524h

					DEBUG_MSG(D_VERBOSE, "\t-> CONSTANT_TYPE + RELATIVE_");
					DEBUG_MSG(D_VERBOSE, "\t-> address %08x", (DWORD) disasm.Instruction.AddrValue);
					va = (DWORD) disasm.Instruction.AddrValue;
					break;

				case REGISTER_TYPE + GENERAL_REG:
					// call edi

					DEBUG_MSG(D_VERBOSE, "\t-> REGISTER_TYPE + GENERAL_REG");
					//DWORD arg1register = disasm.Argument1.ArgType & 0x0000FFFF;
					// TODO implement dynamic flow for tracking register value

					continue;
					break;
				}

				int VAtype = determineVA_(va);
				switch (VAtype) {
				case IMPORT_ADDRESS_VA:
					DEBUG_MSG(D_VERBOSE, "\t-> IMPORT TABLE CALL, skipping ...");
					break;
				case IAT_ADDRESS_VA:
					DEBUG_MSG(D_VERBOSE, "\t-> IMPORT ADDRESS TABLE CALL, skipping ...");
					break;
				case GENERIC_VA:
					if (va >= virtualAddress_)
					{
						DEBUG_MSG(D_VERBOSE, "\t-> AFTER");
						context<StreamingMelter>().stage1().va = va;
						context<StreamingMelter>().stage1().offset = va - virtualAddress_ + currentOffset_;

						DEBUG_MSG(D_VERBOSE, "\t-> HOOKING        %08x", context<StreamingMelter>().stage1().va);
						DEBUG_MSG(D_VERBOSE, "\t-> current offset %08x", currentOffset_);
						DEBUG_MSG(D_VERBOSE, "\t-> hooking offset %08x", context<StreamingMelter>().stage1().offset);

						offsetToNext() = context<StreamingMelter>().stage1().offset;
						return PROCESSED;
					}
					else
					{
						DEBUG_MSG(D_VERBOSE, "\t-> BEFORE, skipping ...");
					}
					break;
				}
				DEBUG_MSG(D_VERBOSE, "");
			}
			break;

			default:
				// (void) printf("%.8X %s\n", (int) disasm.VirtualAddr, (char*) &disasm.CompleteInstr);
				break;
		}
	}

	if (offsetToNext() == 0)
		throw parsing_error("Cannot find a suitable hooking point for stage1 jumper.");

	return PROCESSED;
}

sc::result ParseEntryPoint::transitToNext()
{
	return transit<InjectStage1Trampoline> ();
}

ParseEntryPoint::ParseEntryPoint() :
DataState<ParseEntryPoint, Parsing> (), bytesToDisasm_(maxDisasmBytes_),
		disassembledInstructions_(0)
{
}
