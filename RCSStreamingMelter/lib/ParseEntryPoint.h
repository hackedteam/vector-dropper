/*
 * ParseTextSection.h
 *
 *  Created on: May 4, 2010
 *      Author: daniele
 */

#ifndef PARSEENTRYPOINT_H_
#define PARSEENTRYPOINT_H_

#include <BeaEngine.h>

struct ParseEntryPoint : DataState< ParseEntryPoint, Parsing >
{
public:
	void init();
	StateResult parse();
	StateResult process();
	sc::result transitToNext();

	ParseEntryPoint();
	~ParseEntryPoint() {}

private:
	enum {
		IMPORT_ADDRESS_VA,
		IAT_ADDRESS_VA,
		GENERIC_VA,
	};

	int determineVA_(DWORD va)
	{
		if (isImportAddress_(va))
			return IMPORT_ADDRESS_VA;
		else if (isIATAddress_(va))
			return IAT_ADDRESS_VA;

		return GENERIC_VA;
	}

	bool isImportAddress_(DWORD va)
	{
		if (importAddress_ && importSize_ && va >= importAddress_ && va < importAddress_ + importSize_)
			return true;
		return false;
	}

	bool isIATAddress_(DWORD va)
	{
		if (iatAddress_ && iatSize_ && va >= iatAddress_ && va < iatAddress_ + iatSize_)
			return true;
		return false;
	}

	static const unsigned int maxDisasmBytes_ = 1024;

	unsigned int bytesToDisasm_;
	unsigned int disassembledInstructions_;
	boost::shared_array<DISASM> instruction_;

	DWORD currentOffset_;
	DWORD virtualAddress_;
	DWORD importAddress_;
	DWORD importSize_;

	DWORD iatAddress_;
	DWORD iatSize_;

	DWORD EIPstart_;
	DWORD EIPend_;
};

#endif /* PARSEENTRYPOINT_H_ */
