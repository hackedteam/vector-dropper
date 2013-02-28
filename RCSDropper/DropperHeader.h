#ifndef _DROPPER_HEADER_H
#define _DROPPER_HEADER_H

#ifdef WIN32
#include <Windows.h>
#else
#include "win32types.h"
#endif

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
	} names;

	DataSectionCryptoPack core;
	DataSectionCryptoPack core64;
	DataSectionCryptoPack config;
	DataSectionCryptoPack driver;
	DataSectionCryptoPack driver64;
	DataSectionCryptoPack codec;
} DataSectionFiles;

typedef void (*WINSTARTFUNC)(void);

typedef  __declspec(align(4)) struct _data_section_header 
{
	// RC4
	// Encryption key
	CHAR rc4key[RC4KEYLEN];

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
		DataSectionBlob exitHook;
		DataSectionBlob GetCommandLineAHook;
		DataSectionBlob GetCommandLineWHook;
		DataSectionBlob rvaToOffset;
		DataSectionBlob rc4;
		DataSectionBlob hookIAT;
		DataSectionBlob load;
	} functions;

	DataSectionFiles files;

	PatchBlob stage1;
	PatchBlob stage2;

	DataSectionBlob restore;

	ULONG exeType;
	BOOL isScout;

	CHAR instDir[10];
	CHAR eliteExports[22];
	CHAR version[20];
} DataSectionHeader;

#endif //_DROPPER_HEADER_H